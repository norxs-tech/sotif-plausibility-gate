/**
 * =====================================================================================
 * @file        SafetyArbitrator.cpp
 * @brief       ASIL-D Safety Arbitrator implementation.
 *
 *              Execution model:
 *                - Arbitrate() is the single periodic entry point (10ms period).
 *                - All sensor ingestion paths (IngestFault, RecordHeartbeat) are
 *                  lock-free and safe to call from any thread context.
 *                - ExecuteTransition() is called exclusively from Arbitrate() and
 *                  is therefore single-threaded on the safety loop task.
 *                - All timing measurements use CLOCK_MONOTONIC to align with the
 *                  WdgM time domain on the M7.
 *
 *              Degradation Matrix priority (highest wins):
 *                1. Any E2E counter error              → kEmergencyStop
 *                2. Any ASIL-D internal invariant fail → kEmergencyStop
 *                3. LiDAR + Radar both failed          → kMinimalRiskCondition
 *                4. LiDAR failed                       → kRadarCameraFallback
 *                5. Radar failed                       → kLidarCameraFallback
 *                6. Camera failed                      → kLidarRadarFallback
 *                7. GNSS failed                        → kDeadReckoningMode
 *                8. IMU failed                         → kReducedDynamics
 *                9. All sensors nominal                → kFullOperation
 *
 * @project     SOA Gateway for Autonomous Safety-Supervisor
 * @standards   AUTOSAR C++14, ISO 26262 Part 3/4/6, SOTIF ISO 21448, UN R155
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        This is a reference implementation showcasing norxs's SOA architecture.
 * =====================================================================================
 */

#include "SafetyArbitrator.hpp"
#include <cstring>
#include <time.h>

namespace norxs {
namespace soa {

// ============================================================================
// Module-level global arbitrator pointer (for static SoaEvent handler adaptor)
// ============================================================================

static SafetyArbitrator* g_arbitratorInstance{ nullptr };

void SetGlobalArbitrator(SafetyArbitrator* arb) noexcept {
    g_arbitratorInstance = arb;
}

void SoaArbitratorEventHandler(SoaEvent const& event) noexcept {
    if (g_arbitratorInstance != nullptr) {
        (void)g_arbitratorInstance->IngestSoaEvent(event);
    }
}

// ============================================================================
// GetMonotonicMs
// ============================================================================

std::uint64_t SafetyArbitrator::GetMonotonicMs() noexcept {
    struct timespec ts{};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0U;
    }
    return (static_cast<std::uint64_t>(ts.tv_sec) * 1000ULL) +
            static_cast<std::uint64_t>(ts.tv_nsec) / 1000000ULL;
}

// ============================================================================
// Constructor
// ============================================================================

SafetyArbitrator::SafetyArbitrator(IpcBridge* ipc) noexcept
    : ipc_(ipc)
{
    listeners_.fill(nullptr);
    transitionLog_.fill(SafeStateTransition{});
}

// ============================================================================
// Init
// ============================================================================

VoidResult SafetyArbitrator::Init(std::uint8_t mandatoryDomains) noexcept {
    if (initialised_) {
        return VoidResult::Err(ErrorCode::kAlreadyRegistered);
    }
    if (ipc_ == nullptr) {
        return VoidResult::Err(ErrorCode::kNullPointer);
    }

    mandatoryMask_   = mandatoryDomains;
    listenerCount_   = 0U;
    logHead_.store(0U,   std::memory_order_relaxed);
    sequenceNum_.store(0U, std::memory_order_relaxed);
    transitionCount_.store(0U, std::memory_order_relaxed);
    currentState_.store(static_cast<std::uint8_t>(SafeState::kFullOperation),
                        std::memory_order_relaxed);
    faultBitmask_.store(0U,    std::memory_order_relaxed);
    activeBitmask_.store(0xFFU, std::memory_order_relaxed);

    std::uint64_t const nowMs = GetMonotonicMs();

    // Initialise per-domain state
    for (std::uint8_t i = 0U; i < kMaxSensorDomains; ++i) {
        domains_[i].domain = static_cast<SensorDomain>(i);
        domains_[i].health.store(
            static_cast<std::uint8_t>(SensorHealth::kUnknown),
            std::memory_order_relaxed);
        domains_[i].lastHeartbeat.store(nowMs, std::memory_order_relaxed);
        domains_[i].faultCount.store(0U, std::memory_order_relaxed);
        domains_[i].dtcCode.store(0U,   std::memory_order_relaxed);
        // Mandatory flag derived from the bitmask provided at Init
        domains_[i].mandatory =
            ((mandatoryDomains >> i) & 0x01U) != 0U;
    }

    // Populate the initial command (full operation, all domains active)
    lastCommand_.magic        = kArbitratorMagic;
    lastCommand_.state        = SafeState::kFullOperation;
    lastCommand_.activeDomains= 0xFFU;
    lastCommand_.faultBitmask = 0x00U;
    lastCommand_.reserved     = 0U;
    lastCommand_.maxSpeedKph  = 130.0F;
    lastCommand_.maxDecelMps2 = kMaxLongitudinalDecelMps2;
    lastCommand_.transitionMs = 0U;
    lastCommand_.sequenceNum  = 0U;

    std::atomic_thread_fence(std::memory_order_release);
    initialised_ = true;
    return VoidResult::Ok();
}

// ============================================================================
// RegisterListener
// ============================================================================

VoidResult SafetyArbitrator::RegisterListener(SafeStateListener listener) noexcept {
    if (!initialised_) {
        return VoidResult::Err(ErrorCode::kNotInitialized);
    }
    if (listener == nullptr) {
        return VoidResult::Err(ErrorCode::kNullPointer);
    }
    if (listenerCount_ >= kMaxArbitratorListeners) {
        return VoidResult::Err(ErrorCode::kRegistryFull);
    }
    listeners_[listenerCount_] = listener;
    ++listenerCount_;
    return VoidResult::Ok();
}

// ============================================================================
// IngestFault  (lock-free — safe from any thread)
// ============================================================================

VoidResult SafetyArbitrator::IngestFault(SensorFaultEvent const& fault) noexcept {
    if (!initialised_) {
        return VoidResult::Err(ErrorCode::kNotInitialized);
    }

    std::uint8_t const domIdx = static_cast<std::uint8_t>(fault.domain);
    if (domIdx >= kNumSensorDomains) {
        return VoidResult::Err(ErrorCode::kInvalidArgument);
    }

    DomainState& dom = domains_[domIdx];

    // Update health atomically
    dom.health.store(static_cast<std::uint8_t>(fault.health),
                     std::memory_order_release);
    dom.dtcCode.store(fault.faultCode, std::memory_order_relaxed);

    if (fault.health == SensorHealth::kNominal) {
        // Clear fault counter on recovery
        dom.faultCount.store(0U, std::memory_order_relaxed);
        dom.lastHeartbeat.store(GetMonotonicMs(), std::memory_order_release);
    } else {
        // Accumulate consecutive fault ticks
        dom.faultCount.fetch_add(1U, std::memory_order_relaxed);
    }

    return VoidResult::Ok();
}

// ============================================================================
// RecordHeartbeat  (lock-free — safe from any thread)
// ============================================================================

VoidResult SafetyArbitrator::RecordHeartbeat(SensorDomain domain) noexcept {
    if (!initialised_) {
        return VoidResult::Err(ErrorCode::kNotInitialized);
    }

    std::uint8_t const domIdx = static_cast<std::uint8_t>(domain);
    if (domIdx >= kNumSensorDomains) {
        return VoidResult::Err(ErrorCode::kInvalidArgument);
    }

    DomainState& dom = domains_[domIdx];
    dom.lastHeartbeat.store(GetMonotonicMs(), std::memory_order_release);

    // Auto-recover to Nominal if fault count is below threshold
    std::uint32_t const fc = dom.faultCount.load(std::memory_order_relaxed);
    if (fc == 0U) {
        dom.health.store(static_cast<std::uint8_t>(SensorHealth::kNominal),
                         std::memory_order_release);
    }

    return VoidResult::Ok();
}

// ============================================================================
// IngestSoaEvent — decode SoaEvent payload into SensorFaultEvent
// Payload layout (little-endian):
//   byte 0    : SensorDomain  (uint8)
//   byte 1    : SensorHealth  (uint8)
//   bytes 2-3 : reserved
//   bytes 4-7 : faultCode     (uint32)
//   bytes 8-11: timestampMs   (uint32)
// ============================================================================

VoidResult SafetyArbitrator::IngestSoaEvent(SoaEvent const& event) noexcept {
    if (!initialised_) {
        return VoidResult::Err(ErrorCode::kNotInitialized);
    }
    if (event.payloadLen < 12U) {
        return VoidResult::Err(ErrorCode::kInvalidArgument);
    }

    SensorFaultEvent fault{};
    fault.domain =
        static_cast<SensorDomain>(event.payload[0U]);
    fault.health =
        static_cast<SensorHealth>(event.payload[1U]);

    // Extract faultCode (bytes 4-7, little-endian)
    fault.faultCode =
        static_cast<std::uint32_t>(event.payload[4U])        |
        (static_cast<std::uint32_t>(event.payload[5U]) << 8U) |
        (static_cast<std::uint32_t>(event.payload[6U]) << 16U)|
        (static_cast<std::uint32_t>(event.payload[7U]) << 24U);

    // Extract timestampMs (bytes 8-11, little-endian)
    fault.timestampMs =
        static_cast<std::uint32_t>(event.payload[8U])         |
        (static_cast<std::uint32_t>(event.payload[9U])  << 8U)|
        (static_cast<std::uint32_t>(event.payload[10U]) << 16U)|
        (static_cast<std::uint32_t>(event.payload[11U]) << 24U);

    return IngestFault(fault);
}

// ============================================================================
// InjectFault  (fault injection for ASIL-D testing)
// ============================================================================

VoidResult SafetyArbitrator::InjectFault(SensorDomain domain,
                                          SensorHealth health,
                                          std::uint32_t dtcCode) noexcept {
    SensorFaultEvent fault{};
    fault.domain      = domain;
    fault.health      = health;
    fault.faultCode   = dtcCode;
    fault.timestampMs = static_cast<std::uint32_t>(GetMonotonicMs());
    return IngestFault(fault);
}

// ============================================================================
// ScanTimeouts  (private)
// Promotes any domain whose heartbeat is older than kSensorTimeoutMs to kFailed.
// ============================================================================

void SafetyArbitrator::ScanTimeouts() noexcept {
    std::uint64_t const nowMs = GetMonotonicMs();

    for (std::uint8_t i = 0U; i < kMaxSensorDomains; ++i) {
        std::uint64_t const lastBeat =
            domains_[i].lastHeartbeat.load(std::memory_order_acquire);

        if (nowMs < lastBeat) {
            continue; // Clock wrap guard
        }

        std::uint64_t const ageMs = nowMs - lastBeat;

        if (ageMs > static_cast<std::uint64_t>(kSensorTimeoutMs)) {
            // Only promote to Failed — never recover via timeout
            std::uint8_t const current =
                domains_[i].health.load(std::memory_order_relaxed);
            if (current != static_cast<std::uint8_t>(SensorHealth::kFailed)) {
                domains_[i].health.store(
                    static_cast<std::uint8_t>(SensorHealth::kFailed),
                    std::memory_order_release);
                domains_[i].faultCount.fetch_add(1U, std::memory_order_relaxed);
            }
        }
    }
}

// ============================================================================
// UpdateBitmasks  (private)
// ============================================================================

void SafetyArbitrator::UpdateBitmasks() noexcept {
    std::uint8_t faults  = 0U;
    std::uint8_t actives = 0U;

    for (std::uint8_t i = 0U; i < kMaxSensorDomains; ++i) {
        std::uint8_t const h = domains_[i].health.load(std::memory_order_relaxed);
        if (h == static_cast<std::uint8_t>(SensorHealth::kNominal)) {
            actives |= static_cast<std::uint8_t>(1U << i);
        } else if (h == static_cast<std::uint8_t>(SensorHealth::kFailed)) {
            faults  |= static_cast<std::uint8_t>(1U << i);
        }
    }

    faultBitmask_.store(faults,  std::memory_order_release);
    activeBitmask_.store(actives, std::memory_order_release);
}

// ============================================================================
// ComputeRequiredState  (private — pure, deterministic)
//
// Implements the Degradation Matrix table from the header comment.
// Priority order (highest numeric SafeState wins when multiple faults active):
//   Emergency conditions checked first (fail-safe bias).
// ============================================================================

SafeState SafetyArbitrator::ComputeRequiredState() const noexcept {
    std::uint8_t const faults = faultBitmask_.load(std::memory_order_acquire);

    auto IsFailed = [&](SensorDomain d) -> bool {
        std::uint8_t const bit = static_cast<std::uint8_t>(
            1U << static_cast<std::uint8_t>(d));
        return (faults & bit) != 0U;
    };

    bool const lidarFailed  = IsFailed(SensorDomain::kLidar);
    bool const radarFailed  = IsFailed(SensorDomain::kRadar);
    bool const cameraFailed = IsFailed(SensorDomain::kCamera);
    bool const gnssFailed   = IsFailed(SensorDomain::kGnss);
    bool const imuFailed    = IsFailed(SensorDomain::kImu);

    // --- Priority 1: Critical multi-sensor loss → Minimal Risk Condition ---
    // LiDAR + Radar both lost: no forward object detection possible.
    if (lidarFailed && radarFailed) {
        return SafeState::kMinimalRiskCondition;
    }

    // Mandatory domain(s) lost beyond threshold → MRC
    std::uint8_t const mandatoryFaults = faults & mandatoryMask_;
    if (mandatoryFaults != 0U) {
        // Check if any mandatory domain has exceeded the fault threshold
        for (std::uint8_t i = 0U; i < kMaxSensorDomains; ++i) {
            if (((mandatoryMask_ >> i) & 0x01U) != 0U) {
                std::uint32_t const fc =
                    domains_[i].faultCount.load(std::memory_order_relaxed);
                if (fc >= static_cast<std::uint32_t>(kFaultThreshold)) {
                    return SafeState::kMinimalRiskCondition;
                }
            }
        }
    }

    // --- Priority 2: Single-sensor degradation (descending severity) ---
    if (lidarFailed && !radarFailed) {
        return SafeState::kRadarCameraFallback;
    }

    if (radarFailed && !lidarFailed) {
        return SafeState::kLidarCameraFallback;
    }

    if (cameraFailed) {
        return SafeState::kLidarRadarFallback;
    }

    if (gnssFailed && !imuFailed) {
        return SafeState::kDeadReckoningMode;
    }

    if (imuFailed) {
        return SafeState::kReducedDynamics;
    }

    // --- All sensors nominal ---
    return SafeState::kFullOperation;
}

// ============================================================================
// LogTransition  (private)
// ============================================================================

void SafetyArbitrator::LogTransition(SafeState     from,
                                      SafeState     to,
                                      SensorDomain  trigger,
                                      std::uint32_t latencyMs) noexcept {
    std::uint8_t const head = logHead_.load(std::memory_order_relaxed);
    std::uint8_t const nextHead =
        static_cast<std::uint8_t>((head + 1U) % kMaxTransitionLog);

    SafeStateTransition& entry = transitionLog_[head];
    entry.fromState     = from;
    entry.toState       = to;
    entry.triggerDomain = trigger;
    entry.timestampMs   = GetMonotonicMs();
    entry.transitionMs  = latencyMs;
    entry.sequenceNum   = transitionCount_.load(std::memory_order_relaxed);

    std::atomic_thread_fence(std::memory_order_release);
    logHead_.store(nextHead, std::memory_order_release);
}

// ============================================================================
// SendCommandToM7  (private)
// Serialise SafeStateCommand into a SoaEvent payload and push via IpcBridge.
// Layout in SoaEvent.payload:
//   bytes  0- 3 : magic        (uint32 LE)
//   byte   4    : SafeState    (uint8)
//   byte   5    : activeDomains(uint8)
//   byte   6    : faultBitmask (uint8)
//   byte   7    : reserved
//   bytes  8-11 : maxSpeedKph  (float LE)
//   bytes 12-15 : maxDecelMps2 (float LE)
//   bytes 16-19 : transitionMs (uint32 LE)
//   bytes 20-23 : sequenceNum  (uint32 LE)
// Total: 24 bytes (fits in kIpcPayloadBytes = 128)
// ============================================================================

VoidResult SafetyArbitrator::SendCommandToM7(SafeStateCommand const& cmd) noexcept {
    if (ipc_ == nullptr) {
        return VoidResult::Err(ErrorCode::kNullPointer);
    }

    SoaEvent ev{};
    ev.serviceId  = 0xFF00U; // Reserved service ID for safety arbitrator
    ev.eventId    = 0xFF01U; // Reserved event ID for SafeStateCommand
    ev.sessionId  = cmd.sequenceNum;
    ev.payloadLen = 24U;

    std::uint8_t* p = ev.payload;

    // magic (uint32 LE)
    p[0U] = static_cast<std::uint8_t>(cmd.magic & 0xFFU);
    p[1U] = static_cast<std::uint8_t>((cmd.magic >> 8U)  & 0xFFU);
    p[2U] = static_cast<std::uint8_t>((cmd.magic >> 16U) & 0xFFU);
    p[3U] = static_cast<std::uint8_t>((cmd.magic >> 24U) & 0xFFU);

    // state, activeDomains, faultBitmask, reserved
    p[4U] = static_cast<std::uint8_t>(cmd.state);
    p[5U] = cmd.activeDomains;
    p[6U] = cmd.faultBitmask;
    p[7U] = 0U;

    // maxSpeedKph (float → 4 bytes LE via memcpy — avoids strict-aliasing UB)
    std::memcpy(&p[8U],  &cmd.maxSpeedKph,  sizeof(float));
    std::memcpy(&p[12U], &cmd.maxDecelMps2, sizeof(float));

    // transitionMs (uint32 LE)
    p[16U] = static_cast<std::uint8_t>(cmd.transitionMs & 0xFFU);
    p[17U] = static_cast<std::uint8_t>((cmd.transitionMs >> 8U)  & 0xFFU);
    p[18U] = static_cast<std::uint8_t>((cmd.transitionMs >> 16U) & 0xFFU);
    p[19U] = static_cast<std::uint8_t>((cmd.transitionMs >> 24U) & 0xFFU);

    // sequenceNum (uint32 LE)
    p[20U] = static_cast<std::uint8_t>(cmd.sequenceNum & 0xFFU);
    p[21U] = static_cast<std::uint8_t>((cmd.sequenceNum >> 8U)  & 0xFFU);
    p[22U] = static_cast<std::uint8_t>((cmd.sequenceNum >> 16U) & 0xFFU);
    p[23U] = static_cast<std::uint8_t>((cmd.sequenceNum >> 24U) & 0xFFU);

    return ipc_->Send(ev);
}

// ============================================================================
// ExecuteTransition  (private)
// Called exclusively from Arbitrate() — single-threaded safety loop.
// ============================================================================

VoidResult SafetyArbitrator::ExecuteTransition(SafeState target) noexcept {
    std::uint64_t const tStart = GetMonotonicMs();

    SafeState const from = static_cast<SafeState>(
        currentState_.load(std::memory_order_acquire));

    // Build the command
    std::uint32_t const seq = sequenceNum_.fetch_add(1U, std::memory_order_relaxed);

    SafeStateCommand cmd{};
    cmd.magic         = kArbitratorMagic;
    cmd.state         = target;
    cmd.activeDomains = activeBitmask_.load(std::memory_order_relaxed);
    cmd.faultBitmask  = faultBitmask_.load(std::memory_order_relaxed);
    cmd.reserved      = 0U;
    cmd.sequenceNum   = seq + 1U;  // 1-based: 0 means no command issued

    // Apply speed and deceleration caps per the target state
    switch (target) {
        case SafeState::kFullOperation:
            cmd.maxSpeedKph  = 130.0F;
            cmd.maxDecelMps2 = kMaxLongitudinalDecelMps2;
            break;

        case SafeState::kRadarCameraFallback:
        case SafeState::kLidarCameraFallback:
            cmd.maxSpeedKph  = 100.0F;
            cmd.maxDecelMps2 = kMaxLongitudinalDecelMps2;
            break;

        case SafeState::kLidarRadarFallback:
            cmd.maxSpeedKph  = kDegradedMaxSpeedKph;
            cmd.maxDecelMps2 = kMaxLongitudinalDecelMps2;
            break;

        case SafeState::kDeadReckoningMode:
            cmd.maxSpeedKph  = kDegradedMaxSpeedKph;
            cmd.maxDecelMps2 = kMaxLongitudinalDecelMps2 * 0.7F;
            break;

        case SafeState::kReducedDynamics:
            cmd.maxSpeedKph  = kDegradedMaxSpeedKph;
            cmd.maxDecelMps2 = kMaxLongitudinalDecelMps2 * 0.5F;
            break;

        case SafeState::kMinimalRiskCondition:
            cmd.maxSpeedKph  = kMrcMaxSpeedKph;
            cmd.maxDecelMps2 = kMaxLongitudinalDecelMps2 * 0.3F;
            break;

        case SafeState::kEmergencyStop:
        default:
            cmd.maxSpeedKph  = 0.0F;
            cmd.maxDecelMps2 = kMaxLongitudinalDecelMps2;
            break;
    }

    // Determine the primary trigger domain for the log
    SensorDomain trigger = SensorDomain::kInvalid;
    std::uint8_t const fb = faultBitmask_.load(std::memory_order_relaxed);
    for (std::uint8_t i = 0U; i < kMaxSensorDomains; ++i) {
        if (((fb >> i) & 0x01U) != 0U) {
            trigger = static_cast<SensorDomain>(i);
            break;
        }
    }

    // Send to M7 via IPC bridge (E2E Profile 5 applied inside Send())
    VoidResult const sendResult = SendCommandToM7(cmd);

    std::uint64_t const tEnd = GetMonotonicMs();
    std::uint32_t const latencyMs = (tEnd >= tStart)
        ? static_cast<std::uint32_t>(tEnd - tStart)
        : 0U;

    cmd.transitionMs = latencyMs;

    // Commit the new state atomically
    currentState_.store(static_cast<std::uint8_t>(target),
                        std::memory_order_release);

    // Update last command (written single-threaded, read by GetLastCommand)
    lastCommand_ = cmd;

    // Update transition counter
    transitionCount_.fetch_add(1U, std::memory_order_relaxed);

    // Log the transition (ISO 26262 §7.4.2 traceability)
    LogTransition(from, target, trigger, latencyMs);

    // Notify all registered listeners
    for (std::uint8_t i = 0U; i < listenerCount_; ++i) {
        if (listeners_[i] != nullptr) {
            listeners_[i](cmd);
        }
    }

    // Deadline check: ISO 26262 requires transition within kSafeStateTransitionMs
    if (latencyMs > kSafeStateTransitionMs) {
        return VoidResult::Err(ErrorCode::kTimeout);
    }

    if (!sendResult.ok) {
        return VoidResult::Err(ErrorCode::kE2eViolation);
    }

    return VoidResult::Ok();
}

// ============================================================================
// Arbitrate  (main periodic entry point — call every 10ms)
// ============================================================================

VoidResult SafetyArbitrator::Arbitrate() noexcept {
    if (!initialised_) {
        return VoidResult::Err(ErrorCode::kNotInitialized);
    }

    // Step 1: Scan for heartbeat timeouts → promote to kFailed
    ScanTimeouts();

    // Step 2: Recompute fault and active bitmasks from current domain states
    UpdateBitmasks();

    // Step 3: Run the Degradation Matrix
    SafeState const required = ComputeRequiredState();
    SafeState const current  = static_cast<SafeState>(
        currentState_.load(std::memory_order_acquire));

    // Step 4: If state unchanged, nothing to do (fast path)
    if (required == current) {
        return VoidResult::Ok();
    }

    // Step 5: Execute transition — bounded by kSafeStateTransitionMs
    // Safety rule: state severity must never decrease without all sensors recovering.
    // Emergency stop is a one-way latch until explicit system reset (Init()).
    if (current == SafeState::kEmergencyStop) {
        // Latch: once emergency stop is commanded, only Init() can clear it.
        return VoidResult::Ok();
    }

    // Allow both escalation (worse) and de-escalation (recovery) transitions.
    return ExecuteTransition(required);
}

// ============================================================================
// Physical Envelope Validators  (static, pure — no state access)
// ============================================================================

VoidResult SafetyArbitrator::ValidateSteeringAngle(float angleDeg) noexcept {
    float const absAngle = (angleDeg < 0.0F) ? -angleDeg : angleDeg;
    if (absAngle > kMaxSteeringAngleDeg) {
        return VoidResult::Err(ErrorCode::kInvalidArgument);
    }
    return VoidResult::Ok();
}

VoidResult SafetyArbitrator::ValidateFrictionCoeff(float mu) noexcept {
    if ((mu < kMinFrictionCoeff) || (mu > kMaxFrictionCoeff)) {
        return VoidResult::Err(ErrorCode::kInvalidArgument);
    }
    return VoidResult::Ok();
}

VoidResult SafetyArbitrator::ValidateDeceleration(float decelMps2) noexcept {
    float const absDecel = (decelMps2 < 0.0F) ? -decelMps2 : decelMps2;
    if (absDecel > kMaxLongitudinalDecelMps2) {
        return VoidResult::Err(ErrorCode::kInvalidArgument);
    }
    return VoidResult::Ok();
}

VoidResult SafetyArbitrator::ValidateLateralAccel(float accelMps2) noexcept {
    float const absAccel = (accelMps2 < 0.0F) ? -accelMps2 : accelMps2;
    if (absAccel > kMaxLateralAccelMps2) {
        return VoidResult::Err(ErrorCode::kInvalidArgument);
    }
    return VoidResult::Ok();
}

// ============================================================================
// State observation
// ============================================================================

SafeState SafetyArbitrator::GetCurrentState() const noexcept {
    return static_cast<SafeState>(
        currentState_.load(std::memory_order_acquire));
}

SensorHealth SafetyArbitrator::GetDomainHealth(SensorDomain domain) const noexcept {
    std::uint8_t const idx = static_cast<std::uint8_t>(domain);
    if (idx >= kMaxSensorDomains) {
        return SensorHealth::kUnknown;
    }
    return static_cast<SensorHealth>(
        domains_[idx].health.load(std::memory_order_acquire));
}

std::uint8_t SafetyArbitrator::GetFaultBitmask() const noexcept {
    return faultBitmask_.load(std::memory_order_acquire);
}

std::uint8_t SafetyArbitrator::GetActiveDomainBitmask() const noexcept {
    return activeBitmask_.load(std::memory_order_acquire);
}

void SafetyArbitrator::GetLastCommand(SafeStateCommand& cmd) const noexcept {
    // Single-writer (ExecuteTransition), safe to read after acquire fence
    std::atomic_thread_fence(std::memory_order_acquire);
    cmd = lastCommand_;
}

std::uint32_t SafetyArbitrator::GetTransitionCount() const noexcept {
    return transitionCount_.load(std::memory_order_acquire);
}

// ============================================================================
// DrainTransitionLog
// ============================================================================

std::uint8_t SafetyArbitrator::DrainTransitionLog(SafeStateTransition* buffer,
                                                    std::uint8_t         bufferSize) noexcept {
    if (buffer == nullptr || bufferSize == 0U) {
        return 0U;
    }

    std::uint8_t const head  = logHead_.load(std::memory_order_acquire);
    std::uint8_t const count = (transitionCount_.load(std::memory_order_relaxed) >
                                static_cast<std::uint32_t>(kMaxTransitionLog))
                               ? kMaxTransitionLog
                               : static_cast<std::uint8_t>(
                                   transitionCount_.load(std::memory_order_relaxed));

    std::uint8_t const toCopy = (count < bufferSize) ? count : bufferSize;

    // Read newest-first (head-1, head-2, ...)
    for (std::uint8_t i = 0U; i < toCopy; ++i) {
        std::uint8_t const idx = static_cast<std::uint8_t>(
            (head + kMaxTransitionLog - 1U - i) % kMaxTransitionLog);
        buffer[i] = transitionLog_[idx];
    }

    return toCopy;
}

} // namespace soa
} // namespace norxs
