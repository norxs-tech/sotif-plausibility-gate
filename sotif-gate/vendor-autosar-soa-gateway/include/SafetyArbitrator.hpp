/**
 * =====================================================================================
 * @file        SafetyArbitrator.hpp
 * @brief       ASIL-D Safety Arbitrator — the central decision authority of the
 *              SOA Gateway.  Monitors the health of all safety-relevant sensor
 *              domains (LiDAR, Radar, Camera, GNSS, IMU), executes ISO 26262-
 *              compliant degradation transitions within a 50ms bounded deadline,
 *              and issues authoritative SafeState commands to the Cortex-M7
 *              Safety Supervisor via the IPC bridge.
 *
 *              Architectural role in the pipeline:
 *
 *              [Orin AI Domain]
 *                    │  SOME/IP sensor-health events
 *                    ▼
 *              [SoaServiceManager::ProcessEvents()]
 *                    │  SoaEvent fan-out
 *                    ▼
 *              ╔══════════════════════════════╗
 *              ║     SafetyArbitrator         ║  ← THIS MODULE
 *              ║  ┌─────────────────────┐     ║
 *              ║  │  SensorFaultMonitor │     ║  per-domain fault accumulator
 *              ║  │  DegradationMatrix  │     ║  ISO 26262 Part 3 §6.4.6
 *              ║  │  SafeStateMachine   │     ║  bounded 50ms transition
 *              ║  │  PhysicalEnvelope   │     ║  hardcoded ROM invariants
 *              ║  └─────────────────────┘     ║
 *              ╚══════════════════════════════╝
 *                    │  IpcSlot (E2E Profile 5)
 *                    ▼
 *              [IpcBridge → Shared SRAM]
 *                    │
 *                    ▼
 *              [Cortex-M7 Safety Supervisor (AUTOSAR R25-11)]
 *
 *              Safe State Degradation Matrix (ISO 26262 Part 4 §6.4.6):
 *
 *              ┌─────────────────────┬──────────────────────────────────────┐
 *              │ Fault Condition      │ Safe State Transition                │
 *              ├─────────────────────┼──────────────────────────────────────┤
 *              │ LiDAR loss          │ Radar+Camera braking profile (50ms)  │
 *              │ Radar loss          │ LiDAR+Camera braking profile (50ms)  │
 *              │ Camera loss         │ LiDAR+Radar profile, speed cap 30kph │
 *              │ LiDAR + Radar loss  │ Minimal Risk Condition (MRC): pull   │
 *              │                     │ over + hazard lights within 10s      │
 *              │ GNSS loss           │ Dead reckoning (IMU) + speed cap     │
 *              │ IMU loss            │ Reduced dynamic envelope, no lane    │
 *              │                     │ change manoeuvres permitted          │
 *              │ Any ASIL-D violation│ Emergency stop (immediate)           │
 *              │ E2E counter error   │ Emergency stop (immediate)           │
 *              └─────────────────────┴──────────────────────────────────────┘
 *
 *              Physical envelope invariants (ROM constants — never runtime-writable):
 *                - kMaxSteeringAngleDeg   = 540.0f  (±3 full turns, EPS hard limit)
 *                - kMaxFrictionCoeff      = 1.05f   (dry asphalt upper bound)
 *                - kMinFrictionCoeff      = 0.10f   (black ice lower bound)
 *                - kMaxLateralAccelMps2   = 8.5f    (tyre lateral limit)
 *                - kMaxLongitudinalDecelMps2 = 9.8f (1g braking hard limit)
 *                - kMrcMaxSpeedKph        = 20.0f   (Minimal Risk Condition speed cap)
 *                - kSafeStateTransitionMs = 50U     (ISO 26262 deadline)
 *                - kMrcPullOverTimeMs     = 10000U  (MRC pull-over window)
 *
 * @project     SOA Gateway for Autonomous Safety-Supervisor
 * @standards   AUTOSAR C++14, ISO 26262 Part 3/4/6, SOTIF ISO 21448, UN R155
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        This is a reference implementation showcasing norxs's SOA architecture.
 * =====================================================================================
 */

#ifndef NORXS_SOA_SAFETYARBITRATOR_HPP
#define NORXS_SOA_SAFETYARBITRATOR_HPP

#include "SoaServiceManager.hpp"
#include "IpcBridge.hpp"
#include <cstdint>
#include <array>
#include <atomic>

namespace norxs {
namespace soa {

// ============================================================================
// Physical Envelope Invariants (ISO 26262 Part 4 §6.4.6)
// Declared constexpr — linker places these in .rodata (ROM).
// The M7 supervisor enforces identical constants independently.
// ============================================================================

static constexpr float    kMaxSteeringAngleDeg      = 540.0F;  ///< EPS hard stop
static constexpr float    kMaxFrictionCoeff          = 1.05F;   ///< Dry asphalt
static constexpr float    kMinFrictionCoeff          = 0.10F;   ///< Black ice
static constexpr float    kMaxLateralAccelMps2       = 8.5F;    ///< Tyre lateral limit
static constexpr float    kMaxLongitudinalDecelMps2  = 9.81F;   ///< 1g hard braking
static constexpr float    kMrcMaxSpeedKph            = 20.0F;   ///< MRC speed cap
static constexpr float    kDegradedMaxSpeedKph       = 30.0F;   ///< Degraded speed cap
static constexpr std::uint32_t kSafeStateTransitionMs  = 50U;   ///< ISO 26262 deadline
static constexpr std::uint32_t kMrcPullOverTimeMs       = 10000U;///< 10s pull-over window
static constexpr std::uint32_t kSensorTimeoutMs         = 100U;  ///< Loss-of-signal timeout
static constexpr std::uint8_t  kFaultThreshold          = 3U;    ///< Consecutive faults
static constexpr std::uint8_t  kMaxSensorDomains        = 8U;
static constexpr std::uint8_t  kMaxArbitratorListeners  = 8U;
static constexpr std::uint32_t kArbitratorMagic         = 0x5AFE0001U;

// ============================================================================
// Sensor Domain Identifiers
// ============================================================================

enum class SensorDomain : std::uint8_t {
    kLidar   = 0U,
    kRadar   = 1U,
    kCamera  = 2U,
    kGnss    = 3U,
    kImu     = 4U,
    kV2X     = 5U,   ///< Vehicle-to-Everything (future use)
    kUss     = 6U,   ///< Ultrasonic sensors
    kInvalid = 7U
};

static constexpr std::uint8_t kNumSensorDomains = 7U; ///< All valid domains

// ============================================================================
// Sensor Health Status
// ============================================================================

enum class SensorHealth : std::uint8_t {
    kNominal    = 0U, ///< All signals within spec
    kDegraded   = 1U, ///< Intermittent loss / reduced quality
    kFailed     = 2U, ///< Hard fault — no valid signal
    kUnknown    = 3U  ///< Not yet initialised or timed out
};

// ============================================================================
// System-level Safe State (the arbitrator's output)
// Ordered by severity — higher numeric value = more severe restriction.
// ============================================================================

enum class SafeState : std::uint8_t {
    kFullOperation          = 0U, ///< All sensors nominal — full ADAS active
    kRadarCameraFallback    = 1U, ///< LiDAR lost — Radar+Camera braking profile
    kLidarCameraFallback    = 2U, ///< Radar lost — LiDAR+Camera braking profile
    kLidarRadarFallback     = 3U, ///< Camera lost — speed cap 30 kph
    kDeadReckoningMode      = 4U, ///< GNSS lost — IMU dead reckoning, speed cap
    kReducedDynamics        = 5U, ///< IMU lost — no lane change, reduced envelope
    kMinimalRiskCondition   = 6U, ///< Multi-sensor loss — pull over within 10s
    kEmergencyStop          = 7U  ///< ASIL-D violation or E2E error — immediate stop
};

// ============================================================================
// Fault Event — sourced from SOME/IP sensor-health events
// ============================================================================

struct SensorFaultEvent {
    SensorDomain  domain      { SensorDomain::kInvalid };
    SensorHealth  health      { SensorHealth::kUnknown };
    std::uint32_t timestampMs { 0U };
    std::uint32_t faultCode   { 0U }; ///< Domain-specific DTC
    std::uint8_t  reserved[4] {};
};

static_assert(sizeof(SensorFaultEvent) == 16U,
              "SensorFaultEvent must be 16 bytes (IPC-aligned)");

// ============================================================================
// Safe State Command — written to IPC SRAM for the M7 supervisor
// ============================================================================

struct SafeStateCommand {
    std::uint32_t magic          { kArbitratorMagic };
    SafeState     state          { SafeState::kFullOperation };
    std::uint8_t  activeDomains  { 0xFFU }; ///< Bitmask: bit N = SensorDomain N active
    std::uint8_t  faultBitmask   { 0x00U }; ///< Bitmask: bit N = SensorDomain N faulted
    std::uint8_t  reserved       { 0U };
    float         maxSpeedKph    { 130.0F };
    float         maxDecelMps2   { kMaxLongitudinalDecelMps2 };
    std::uint32_t transitionMs   { 0U };    ///< Measured transition time
    std::uint32_t sequenceNum    { 0U };    ///< Monotone command counter
};

static_assert(sizeof(SafeStateCommand) == 24U,
              "SafeStateCommand must be 24 bytes (4+1+1+1+1+4+4+4+4)");

// ============================================================================
// Per-domain health tracking (internal)
// ============================================================================

struct DomainState {
    SensorDomain             domain        { SensorDomain::kInvalid };
    std::atomic<uint8_t>     health        { static_cast<std::uint8_t>(
                                               SensorHealth::kUnknown) };
    std::atomic<uint64_t>    lastHeartbeat { 0U };  ///< ms monotonic
    std::atomic<uint32_t>    faultCount    { 0U };  ///< Consecutive fault ticks
    std::atomic<uint32_t>    dtcCode       { 0U };  ///< Last DTC reported
    bool                     mandatory     { false };///< Loss triggers MRC if true

    DomainState() noexcept = default;
    DomainState(DomainState const&)            = delete;
    DomainState& operator=(DomainState const&) = delete;
    DomainState(DomainState&&)                 = delete;
    DomainState& operator=(DomainState&&)      = delete;
};

// ============================================================================
// State transition record (audit trail — ISO 26262 §7.4.2 traceability)
// ============================================================================

struct SafeStateTransition {
    SafeState     fromState    { SafeState::kFullOperation };
    SafeState     toState      { SafeState::kEmergencyStop };
    SensorDomain  triggerDomain{ SensorDomain::kInvalid };
    std::uint64_t timestampMs  { 0U };
    std::uint32_t transitionMs { 0U }; ///< Actual measured latency
    std::uint32_t sequenceNum  { 0U };
};

static constexpr std::uint8_t kMaxTransitionLog = 32U;

// ============================================================================
// Listener callback — invoked after every state transition
// ============================================================================

using SafeStateListener = void (*)(SafeStateCommand const&);

// ============================================================================
// SafetyArbitrator
// ============================================================================

class SafetyArbitrator final {
public:
    /**
     * @brief  Construct the arbitrator with a pointer to the IPC bridge used to
     *         transmit SafeStateCommand structs to the M7 supervisor.
     * @param  ipc  Non-owning pointer; must remain valid for object lifetime.
     */
    explicit SafetyArbitrator(IpcBridge* ipc) noexcept;
    ~SafetyArbitrator() noexcept = default;

    SafetyArbitrator(SafetyArbitrator const&)            = delete;
    SafetyArbitrator& operator=(SafetyArbitrator const&) = delete;
    SafetyArbitrator(SafetyArbitrator&&)                 = delete;
    SafetyArbitrator& operator=(SafetyArbitrator&&)      = delete;

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    /**
     * @brief  Initialise all domain states, transition log, and internal
     *         sequencing.  Must be called before any other method.
     * @param  mandatoryDomains  Bitmask of SensorDomain values whose loss
     *                           immediately triggers MRC (e.g. LiDAR | Radar).
     */
    VoidResult Init(std::uint8_t mandatoryDomains) noexcept;

    // -------------------------------------------------------------------------
    // Event ingestion (called from SoaServiceManager event handlers)
    // -------------------------------------------------------------------------

    /**
     * @brief  Ingest a sensor fault event from the SOME/IP pipeline.
     *         This is the primary ingestion point — attach this method's
     *         wrapper as a SoaServiceManager EventHandler.
     *         Lock-free: updates only atomic fields in DomainState.
     *
     * @param  fault  Decoded fault event from the Orin AI domain.
     * @return VoidResult::Ok() always (fault is recorded regardless).
     */
    VoidResult IngestFault(SensorFaultEvent const& fault) noexcept;

    /**
     * @brief  Record a heartbeat for a sensor domain (called on healthy frames).
     *         Resets the consecutive fault counter if previously degraded.
     *         Lock-free atomic timestamp update.
     */
    VoidResult RecordHeartbeat(SensorDomain domain) noexcept;

    /**
     * @brief  Convenience adaptor: decode a raw SoaEvent from SoaServiceManager
     *         into a SensorFaultEvent and call IngestFault().
     *         Register this as the SoaServiceManager event handler for the
     *         sensor-health SOME/IP service.
     */
    VoidResult IngestSoaEvent(SoaEvent const& event) noexcept;

    // -------------------------------------------------------------------------
    // Periodic arbitration (call every 10ms from the main safety loop)
    // -------------------------------------------------------------------------

    /**
     * @brief  Execute one arbitration cycle:
     *           1. Scan all domain states for timeouts (> kSensorTimeoutMs).
     *           2. Apply the Degradation Matrix to determine the required SafeState.
     *           3. If state changed, execute transition within kSafeStateTransitionMs.
     *           4. Serialise SafeStateCommand into IpcBridge → M7.
     *           5. Invoke registered state-change listeners.
     *           6. Log the transition.
     *
     *         Execution time budget: < 2ms on Cortex-A53 @ 1GHz.
     *         Must NOT block; all paths are bounded.
     *
     * @return VoidResult::Ok() if no state change or transition succeeded.
     *         Err(kTimeout) if the transition exceeded kSafeStateTransitionMs.
     *         Err(kE2eViolation) if IPC send failed.
     */
    VoidResult Arbitrate() noexcept;

    // -------------------------------------------------------------------------
    // Direct fault injection (for fault injection testing — ASIL-D requirement)
    // -------------------------------------------------------------------------

    /**
     * @brief  Force a specific domain into a given health state.
     *         Used ONLY by the fault-injection test suite.
     *         Guarded by a compile-time flag in production builds.
     */
    VoidResult InjectFault(SensorDomain domain,
                           SensorHealth health,
                           std::uint32_t dtcCode) noexcept;

    // -------------------------------------------------------------------------
    // State observation (read-only, safe to call from any context)
    // -------------------------------------------------------------------------

    /**
     * @brief  Return the current system safe state (atomic load, no locking).
     */
    SafeState GetCurrentState() const noexcept;

    /**
     * @brief  Return the health of a specific sensor domain.
     */
    SensorHealth GetDomainHealth(SensorDomain domain) const noexcept;

    /**
     * @brief  Return the fault bitmask (bit N set = SensorDomain N faulted).
     */
    std::uint8_t GetFaultBitmask() const noexcept;

    /**
     * @brief  Return the active domain bitmask (bit N set = domain N healthy).
     */
    std::uint8_t GetActiveDomainBitmask() const noexcept;

    /**
     * @brief  Copy the most recent SafeStateCommand into cmd.
     */
    void GetLastCommand(SafeStateCommand& cmd) const noexcept;

    /**
     * @brief  Return the total number of state transitions since Init().
     */
    std::uint32_t GetTransitionCount() const noexcept;

    /**
     * @brief  Copy up to bufferSize transition records into buffer (newest first).
     * @return Number of records copied.
     */
    std::uint8_t DrainTransitionLog(SafeStateTransition* buffer,
                                     std::uint8_t         bufferSize) noexcept;

    // -------------------------------------------------------------------------
    // Listener registration
    // -------------------------------------------------------------------------

    /**
     * @brief  Register a callback invoked synchronously after every state
     *         transition.  Used by diagnostics and the DDS QoS enforcer.
     * @return VoidResult::Ok() or Err(kRegistryFull).
     */
    VoidResult RegisterListener(SafeStateListener listener) noexcept;

    // -------------------------------------------------------------------------
    // Physical envelope validation (callable from any module)
    // -------------------------------------------------------------------------

    /**
     * @brief  Validate a steering angle request against the ROM invariant.
     * @return VoidResult::Ok() if within bounds; Err(kInvalidArgument) if not.
     */
    static VoidResult ValidateSteeringAngle(float angleDeg) noexcept;

    /**
     * @brief  Validate a friction coefficient estimate.
     */
    static VoidResult ValidateFrictionCoeff(float mu) noexcept;

    /**
     * @brief  Validate a longitudinal deceleration request.
     */
    static VoidResult ValidateDeceleration(float decelMps2) noexcept;

    /**
     * @brief  Validate a lateral acceleration request.
     */
    static VoidResult ValidateLateralAccel(float accelMps2) noexcept;

private:
    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * @brief  Run the Degradation Matrix against the current domain states.
     *         Pure function — reads only atomic state, writes nothing.
     * @return The required SafeState derived from the current fault pattern.
     */
    SafeState ComputeRequiredState() const noexcept;

    /**
     * @brief  Execute a state transition from current_ to target, serialise
     *         the command to IPC, and record the measured latency.
     *         Called only from Arbitrate() under the single-caller guarantee.
     * @return VoidResult::Ok() or Err(kTimeout / kE2eViolation).
     */
    VoidResult ExecuteTransition(SafeState target) noexcept;

    /**
     * @brief  Serialise a SafeStateCommand into a SoaEvent and push it
     *         through IpcBridge (E2E Profile 5 applied automatically).
     */
    VoidResult SendCommandToM7(SafeStateCommand const& cmd) noexcept;

    /**
     * @brief  Scan all domains for heartbeat timeout (> kSensorTimeoutMs).
     *         Promotes timed-out domains to kFailed.
     */
    void ScanTimeouts() noexcept;

    /**
     * @brief  Build the fault and active domain bitmasks from domain states.
     */
    void UpdateBitmasks() noexcept;

    /**
     * @brief  Append a transition record to the circular transition log.
     */
    void LogTransition(SafeState     from,
                       SafeState     to,
                       SensorDomain  trigger,
                       std::uint32_t latencyMs) noexcept;

    /**
     * @brief  POSIX CLOCK_MONOTONIC in milliseconds.
     */
    static std::uint64_t GetMonotonicMs() noexcept;

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    IpcBridge*                                        ipc_;
    std::array<DomainState, kMaxSensorDomains>        domains_{};
    std::atomic<std::uint8_t>                         currentState_{
        static_cast<std::uint8_t>(SafeState::kFullOperation) };
    std::atomic<std::uint8_t>                         faultBitmask_{ 0U };
    std::atomic<std::uint8_t>                         activeBitmask_{ 0xFFU };
    std::atomic<std::uint32_t>                        sequenceNum_{ 0U };
    std::atomic<std::uint32_t>                        transitionCount_{ 0U };

    // Mandatory-domain bitmask (set at Init, read-only afterward)
    std::uint8_t                                      mandatoryMask_{ 0U };

    // Last command (written by ExecuteTransition, read by GetLastCommand)
    SafeStateCommand                                  lastCommand_{};

    // Circular transition log
    std::array<SafeStateTransition, kMaxTransitionLog> transitionLog_{};
    std::atomic<std::uint8_t>                          logHead_{ 0U };

    // Listener table
    std::array<SafeStateListener, kMaxArbitratorListeners> listeners_{};
    std::uint8_t                                           listenerCount_{ 0U };

    bool                                              initialised_{ false };
};

// ============================================================================
// Static SoaEvent handler adaptor
// Register with SoaServiceManager::Subscribe() for the sensor-health service.
// The arbitrator instance is passed via a static pointer set at startup.
// ============================================================================

/**
 * @brief  Set the global SafetyArbitrator instance used by SoaEventHandler().
 *         Must be called once before SoaServiceManager::ProcessEvents().
 */
void SetGlobalArbitrator(SafetyArbitrator* arb) noexcept;

/**
 * @brief  Static EventHandler function pointer compatible with SoaServiceManager.
 *         Forwards the SoaEvent to the global SafetyArbitrator instance.
 */
void SoaArbitratorEventHandler(SoaEvent const& event) noexcept;

} // namespace soa
} // namespace norxs

#endif // NORXS_SOA_SAFETYARBITRATOR_HPP
