/**
 * =====================================================================================
 * @file        SotifPlausibilityGate.hpp
 * @brief       ISO 21448 (SOTIF) plausibility gate for AI-derived driving-command
 *              candidates, positioned upstream of SafetyArbitrator in the SOA Gateway
 *              pipeline.
 *
 *              Why this module exists (and why it is not redundant with
 *              SafetyArbitrator): SafetyArbitrator.hpp documents "SOTIF ISO 21448" in
 *              its @standards line, but its actual mechanism — SensorFaultMonitor,
 *              DegradationMatrix, PhysicalEnvelope ROM bounds — is fault-based and
 *              bound-based. It answers "is a sensor domain reporting Nominal /
 *              Degraded / Failed?" and "is this command inside the hardcoded physical
 *              envelope?". Neither question is SOTIF's question. ISO 21448 is about
 *              functional insufficiency: every sensor domain can report kNominal,
 *              every physical bound (kMaxLateralAccelMps2, kMaxSteeringAngleDeg, ...)
 *              can be satisfied, and the AI's judgement can still be wrong — because
 *              its own confidence estimate is internally inconsistent, or its
 *              calibration has silently drifted. SafetyArbitrator's ValidateSteeringAngle
 *              / ValidateFrictionCoeff / ValidateDeceleration / ValidateLateralAccel
 *              cannot see that; they only see the number, not whether the AI should be
 *              trusted to have produced it. This module closes exactly that gap, and
 *              only that gap — it does not re-validate physical bounds (SafetyArbitrator
 *              already does that correctly) and does not touch sensor fault handling
 *              (also already correct).
 *
 *              Deterministic core only, per the same discipline used throughout this
 *              gate: no learned/statistical component sits in the accept/reject path,
 *              because a learned plausibility check has its own SOTIF problem and would
 *              not actually close the gap it exists to close.
 *
 *              Pipeline position:
 *
 *              [Orin AI Domain] → PerceptionCandidateEvent (SOME/IP)
 *                    │
 *                    ▼
 *              [SoaServiceManager::ProcessEvents()]
 *                    │  SoaEvent fan-out
 *                    ▼
 *              ╔══════════════════════════════╗
 *              ║   SotifPlausibilityGate      ║  ← THIS MODULE (new)
 *              ║  cross-estimate confidence   ║
 *              ║  calibration-drift check     ║
 *              ║  input freshness check       ║
 *              ╚══════════════════════════════╝
 *                    │  accepted candidate only
 *                    ▼
 *              [SafetyArbitrator::Validate*]  ← unchanged, still the physical-bound gate
 *                    │
 *                    ▼
 *              [IpcBridge → Cortex-M7 Safety Supervisor]
 *
 *              On rejection, this module does NOT call SafetyArbitrator at all — it
 *              independently packs a conservative SafeStateCommand (reusing the exact
 *              struct SafetyArbitrator.hpp defines) and sends it through the same
 *              IpcBridge, so a SOTIF rejection reaches the M7 supervisor over the
 *              identical E2E Profile 5 protected channel, without requiring any change
 *              to SafetyArbitrator or private access to its internals.
 *
 * @project     SOTIF Plausibility Gate — companion to SOA Gateway for Autonomous
 *              Safety-Supervisor
 * @standards   AUTOSAR C++14, ISO 21448 (SOTIF), POSIX
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        Depends on autosar-soa-gateway's public headers (SoaServiceManager.hpp,
 *              SafetyArbitrator.hpp, IpcBridge.hpp) — see that repository. Vendored
 *              copies under vendor/ in this repository are for build purposes only;
 *              the real dependency is that repository, not this copy.
 * =====================================================================================
 */

#ifndef NORXS_SOTIF_SOTIFPLAUSIBILITYGATE_HPP
#define NORXS_SOTIF_SOTIFPLAUSIBILITYGATE_HPP

#include "SoaServiceManager.hpp"
#include "SafetyArbitrator.hpp"
#include "IpcBridge.hpp"
#include <cstdint>
#include <atomic>

namespace norxs {
namespace sotif {

using norxs::soa::SoaEvent;
using norxs::soa::IpcBridge;
using norxs::soa::VoidResult;
using norxs::soa::ErrorCode;
using norxs::soa::SafeStateCommand;
using norxs::soa::SafeState;

// ============================================================================
// Perception candidate — the AI domain's driving-command output, carried as a
// SoaEvent payload exactly the way SensorFaultEvent is (fixed-size POD,
// IPC-aligned). This is a NEW event type; SafetyArbitrator never sees this
// struct — it only ever sees candidates SotifPlausibilityGate has accepted,
// via the existing physical-bound Validate* calls the integrator wires up
// downstream of this gate.
// ============================================================================

struct PerceptionCandidateEvent {
    float         lateralAccelMps2;
    float         longitudinalDecelMps2;
    float         steeringAngleDeg;
    float         primaryConfidence;       ///< [0,1], AI's own reported confidence
    float         secondaryConfidence;     ///< [0,1], independent redundant estimate
    float         calibrationDriftMetric;  ///< >=0, from an upstream calibration check
    std::uint32_t timestampMs;             ///< Monotonic, same clock domain as Evaluate()'s nowMs
    std::uint32_t sequenceNum;             ///< Monotonically increasing per source
};

static_assert(sizeof(PerceptionCandidateEvent) == 32U,
              "PerceptionCandidateEvent must be 32 bytes (6 floats + 2 uint32) for IPC alignment");

// ============================================================================
// Rejection rationale — retained for the SOTIF evidence log (traceability),
// mirroring the DTC-catalogue discipline SafetyArbitrator/Dem already use.
// ============================================================================

enum class SotifRejectReason : std::uint8_t {
    kNone                       = 0U,
    kInvalidInput               = 1U,  ///< non-finite field, or NULL
    kStaleInput                 = 2U,  ///< age > config_.maxInputAgeMs
    kSequenceAnomaly            = 3U,  ///< non-monotonic / replayed sequence
    kCrossEstimateDisagreement  = 4U,  ///< |primary - secondary confidence| > threshold
    kLowConfidence              = 5U,  ///< either confidence below minimum
    kCalibrationDrift           = 6U   ///< drift metric over threshold
};

// ============================================================================
// Configuration — illustrative defaults; see the AoU in README.md before
// treating these as validated for any real vehicle programme.
// ============================================================================

struct SotifPlausibilityConfig {
    float         maxConfidenceDisagreement { 0.25F };
    float         minConfidence             { 0.60F };
    float         maxCalibrationDrift       { 0.15F };
    std::uint32_t maxInputAgeMs             { 40U };
};

// ============================================================================
// SotifPlausibilityGate
// ============================================================================

class SotifPlausibilityGate final {
public:
    /**
     * @param ipc  Non-owning pointer to the SAME IpcBridge instance the rest
     *             of the gateway uses; must remain valid for object lifetime.
     *             Used only on the reject path, to send a conservative
     *             SafeStateCommand independently of SafetyArbitrator.
     */
    explicit SotifPlausibilityGate(IpcBridge* ipc) noexcept;
    ~SotifPlausibilityGate() noexcept = default;

    SotifPlausibilityGate(SotifPlausibilityGate const&)            = delete;
    SotifPlausibilityGate& operator=(SotifPlausibilityGate const&) = delete;
    SotifPlausibilityGate(SotifPlausibilityGate&&)                 = delete;
    SotifPlausibilityGate& operator=(SotifPlausibilityGate&&)      = delete;

    VoidResult Init(SotifPlausibilityConfig const& config) noexcept;

    /**
     * @brief  Evaluate one perception candidate. Fail-safe default: any
     *         invalid argument or failed check results in a reject and (on
     *         a successfully-parsed-but-implausible candidate) an
     *         independent SafeStateCommand sent via IpcBridge. Returns
     *         false only when Init() was not called or ipc_ is null —
     *         every other outcome, including every reject reason, is a
     *         normal result with GetLastRejectReason() set accordingly.
     */
    VoidResult Evaluate(PerceptionCandidateEvent const& candidate,
                         std::uint32_t                   nowMs) noexcept;

    /**
     * @brief  Convenience adaptor: decode a raw SoaEvent from
     *         SoaServiceManager into a PerceptionCandidateEvent and call
     *         Evaluate(). Register this as the SoaServiceManager event
     *         handler for the AI perception-candidate SOME/IP service —
     *         the same integration idiom SafetyArbitrator::IngestSoaEvent
     *         uses for sensor-health events.
     */
    VoidResult IngestSoaEvent(SoaEvent const& event, std::uint32_t nowMs) noexcept;

    SotifRejectReason GetLastRejectReason() const noexcept;
    std::uint32_t     GetAcceptCount() const noexcept;
    std::uint32_t     GetRejectCount() const noexcept;

private:
    bool CheckFreshnessAndSequence(PerceptionCandidateEvent const& c,
                                    std::uint32_t                   nowMs,
                                    SotifRejectReason&               outReason) noexcept;
    bool CheckCrossEstimateConfidence(PerceptionCandidateEvent const& c,
                                       SotifRejectReason&               outReason) noexcept;
    bool CheckCalibrationDrift(PerceptionCandidateEvent const& c,
                                SotifRejectReason&               outReason) noexcept;

    /**
     * @brief  Independently pack and send a conservative SafeStateCommand
     *         through IpcBridge — reuses the exact struct and E2E Profile 5
     *         path SafetyArbitrator uses, without needing access to its
     *         private SendCommandToM7.
     */
    void EscalateToSafeState(SafeState reason) noexcept;

    IpcBridge*                  ipc_;
    SotifPlausibilityConfig     config_{};
    std::atomic<std::uint32_t>  lastSequence_{ 0U };
    std::atomic<bool>           hasPriorSample_{ false };
    std::atomic<std::uint8_t>   lastRejectReason_{ 0U };
    std::atomic<std::uint32_t>  acceptCount_{ 0U };
    std::atomic<std::uint32_t>  rejectCount_{ 0U };
    std::atomic<std::uint32_t>  escalationSequence_{ 0U };
    bool                        initialised_{ false };
};

// ============================================================================
// Static SoaEvent handler adaptor — same idiom as
// SetGlobalArbitrator/SoaArbitratorEventHandler in SafetyArbitrator.hpp.
// ============================================================================

void SetGlobalSotifGate(SotifPlausibilityGate* gate) noexcept;
void SotifGateEventHandler(SoaEvent const& event) noexcept;

} // namespace sotif
} // namespace norxs

#endif // NORXS_SOTIF_SOTIFPLAUSIBILITYGATE_HPP
