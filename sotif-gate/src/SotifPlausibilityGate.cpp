/**
 * =====================================================================================
 * @file        SotifPlausibilityGate.cpp
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * =====================================================================================
 */

#include "norxs/SotifPlausibilityGate.hpp"
#include <cmath>
#include <cstring>
#include <ctime>

namespace norxs {
namespace sotif {

namespace {
SotifPlausibilityGate* g_globalGate = nullptr;

bool IsFinite(float v) noexcept {
    return std::isfinite(static_cast<double>(v));
}

// POSIX CLOCK_MONOTONIC in milliseconds — same clock source discipline as
// SafetyArbitrator::GetMonotonicMs(), reimplemented here rather than reused
// because that method is private to SafetyArbitrator. Used only by the
// static SoaServiceManager adaptor below; Evaluate()/IngestSoaEvent() never
// read the clock themselves, so they stay pure and unit-testable with an
// explicit nowMs.
std::uint32_t MonotonicMs() noexcept {
    struct timespec ts{};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0U;
    }
    std::uint64_t const ms =
        (static_cast<std::uint64_t>(ts.tv_sec) * 1000ULL) +
        (static_cast<std::uint64_t>(ts.tv_nsec) / 1000000ULL);
    return static_cast<std::uint32_t>(ms & 0xFFFFFFFFULL);
}
} // namespace

SotifPlausibilityGate::SotifPlausibilityGate(IpcBridge* ipc) noexcept
    : ipc_(ipc) {
}

VoidResult SotifPlausibilityGate::Init(SotifPlausibilityConfig const& config) noexcept {
    if (ipc_ == nullptr) {
        return VoidResult::Err(ErrorCode::kNullPointer);
    }
    if ((!IsFinite(config.maxConfidenceDisagreement)) || (config.maxConfidenceDisagreement < 0.0F) ||
        (!IsFinite(config.minConfidence)) || (config.minConfidence < 0.0F) || (config.minConfidence > 1.0F) ||
        (!IsFinite(config.maxCalibrationDrift)) || (config.maxCalibrationDrift < 0.0F)) {
        return VoidResult::Err(ErrorCode::kInvalidArgument);
    }

    config_       = config;
    initialised_  = true;
    return VoidResult::Ok();
}

bool SotifPlausibilityGate::CheckFreshnessAndSequence(PerceptionCandidateEvent const& c,
                                                        std::uint32_t                   nowMs,
                                                        SotifRejectReason&               outReason) noexcept {
    bool pass;

    if (nowMs < c.timestampMs) {
        // Clock-domain mismatch or malformed input; cannot trust elapsed time.
        pass      = false;
        outReason = SotifRejectReason::kInvalidInput;
    } else {
        std::uint32_t const ageMs = nowMs - c.timestampMs;
        if (ageMs > config_.maxInputAgeMs) {
            pass      = false;
            outReason = SotifRejectReason::kStaleInput;
        } else if (hasPriorSample_.load(std::memory_order_relaxed) &&
                   (c.sequenceNum <= lastSequence_.load(std::memory_order_relaxed))) {
            pass      = false;
            outReason = SotifRejectReason::kSequenceAnomaly;
        } else {
            pass      = true;
            outReason = SotifRejectReason::kNone;
        }
    }

    return pass;
}

bool SotifPlausibilityGate::CheckCrossEstimateConfidence(PerceptionCandidateEvent const& c,
                                                            SotifRejectReason&               outReason) noexcept {
    bool pass;

    if ((!IsFinite(c.primaryConfidence)) || (!IsFinite(c.secondaryConfidence)) ||
        (c.primaryConfidence < 0.0F) || (c.primaryConfidence > 1.0F) ||
        (c.secondaryConfidence < 0.0F) || (c.secondaryConfidence > 1.0F)) {
        pass      = false;
        outReason = SotifRejectReason::kInvalidInput;
    } else if ((c.primaryConfidence < config_.minConfidence) ||
               (c.secondaryConfidence < config_.minConfidence)) {
        pass      = false;
        outReason = SotifRejectReason::kLowConfidence;
    } else {
        float const disagreement = std::fabs(c.primaryConfidence - c.secondaryConfidence);
        if (disagreement > config_.maxConfidenceDisagreement) {
            pass      = false;
            outReason = SotifRejectReason::kCrossEstimateDisagreement;
        } else {
            pass      = true;
            outReason = SotifRejectReason::kNone;
        }
    }

    return pass;
}

bool SotifPlausibilityGate::CheckCalibrationDrift(PerceptionCandidateEvent const& c,
                                                     SotifRejectReason&               outReason) noexcept {
    bool pass;

    if ((!IsFinite(c.calibrationDriftMetric)) || (c.calibrationDriftMetric < 0.0F)) {
        pass      = false;
        outReason = SotifRejectReason::kInvalidInput;
    } else if (c.calibrationDriftMetric > config_.maxCalibrationDrift) {
        pass      = false;
        outReason = SotifRejectReason::kCalibrationDrift;
    } else {
        pass      = true;
        outReason = SotifRejectReason::kNone;
    }

    return pass;
}

void SotifPlausibilityGate::EscalateToSafeState(SafeState reason) noexcept {
    // Independently packs a SafeStateCommand-shaped SoaEvent and sends it via
    // the SAME IpcBridge and the SAME reserved serviceId/eventId
    // SafetyArbitrator::SendCommandToM7 uses (0xFF00 / 0xFF01) — see that
    // function in autosar-soa-gateway/src/SafetyArbitrator.cpp. Reusing the
    // exact wire contract means the M7 supervisor requires zero changes to
    // honour a SOTIF-triggered safe state: it cannot distinguish this from a
    // SafetyArbitrator-originated command, by design.
    if (ipc_ == nullptr) {
        return;
    }

    std::uint32_t const seq = escalationSequence_.fetch_add(1U, std::memory_order_relaxed);

    SafeStateCommand cmd{};
    cmd.state        = reason;
    cmd.activeDomains = 0xFFU; // SOTIF gate does not track sensor domains; unchanged
    cmd.faultBitmask  = 0x00U; // not a sensor fault; see SoaEvent.sessionId for reject reason instead
    cmd.maxSpeedKph   = 30.0F; // conservative cap, matches SafetyArbitrator's kDegradedMaxSpeedKph
    cmd.transitionMs  = 0U;    // not measured here; SotifPlausibilityGate is not timing this transition
    cmd.sequenceNum   = seq;

    SoaEvent ev{};
    ev.serviceId  = 0xFF00U; // same reserved service ID as SafetyArbitrator's SafeStateCommand channel
    ev.eventId    = 0xFF01U; // same reserved event ID — M7 side needs no new decode path
    ev.sessionId  = static_cast<std::uint32_t>(lastRejectReason_.load(std::memory_order_relaxed));
    ev.payloadLen = 24U;

    std::uint8_t* p = ev.payload;

    p[0U] = static_cast<std::uint8_t>(cmd.magic & 0xFFU);
    p[1U] = static_cast<std::uint8_t>((cmd.magic >> 8U) & 0xFFU);
    p[2U] = static_cast<std::uint8_t>((cmd.magic >> 16U) & 0xFFU);
    p[3U] = static_cast<std::uint8_t>((cmd.magic >> 24U) & 0xFFU);

    p[4U] = static_cast<std::uint8_t>(cmd.state);
    p[5U] = cmd.activeDomains;
    p[6U] = cmd.faultBitmask;
    p[7U] = 0U;

    std::memcpy(&p[8U],  &cmd.maxSpeedKph,  sizeof(float));
    std::memcpy(&p[12U], &cmd.maxDecelMps2, sizeof(float));

    p[16U] = static_cast<std::uint8_t>(cmd.transitionMs & 0xFFU);
    p[17U] = static_cast<std::uint8_t>((cmd.transitionMs >> 8U) & 0xFFU);
    p[18U] = static_cast<std::uint8_t>((cmd.transitionMs >> 16U) & 0xFFU);
    p[19U] = static_cast<std::uint8_t>((cmd.transitionMs >> 24U) & 0xFFU);

    p[20U] = static_cast<std::uint8_t>(cmd.sequenceNum & 0xFFU);
    p[21U] = static_cast<std::uint8_t>((cmd.sequenceNum >> 8U) & 0xFFU);
    p[22U] = static_cast<std::uint8_t>((cmd.sequenceNum >> 16U) & 0xFFU);
    p[23U] = static_cast<std::uint8_t>((cmd.sequenceNum >> 24U) & 0xFFU);

    (void)ipc_->Send(ev);
}

VoidResult SotifPlausibilityGate::Evaluate(PerceptionCandidateEvent const& candidate,
                                            std::uint32_t                   nowMs) noexcept {
    if (!initialised_) {
        return VoidResult::Err(ErrorCode::kNotInitialized);
    }
    if (ipc_ == nullptr) {
        return VoidResult::Err(ErrorCode::kNullPointer);
    }

    SotifRejectReason reason = SotifRejectReason::kInvalidInput;
    bool               accepted;

    if (!CheckFreshnessAndSequence(candidate, nowMs, reason)) {
        accepted = false;
    } else if (!CheckCrossEstimateConfidence(candidate, reason)) {
        accepted = false;
    } else if (!CheckCalibrationDrift(candidate, reason)) {
        accepted = false;
    } else {
        accepted = true;
        reason   = SotifRejectReason::kNone;
    }

    // Advance the replay guard only on genuine forward progress — same
    // non-regression discipline as sotif-plausibility-monitor.
    if ((!hasPriorSample_.load(std::memory_order_relaxed)) ||
        (candidate.sequenceNum > lastSequence_.load(std::memory_order_relaxed))) {
        lastSequence_.store(candidate.sequenceNum, std::memory_order_relaxed);
        hasPriorSample_.store(true, std::memory_order_relaxed);
    }

    lastRejectReason_.store(static_cast<std::uint8_t>(reason), std::memory_order_relaxed);

    if (accepted) {
        acceptCount_.fetch_add(1U, std::memory_order_relaxed);
        return VoidResult::Ok();
    }

    rejectCount_.fetch_add(1U, std::memory_order_relaxed);
    EscalateToSafeState(SafeState::kReducedDynamics);
    return VoidResult::Err(ErrorCode::kInvalidArgument);
}

VoidResult SotifPlausibilityGate::IngestSoaEvent(SoaEvent const& event, std::uint32_t nowMs) noexcept {
    if (event.payloadLen != sizeof(PerceptionCandidateEvent)) {
        return VoidResult::Err(ErrorCode::kInvalidArgument);
    }

    PerceptionCandidateEvent candidate{};
    std::memcpy(&candidate, event.payload, sizeof(PerceptionCandidateEvent));

    return Evaluate(candidate, nowMs);
}

SotifRejectReason SotifPlausibilityGate::GetLastRejectReason() const noexcept {
    return static_cast<SotifRejectReason>(lastRejectReason_.load(std::memory_order_relaxed));
}

std::uint32_t SotifPlausibilityGate::GetAcceptCount() const noexcept {
    return acceptCount_.load(std::memory_order_relaxed);
}

std::uint32_t SotifPlausibilityGate::GetRejectCount() const noexcept {
    return rejectCount_.load(std::memory_order_relaxed);
}

void SetGlobalSotifGate(SotifPlausibilityGate* gate) noexcept {
    g_globalGate = gate;
}

void SotifGateEventHandler(SoaEvent const& event) noexcept {
    if (g_globalGate != nullptr) {
        (void)g_globalGate->IngestSoaEvent(event, MonotonicMs());
    }
}

} // namespace sotif
} // namespace norxs
