/**
 * @copyright (c) 2026 norxs Technology LLC. All rights reserved.
 *
 * Unit + interop tests for SotifPlausibilityGate.
 *
 * The interop tests link against the REAL IpcBridge.cpp from
 * autosar-soa-gateway (vendored under vendor/ for this build) and verify
 * that a SOTIF rejection produces a SoaEvent that IpcBridge::Send() accepts
 * and writes into a real IpcRingBuffer with a valid E2E Profile 5 header —
 * i.e. this is not a claim of interoperability, it is executed proof of it.
 */
#include "norxs/SotifPlausibilityGate.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <limits>

using namespace norxs::soa;
using namespace norxs::sotif;

// Local, test-only monotonic read - independent of the module's own
// MonotonicMs() (that one is anonymous-namespace-private to the .cpp) - used
// only to construct a candidate whose timestamp is realistic relative to
// wall-clock time, for the one test that goes through the real static
// adaptor instead of calling Evaluate()/IngestSoaEvent() with an injected
// nowMs.
static std::uint32_t TestNowMs() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    std::uint64_t const ms = (static_cast<std::uint64_t>(ts.tv_sec) * 1000ULL) +
                              (static_cast<std::uint64_t>(ts.tv_nsec) / 1000000ULL);
    return static_cast<std::uint32_t>(ms & 0xFFFFFFFFULL);
}

static PerceptionCandidateEvent NominalCandidate(std::uint32_t seq, std::uint32_t ts) {
    PerceptionCandidateEvent c{};
    c.lateralAccelMps2      = 1.0F;
    c.longitudinalDecelMps2 = 1.0F;
    c.steeringAngleDeg      = 5.0F;
    c.primaryConfidence     = 0.9F;
    c.secondaryConfidence   = 0.88F;
    c.calibrationDriftMetric = 0.01F;
    c.timestampMs           = ts;
    c.sequenceNum           = seq;
    return c;
}

static void test_nominal_candidate_accepted() {
    IpcRingBuffer ring{};
    IpcBridge     ipc(&ring);
    assert(ipc.Init().ok);

    SotifPlausibilityGate gate(&ipc);
    SotifPlausibilityConfig cfg{};
    assert(gate.Init(cfg).ok);

    PerceptionCandidateEvent c = NominalCandidate(1U, 1000U);
    VoidResult const result = gate.Evaluate(c, 1020U);

    assert(result.ok);
    assert(gate.GetLastRejectReason() == SotifRejectReason::kNone);
    assert(gate.GetAcceptCount() == 1U);
    std::printf("PASS: test_nominal_candidate_accepted\n");
}

static void test_cross_estimate_disagreement_rejected() {
    IpcRingBuffer ring{};
    IpcBridge     ipc(&ring);
    assert(ipc.Init().ok);

    SotifPlausibilityGate gate(&ipc);
    assert(gate.Init(SotifPlausibilityConfig{}).ok);

    PerceptionCandidateEvent c = NominalCandidate(1U, 1000U);
    // Both individually above the 0.60 min-confidence floor, so this
    // isolates disagreement specifically rather than tripping the
    // low-confidence check first (0.30 gap > default 0.25 threshold).
    c.primaryConfidence   = 0.95F;
    c.secondaryConfidence = 0.65F;

    VoidResult const result = gate.Evaluate(c, 1020U);

    assert(!result.ok);
    assert(gate.GetLastRejectReason() == SotifRejectReason::kCrossEstimateDisagreement);
    std::printf("PASS: test_cross_estimate_disagreement_rejected\n");
}

static void test_low_confidence_rejected_when_agreement_would_otherwise_pass() {
    IpcRingBuffer ring{};
    IpcBridge     ipc(&ring);
    assert(ipc.Init().ok);

    SotifPlausibilityGate gate(&ipc);
    assert(gate.Init(SotifPlausibilityConfig{}).ok);

    PerceptionCandidateEvent c = NominalCandidate(1U, 1000U);
    // Both agree closely (0.05 gap, well under the 0.25 disagreement
    // threshold) but both sit below the 0.60 floor - isolates the
    // low-confidence branch specifically, distinct from disagreement.
    c.primaryConfidence   = 0.50F;
    c.secondaryConfidence = 0.45F;

    VoidResult const result = gate.Evaluate(c, 1020U);

    assert(!result.ok);
    assert(gate.GetLastRejectReason() == SotifRejectReason::kLowConfidence);
    std::printf("PASS: test_low_confidence_rejected_when_agreement_would_otherwise_pass\n");
}

static void test_calibration_drift_rejected() {
    IpcRingBuffer ring{};
    IpcBridge     ipc(&ring);
    assert(ipc.Init().ok);

    SotifPlausibilityGate gate(&ipc);
    assert(gate.Init(SotifPlausibilityConfig{}).ok);

    PerceptionCandidateEvent c = NominalCandidate(1U, 1000U);
    c.calibrationDriftMetric = 0.9F;

    VoidResult const result = gate.Evaluate(c, 1020U);

    assert(!result.ok);
    assert(gate.GetLastRejectReason() == SotifRejectReason::kCalibrationDrift);
    std::printf("PASS: test_calibration_drift_rejected\n");
}

static void test_stale_input_rejected() {
    IpcRingBuffer ring{};
    IpcBridge     ipc(&ring);
    assert(ipc.Init().ok);

    SotifPlausibilityGate gate(&ipc);
    assert(gate.Init(SotifPlausibilityConfig{}).ok);

    PerceptionCandidateEvent c = NominalCandidate(1U, 1000U);
    VoidResult const result = gate.Evaluate(c, 1000U + 100000U); // far beyond 40ms default

    assert(!result.ok);
    assert(gate.GetLastRejectReason() == SotifRejectReason::kStaleInput);
    std::printf("PASS: test_stale_input_rejected\n");
}

static void test_sequence_replay_rejected_and_does_not_regress() {
    IpcRingBuffer ring{};
    IpcBridge     ipc(&ring);
    assert(ipc.Init().ok);

    SotifPlausibilityGate gate(&ipc);
    assert(gate.Init(SotifPlausibilityConfig{}).ok);

    PerceptionCandidateEvent first = NominalCandidate(10U, 1000U);
    assert(gate.Evaluate(first, 1020U).ok);

    PerceptionCandidateEvent replay = NominalCandidate(5U, 2000U);
    VoidResult const result = gate.Evaluate(replay, 2020U);

    assert(!result.ok);
    assert(gate.GetLastRejectReason() == SotifRejectReason::kSequenceAnomaly);

    PerceptionCandidateEvent nextReal = NominalCandidate(11U, 3000U);
    assert(gate.Evaluate(nextReal, 3020U).ok); // proves last-sequence wasn't dragged back

    std::printf("PASS: test_sequence_replay_rejected_and_does_not_regress\n");
}

// ---------------------------------------------------------------------------
// Interop test: proves a SOTIF rejection produces a real, E2E-valid SoaEvent
// in the REAL IpcRingBuffer, decodable by the REAL IpcBridge::VerifyE2e().
// ---------------------------------------------------------------------------
static void test_rejection_produces_valid_e2e_protected_ipc_slot() {
    IpcRingBuffer ring{};
    IpcBridge     ipc(&ring);
    assert(ipc.Init().ok);

    SotifPlausibilityGate gate(&ipc);
    assert(gate.Init(SotifPlausibilityConfig{}).ok);

    PerceptionCandidateEvent bad = NominalCandidate(1U, 1000U);
    bad.calibrationDriftMetric   = 0.9F; // forces a reject → EscalateToSafeState()

    assert(!gate.Evaluate(bad, 1020U).ok);

    // The ring buffer's head must have advanced by exactly one slot.
    assert(ring.head == 1U);

    IpcSlot const& slot = ring.slots[0U];

    // Reserved service/event IDs must match SafetyArbitrator's SafeStateCommand
    // channel exactly — this is the whole point: the M7 side needs zero changes.
    assert(slot.serviceId == 0xFF00U);
    assert(slot.eventId   == 0xFF01U);
    assert(slot.payloadLen == 24U);

    // The REAL IpcBridge::VerifyE2e must accept this slot as-is. IpcBridge's
    // seqCounter_ starts at 0 (set in Init()) and is read before incrementing,
    // so the first Send() carries counter == 0 — confirmed by reading
    // IpcBridge.cpp's Init()/ApplyE2eHeader(), not assumed.
    VoidResult const verify = IpcBridge::VerifyE2e(slot, 0U);
    assert(verify.ok);

    std::printf("PASS: test_rejection_produces_valid_e2e_protected_ipc_slot "
                "(serviceId=0x%04X eventId=0x%04X, verified against real IpcBridge::VerifyE2e)\n",
                slot.serviceId, slot.eventId);
}

static void test_null_ipc_fails_safely_at_construction_use() {
    SotifPlausibilityGate gate(nullptr);
    assert(!gate.Init(SotifPlausibilityConfig{}).ok);
    std::printf("PASS: test_null_ipc_fails_safely_at_construction_use\n");
}

static void test_init_rejects_invalid_config() {
    IpcRingBuffer ring{};
    IpcBridge     ipc(&ring);
    assert(ipc.Init().ok);

    SotifPlausibilityGate gate(&ipc);
    SotifPlausibilityConfig bad{};
    bad.maxConfidenceDisagreement = -1.0F; // negative: invalid

    assert(!gate.Init(bad).ok);
    std::printf("PASS: test_init_rejects_invalid_config\n");
}

// ---------------------------------------------------------------------------
// IngestSoaEvent: the SoaServiceManager-facing wrapper, not exercised by
// calling Evaluate() directly in the tests above.
// ---------------------------------------------------------------------------
static void test_ingest_soa_event_valid_payload_accepted() {
    IpcRingBuffer ring{};
    IpcBridge     ipc(&ring);
    assert(ipc.Init().ok);

    SotifPlausibilityGate gate(&ipc);
    assert(gate.Init(SotifPlausibilityConfig{}).ok);

    PerceptionCandidateEvent c = NominalCandidate(1U, 1000U);
    SoaEvent ev{};
    ev.payloadLen = static_cast<std::uint8_t>(sizeof(PerceptionCandidateEvent));
    std::memcpy(ev.payload, &c, sizeof(PerceptionCandidateEvent));

    VoidResult const result = gate.IngestSoaEvent(ev, 1020U);
    assert(result.ok);
    assert(gate.GetAcceptCount() == 1U);
    std::printf("PASS: test_ingest_soa_event_valid_payload_accepted\n");
}

static void test_ingest_soa_event_wrong_payload_length_rejected() {
    IpcRingBuffer ring{};
    IpcBridge     ipc(&ring);
    assert(ipc.Init().ok);

    SotifPlausibilityGate gate(&ipc);
    assert(gate.Init(SotifPlausibilityConfig{}).ok);

    SoaEvent ev{};
    ev.payloadLen = 4U; // wrong: not sizeof(PerceptionCandidateEvent)

    VoidResult const result = gate.IngestSoaEvent(ev, 1020U);
    assert(!result.ok);
    // Rejected before ever reaching Evaluate(), so neither counter moves.
    assert(gate.GetAcceptCount() == 0U);
    assert(gate.GetRejectCount() == 0U);
    std::printf("PASS: test_ingest_soa_event_wrong_payload_length_rejected\n");
}

static void test_reject_count_increments_across_multiple_rejections() {
    IpcRingBuffer ring{};
    IpcBridge     ipc(&ring);
    assert(ipc.Init().ok);

    SotifPlausibilityGate gate(&ipc);
    assert(gate.Init(SotifPlausibilityConfig{}).ok);

    PerceptionCandidateEvent bad1 = NominalCandidate(1U, 1000U);
    bad1.calibrationDriftMetric   = 0.9F;
    assert(!gate.Evaluate(bad1, 1020U).ok);

    PerceptionCandidateEvent bad2 = NominalCandidate(2U, 2000U);
    bad2.calibrationDriftMetric   = 0.9F;
    assert(!gate.Evaluate(bad2, 2020U).ok);

    assert(gate.GetRejectCount() == 2U);
    std::printf("PASS: test_reject_count_increments_across_multiple_rejections\n");
}

// ---------------------------------------------------------------------------
// Static SoaServiceManager adaptor pair — the actual integration idiom a
// real integrator wires into SoaServiceManager::Subscribe().
// ---------------------------------------------------------------------------
static void test_static_adaptor_forwards_to_global_gate() {
    IpcRingBuffer ring{};
    IpcBridge     ipc(&ring);
    assert(ipc.Init().ok);

    SotifPlausibilityGate gate(&ipc);
    assert(gate.Init(SotifPlausibilityConfig{}).ok);

    SetGlobalSotifGate(&gate);

    // Real, current monotonic timestamp - MonotonicMs() inside the static
    // adaptor reads the actual wall clock, so a fake small value like the
    // 1000 used elsewhere in this file would always read as stale here.
    PerceptionCandidateEvent c = NominalCandidate(1U, TestNowMs());
    SoaEvent ev{};
    ev.payloadLen = static_cast<std::uint8_t>(sizeof(PerceptionCandidateEvent));
    std::memcpy(ev.payload, &c, sizeof(PerceptionCandidateEvent));

    // Uses MonotonicMs() internally (real CLOCK_MONOTONIC read), so this is
    // also the only test that exercises that function - a fixed nowMs can't
    // be injected through the static adaptor by design (see header: it's
    // deliberately the one place a clock read happens, kept out of the
    // pure, unit-testable Evaluate()/IngestSoaEvent() path).
    SotifGateEventHandler(ev);
    assert(gate.GetAcceptCount() == 1U);

    SetGlobalSotifGate(nullptr); // leave global state clean for later tests
    std::printf("PASS: test_static_adaptor_forwards_to_global_gate\n");
}

static void test_evaluate_before_init_fails_safely() {
    IpcRingBuffer ring{};
    IpcBridge     ipc(&ring);
    assert(ipc.Init().ok);

    SotifPlausibilityGate gate(&ipc); // constructed, never Init()'d

    PerceptionCandidateEvent c = NominalCandidate(1U, 1000U);
    VoidResult const result = gate.Evaluate(c, 1020U);

    assert(!result.ok); // ErrorCode::kNotInitialized, not a crash
    std::printf("PASS: test_evaluate_before_init_fails_safely\n");
}

static void test_non_finite_fields_rejected_as_invalid_input() {
    IpcRingBuffer ring{};
    IpcBridge     ipc(&ring);
    assert(ipc.Init().ok);

    SotifPlausibilityGate gate(&ipc);
    assert(gate.Init(SotifPlausibilityConfig{}).ok);

    float const nan = std::numeric_limits<float>::quiet_NaN();

    // NaN confidence must be caught by the finite-check, not silently
    // compared (NaN comparisons are always false, which would otherwise
    // let a NaN "confidence" slip past a naive `< minConfidence` check).
    PerceptionCandidateEvent c1 = NominalCandidate(1U, 1000U);
    c1.primaryConfidence = nan;
    VoidResult const r1 = gate.Evaluate(c1, 1020U);
    assert(!r1.ok);
    assert(gate.GetLastRejectReason() == SotifRejectReason::kInvalidInput);

    // NaN calibration drift, same discipline.
    PerceptionCandidateEvent c2 = NominalCandidate(2U, 2000U);
    c2.calibrationDriftMetric = nan;
    VoidResult const r2 = gate.Evaluate(c2, 2020U);
    assert(!r2.ok);
    assert(gate.GetLastRejectReason() == SotifRejectReason::kInvalidInput);

    // now < timestampMs (clock-domain mismatch) also routes to kInvalidInput.
    PerceptionCandidateEvent c3 = NominalCandidate(3U, 5000U);
    VoidResult const r3 = gate.Evaluate(c3, 1000U); // nowMs before timestampMs
    assert(!r3.ok);
    assert(gate.GetLastRejectReason() == SotifRejectReason::kInvalidInput);

    std::printf("PASS: test_non_finite_fields_rejected_as_invalid_input\n");
}

static void test_static_adaptor_noop_when_no_global_gate_set() {
    SoaEvent ev{}; // arbitrary; must not crash or do anything observable
    SetGlobalSotifGate(nullptr);
    SotifGateEventHandler(ev); // must not dereference a null gate pointer
    std::printf("PASS: test_static_adaptor_noop_when_no_global_gate_set\n");
}

int main() {
    test_nominal_candidate_accepted();
    test_cross_estimate_disagreement_rejected();
    test_low_confidence_rejected_when_agreement_would_otherwise_pass();
    test_calibration_drift_rejected();
    test_stale_input_rejected();
    test_sequence_replay_rejected_and_does_not_regress();
    test_rejection_produces_valid_e2e_protected_ipc_slot();
    test_null_ipc_fails_safely_at_construction_use();
    test_init_rejects_invalid_config();
    test_ingest_soa_event_valid_payload_accepted();
    test_ingest_soa_event_wrong_payload_length_rejected();
    test_reject_count_increments_across_multiple_rejections();
    test_static_adaptor_forwards_to_global_gate();
    test_evaluate_before_init_fails_safely();
    test_non_finite_fields_rejected_as_invalid_input();
    test_static_adaptor_noop_when_no_global_gate_set();
    std::printf("All tests passed.\n");
    return 0;
}
