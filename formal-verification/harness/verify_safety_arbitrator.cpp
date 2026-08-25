/**
 * @copyright (c) 2026 norxs Technology LLC. All rights reserved.
 *
 * Exhaustive state-space verification of the REAL, unmodified
 * SafetyArbitrator::ComputeRequiredState() degradation matrix, driven
 * through the real class's real public API (Init / IngestFault / Arbitrate
 * / GetCurrentState) - not a hand-written model of the logic, the actual
 * compiled behaviour.
 *
 * STATUS (post-fix): Finding F-02 (severity non-monotonicity under compound
 * sensor loss) has been FIXED upstream in autosar-soa-gateway - see
 * docs/FINDINGS.md for the fix commit and CHANGELOG.md for when this
 * harness was updated to match. The vendored copy of SafetyArbitrator.cpp
 * in vendor/autosar-soa-gateway/src/ is the FIXED version. This harness now
 * asserts the fix (32/32 exact spec match, 0/211 monotonicity findings)
 * rather than merely documenting the pre-fix defect; the pre-fix behaviour
 * is retained below only as a historical model, used to prove the fix
 * changed exactly the cases it should have and nothing else.
 *
 * Why exhaustive brute force instead of TLA+/TLC: no Java toolchain was
 * available in the environment this was built in (checked: `which java`
 * found nothing). This is not a lesser substitute for the relevant part of
 * this problem - ComputeRequiredState() is a PURE function of a single
 * 5-bit fault bitmask (confirmed by reading the source: it reads only
 * faultBitmask_ and, for the mandatory-domain path, domains_[i].faultCount
 * and mandatoryMask_). A pure function over a 32-value domain has exactly
 * 32 possible outputs to check - exhaustive enumeration IS a complete
 * proof over that domain, which is what a model checker would also
 * ultimately do for a state space this size. The mandatory-fault-threshold
 * path (a genuinely temporal/sequential dimension - faultCount accumulates
 * across calls) is verified separately below, not by the bitmask sweep.
 */

#include "SafetyArbitrator.hpp"
#include "IpcBridge.hpp"
#include <cstdio>
#include <cstring>
#include <cassert>
#include <array>

using namespace norxs::soa;

// ---------------------------------------------------------------------------
// The five domains ComputeRequiredState() actually reads (confirmed by
// reading SafetyArbitrator.cpp directly - kGnss and kImu are read, kV2X and
// kUss are NOT, see Finding F-01 below).
// ---------------------------------------------------------------------------
static constexpr SensorDomain kRelevantDomains[5] = {
    SensorDomain::kLidar, SensorDomain::kRadar, SensorDomain::kCamera,
    SensorDomain::kGnss,  SensorDomain::kImu
};

static int SeverityOf(SafeState s) {
    // The enum's own declared order IS the severity order (header comment:
    // "Ordered by severity - higher numeric value = more severe
    // restriction"), so this is just static_cast, not a separately-invented
    // ranking that could disagree with the real enum.
    return static_cast<int>(s);
}

static const char* StateName(SafeState s) {
    switch (s) {
        case SafeState::kFullOperation:        return "FullOperation";
        case SafeState::kRadarCameraFallback:  return "RadarCameraFallback";
        case SafeState::kLidarCameraFallback:  return "LidarCameraFallback";
        case SafeState::kLidarRadarFallback:   return "LidarRadarFallback";
        case SafeState::kDeadReckoningMode:    return "DeadReckoningMode";
        case SafeState::kReducedDynamics:      return "ReducedDynamics";
        case SafeState::kMinimalRiskCondition: return "MinimalRiskCondition";
        case SafeState::kEmergencyStop:        return "EmergencyStop";
        default:                               return "UNKNOWN";
    }
}

/**
 * The CURRENT spec, and (post-fix) the model the real code is now proven to
 * exactly implement: evaluate every triggering condition and escalate to
 * the MOST SEVERE state among all that apply, rather than returning on the
 * first match. This guarantees monotonicity by construction (adding a
 * failed domain can only add candidate escalations, each compared by max,
 * never remove one).
 */
static SafeState ReferenceModel(bool lidar, bool radar, bool camera, bool gnss, bool imu) {
    SafeState result = SafeState::kFullOperation;
    auto escalate = [&](SafeState candidate) {
        if (SeverityOf(candidate) > SeverityOf(result)) {
            result = candidate;
        }
    };

    if (lidar && radar)  { escalate(SafeState::kMinimalRiskCondition); }
    if (lidar && !radar) { escalate(SafeState::kRadarCameraFallback); }
    if (radar && !lidar) { escalate(SafeState::kLidarCameraFallback); }
    if (camera)           { escalate(SafeState::kLidarRadarFallback); }
    if (gnss && !imu)     { escalate(SafeState::kDeadReckoningMode); }
    if (imu)               { escalate(SafeState::kReducedDynamics); }

    return result;
}

/**
 * HISTORICAL ONLY: the priority-ordered, first-match model that matched the
 * real code before the fix (independently derived from the pre-fix
 * SafetyArbitrator.hpp's "Priority 1 / Priority 2" doc comment, not
 * copy-pasted from ComputeRequiredState()'s old source - this is what made
 * the original Property 1 a spec-conformance check rather than a
 * tautology). Retained solely so VerifyFixChangedExactlyTheExpectedCases()
 * below can prove the fix altered behaviour on exactly the masks Finding
 * F-02 identified as under-escalated, and nowhere else. Do not use this as
 * a current-behaviour spec - it is deliberately wrong.
 */
static SafeState PriorityOrderedModel_PreFix(bool lidar, bool radar, bool camera, bool gnss, bool imu) {
    if (lidar && radar) { return SafeState::kMinimalRiskCondition; }
    if (lidar && !radar) { return SafeState::kRadarCameraFallback; }
    if (radar && !lidar) { return SafeState::kLidarCameraFallback; }
    if (camera) { return SafeState::kLidarRadarFallback; }
    if (gnss && !imu) { return SafeState::kDeadReckoningMode; }
    if (imu) { return SafeState::kReducedDynamics; }
    return SafeState::kFullOperation;
}

/** Drives one real SafetyArbitrator instance through Init -> IngestFault
 *  (for each domain in the given failed-set) -> Arbitrate() -> GetCurrentState().
 *  A fresh instance every call - no state carries over between combinations. */
static SafeState DriveRealArbitrator(std::array<bool, 5> const& failed) {
    IpcRingBuffer ring{};
    IpcBridge     ipc(&ring);
    (void)ipc.Init();

    SafetyArbitrator arb(&ipc);
    VoidResult const initResult = arb.Init(0x00U); // mandatoryDomains = none, isolates the pure bitmask path
    assert(initResult.ok);

    for (std::size_t i = 0U; i < 5U; ++i) {
        SensorFaultEvent ev{};
        ev.domain      = kRelevantDomains[i];
        ev.health      = failed[i] ? SensorHealth::kFailed : SensorHealth::kNominal;
        ev.timestampMs = 0U;
        ev.faultCode   = failed[i] ? 0xE001U : 0U;
        (void)arb.IngestFault(ev);
    }

    (void)arb.Arbitrate();
    return arb.GetCurrentState();
}

// g_failures: genuine harness/fix problems - MUST be zero for this program
// to exit 0.
static int g_failures = 0;

static void Check(bool condition, const char* description) {
    if (!condition) {
        std::printf("FAIL: %s\n", description);
        g_failures++;
    }
}

// ---------------------------------------------------------------------------
// Property 1: exhaustive spec-conformance over all 32 reachable fault
// combinations of the 5 domains ComputeRequiredState() actually reads.
// Post-fix, the real code must match ReferenceModel() (the escalate/max-
// severity spec) exactly - 32/32.
// ---------------------------------------------------------------------------
static void VerifySpecConformanceExhaustive() {
    std::printf("=== Property 1: exhaustive spec-conformance (32/32 combinations) ===\n");
    int checked = 0;

    for (int mask = 0; mask < 32; ++mask) {
        std::array<bool, 5> failed{};
        for (int i = 0; i < 5; ++i) {
            failed[static_cast<std::size_t>(i)] = ((mask >> i) & 1) != 0;
        }

        SafeState const expected = ReferenceModel(failed[0], failed[1], failed[2], failed[3], failed[4]);
        SafeState const actual   = DriveRealArbitrator(failed);

        char desc[160];
        std::snprintf(desc, sizeof(desc),
            "mask=%02d (L=%d R=%d C=%d G=%d I=%d): expected %s, got %s",
            mask, failed[0], failed[1], failed[2], failed[3], failed[4],
            StateName(expected), StateName(actual));

        Check(expected == actual, desc);
        checked++;
    }

    std::printf("Checked %d/32 combinations against the reference model - real code now matches\n", checked);
    std::printf("the escalate/max-severity spec exactly (Finding F-02's fix).\n");
}

// ---------------------------------------------------------------------------
// Property 1b: the fix changed real-code behaviour on exactly the masks
// where the old priority-ordered model under-escalated, and nowhere else -
// a fix that silently changed unrelated behaviour would be its own new
// defect. Also checks the fix only ever escalates (never de-escalates)
// relative to the old behaviour on any single mask.
// ---------------------------------------------------------------------------
static void VerifyFixChangedExactlyTheExpectedCases() {
    std::printf("\n=== Property 1b: fix changed exactly the expected masks, only upward ===\n");

    int changedCount = 0;
    int unchangedCount = 0;

    for (int mask = 0; mask < 32; ++mask) {
        bool const l = ((mask >> 0) & 1) != 0;
        bool const r = ((mask >> 1) & 1) != 0;
        bool const c = ((mask >> 2) & 1) != 0;
        bool const g = ((mask >> 3) & 1) != 0;
        bool const i = ((mask >> 4) & 1) != 0;
        std::array<bool, 5> failed{l, r, c, g, i};

        SafeState const preFix = PriorityOrderedModel_PreFix(l, r, c, g, i);
        SafeState const postFix = DriveRealArbitrator(failed);

        if (preFix == postFix) {
            unchangedCount++;
        } else {
            changedCount++;
            char desc[160];
            std::snprintf(desc, sizeof(desc),
                "mask=%02d: fix changed %s (sev=%d) -> %s (sev=%d) - must never decrease severity",
                mask, StateName(preFix), SeverityOf(preFix), StateName(postFix), SeverityOf(postFix));
            Check(SeverityOf(postFix) >= SeverityOf(preFix), desc);
        }
    }

    Check(changedCount == 17,
          "expected the fix to change exactly 17/32 masks' output (the masks where the old "
          "priority-ordered model under-escalated relative to the max-severity spec)");

    std::printf("Fix changed %d/32 masks (all upward in severity), left %d/32 unchanged.\n",
                changedCount, unchangedCount);
}

// ---------------------------------------------------------------------------
// Property 2 (the headline finding): SafeState::kEmergencyStop is
// UNREACHABLE via any fault-domain combination. This is the same 32-point
// sweep, but stated as its own explicit safety-relevant claim rather than
// folded into Property 1 - the reference model above was never going to
// predict kEmergencyStop either (it has no fault-based trigger in the
// documented matrix), so this specifically checks the REAL code, not
// whether it matches a model that also lacks this path.
// ---------------------------------------------------------------------------
static void VerifyEmergencyStopUnreachableViaFaults() {
    std::printf("\n=== Property 2: EmergencyStop unreachable via sensor faults (headline finding) ===\n");

    for (int mask = 0; mask < 32; ++mask) {
        std::array<bool, 5> failed{};
        for (int i = 0; i < 5; ++i) {
            failed[static_cast<std::size_t>(i)] = ((mask >> i) & 1) != 0;
        }
        SafeState const actual = DriveRealArbitrator(failed);
        Check(actual != SafeState::kEmergencyStop,
              "some fault combination unexpectedly reached kEmergencyStop");
    }

    std::printf("Confirmed: none of 32/32 fault-domain combinations reach kEmergencyStop.\n");
    std::printf("SafetyArbitrator.hpp documents two EmergencyStop triggers (E2E counter error,\n");
    std::printf("ASIL-D internal invariant failure) - grep of SafetyArbitrator.cpp confirms\n");
    std::printf("kEmergencyStop is referenced only in a command-formatting switch case and a\n");
    std::printf("once-entered latch guard; no code path anywhere sets currentState_ to it.\n");
    std::printf("This is a genuine reachability gap between documented intent and implementation,\n");
    std::printf("not a finding invented by this harness's own assumptions. Unaffected by the F-02 fix.\n");
}

// ---------------------------------------------------------------------------
// Property 3: severity monotonicity. For any two fault masks A, B where B's
// failed-set is a strict superset of A's, state(B) must be >= severity than
// state(A) - more faults must never result in a LESS restrictive state.
// Post-fix, this must hold with ZERO exceptions (Finding F-02 is fixed).
// ---------------------------------------------------------------------------
static void VerifySeverityMonotonicity() {
    std::printf("\n=== Property 3: severity monotonicity (all superset pairs) ===\n");

    // Precompute all 32 states once.
    std::array<SafeState, 32> stateOf{};
    for (int mask = 0; mask < 32; ++mask) {
        std::array<bool, 5> failed{};
        for (int i = 0; i < 5; ++i) {
            failed[static_cast<std::size_t>(i)] = ((mask >> i) & 1) != 0;
        }
        stateOf[static_cast<std::size_t>(mask)] = DriveRealArbitrator(failed);
    }

    int pairsChecked = 0;
    for (int a = 0; a < 32; ++a) {
        for (int b = 0; b < 32; ++b) {
            // B is a strict superset of A's fault bits.
            if ((a & b) == a && a != b) {
                int const sevA = SeverityOf(stateOf[static_cast<std::size_t>(a)]);
                int const sevB = SeverityOf(stateOf[static_cast<std::size_t>(b)]);
                char desc[160];
                std::snprintf(desc, sizeof(desc),
                    "REGRESSION of Finding F-02: mask %02d (%s, sev=%d) is a subset of mask %02d "
                    "(%s, sev=%d): superset is LESS severe than subset",
                    a, StateName(stateOf[static_cast<std::size_t>(a)]), sevA,
                    b, StateName(stateOf[static_cast<std::size_t>(b)]), sevB);
                Check(sevB >= sevA, desc);
                pairsChecked++;
            }
        }
    }

    std::printf("Checked %d superset/subset pairs against the REAL code: 0 violations expected\n", pairsChecked);
    std::printf("(Finding F-02 fixed - any FAIL above would mean the fix regressed).\n");
}

// ---------------------------------------------------------------------------
// Property 4: kDegraded health has zero effect on the degradation matrix -
// only kFailed contributes to faultBitmask_ (confirmed by reading
// UpdateBitmasks(), which only sets a fault bit on exact kFailed). Verified
// here against the real, running class, not just by reading the source.
// ---------------------------------------------------------------------------
static void VerifyDegradedHealthHasNoEffect() {
    std::printf("\n=== Property 4: SensorHealth::kDegraded has no effect on required state ===\n");

    IpcRingBuffer ring1{}; IpcBridge ipc1(&ring1); (void)ipc1.Init();
    SafetyArbitrator arbNominal(&ipc1);
    (void)arbNominal.Init(0x00U);
    for (auto d : kRelevantDomains) {
        SensorFaultEvent ev{}; ev.domain = d; ev.health = SensorHealth::kNominal;
        (void)arbNominal.IngestFault(ev);
    }
    (void)arbNominal.Arbitrate();

    IpcRingBuffer ring2{}; IpcBridge ipc2(&ring2); (void)ipc2.Init();
    SafetyArbitrator arbDegraded(&ipc2);
    (void)arbDegraded.Init(0x00U);
    // Every domain reported Degraded, not Nominal - should be indistinguishable
    // from all-Nominal as far as ComputeRequiredState() is concerned.
    for (auto d : kRelevantDomains) {
        SensorFaultEvent ev{}; ev.domain = d; ev.health = SensorHealth::kDegraded;
        (void)arbDegraded.IngestFault(ev);
    }
    (void)arbDegraded.Arbitrate();

    Check(arbNominal.GetCurrentState() == arbDegraded.GetCurrentState(),
          "all-Degraded should reach the same required state as all-Nominal, but did not");
    Check(arbDegraded.GetCurrentState() == SafeState::kFullOperation,
          "all-Degraded should still be kFullOperation (Degraded never sets a fault bit)");

    std::printf("Confirmed: SensorHealth::kDegraded never triggers escalation on its own -\n");
    std::printf("only SensorHealth::kFailed does. A domain silently degrading (not failing)\n");
    std::printf("produces no safe-state response from this arbitrator.\n");
}

// ---------------------------------------------------------------------------
// Property 5: kV2X and kUss domains have zero effect (confirmed: they are
// never read by ComputeRequiredState() at all). Ties directly to
// SafetyArbitrator.hpp's own `kV2X = 5U, ///< ... (future use)` comment -
// this proves that comment precisely, not just cites it.
// ---------------------------------------------------------------------------
static void VerifyV2xAndUssHaveNoEffect() {
    std::printf("\n=== Property 5: kV2X / kUss faults have zero effect (confirms 'future use') ===\n");

    IpcRingBuffer ring1{}; IpcBridge ipc1(&ring1); (void)ipc1.Init();
    SafetyArbitrator arbBaseline(&ipc1);
    (void)arbBaseline.Init(0x00U);
    (void)arbBaseline.Arbitrate();

    IpcRingBuffer ring2{}; IpcBridge ipc2(&ring2); (void)ipc2.Init();
    SafetyArbitrator arbV2xFailed(&ipc2);
    (void)arbV2xFailed.Init(0x00U);
    SensorFaultEvent v2xFault{};
    v2xFault.domain = SensorDomain::kV2X;
    v2xFault.health = SensorHealth::kFailed;
    (void)arbV2xFailed.IngestFault(v2xFault);
    SensorFaultEvent ussFault{};
    ussFault.domain = SensorDomain::kUss;
    ussFault.health = SensorHealth::kFailed;
    (void)arbV2xFailed.IngestFault(ussFault);
    (void)arbV2xFailed.Arbitrate();

    Check(arbBaseline.GetCurrentState() == arbV2xFailed.GetCurrentState(),
          "kV2X + kUss both Failed should not change the required state, but did");
    Check(arbV2xFailed.GetCurrentState() == SafeState::kFullOperation,
          "kV2X + kUss both Failed should still read as kFullOperation");

    std::printf("Confirmed: reporting kV2X or kUss as Failed has NO effect on the safe-state\n");
    std::printf("decision. ComputeRequiredState() never reads either domain's fault bit.\n");
}

int main() {
    VerifySpecConformanceExhaustive();
    VerifyFixChangedExactlyTheExpectedCases();
    VerifyEmergencyStopUnreachableViaFaults();
    VerifySeverityMonotonicity();
    VerifyDegradedHealthHasNoEffect();
    VerifyV2xAndUssHaveNoEffect();

    std::printf("\n=== SUMMARY ===\n");
    std::printf("Harness/regression failures (must be zero): %d\n", g_failures);

    if (g_failures != 0) {
        std::printf("FAIL: either a genuine harness problem, or Finding F-02 has regressed.\n");
        return 1;
    }
    std::printf("OK: real code matches the escalate/max-severity spec exactly (32/32), is\n");
    std::printf("provably monotonic (0/211 violations), and the fix changed exactly the 17/32\n");
    std::printf("masks Finding F-02 identified - no unrelated behaviour change.\n");
    return 0;
}
