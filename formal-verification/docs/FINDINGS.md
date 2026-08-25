# Formal Verification Findings — `SafetyArbitrator::ComputeRequiredState()`

**Method:** exhaustive state-space enumeration against the real, unmodified,
compiled `SafetyArbitrator` class (linked from vendored real source, driven
through its real public API), not a hand-written model of its logic.
TLA+/TLC was not used — no Java toolchain was available in the environment
this was built in (`which java` found nothing, checked before choosing this
method). This is not a lesser substitute for the property actually being
checked: `ComputeRequiredState()` is a pure function of a 5-bit fault
bitmask (confirmed by reading the source — it reads only `faultBitmask_`
and, on the mandatory-domain path, `mandatoryMask_`/`faultCount`), so
exhaustive enumeration over all 32 inputs **is** a complete proof over that
domain, which is what a model checker would ultimately do for a
state space this size regardless of tool.

Reproduce: `cd harness && g++ -std=c++14 -Wall -Wextra -Wshadow -Wconversion
-Wcast-qual -I../vendor/autosar-soa-gateway/include -o verify
verify_safety_arbitrator.cpp ../vendor/autosar-soa-gateway/src/SafetyArbitrator.cpp
../vendor/autosar-soa-gateway/src/IpcBridge.cpp && ./verify` — exit code 0
means every property held with zero violations (see the harness's own
summary logic).

**Note on vendored source version:** `vendor/autosar-soa-gateway/src/
SafetyArbitrator.cpp` was updated to the FIXED version once Finding F-02
(below) was corrected upstream. The harness asserts the fixed behavior
(32/32 spec match, 0/211 monotonicity violations) rather than merely
documenting the pre-fix defect. Finding F-02's original mechanism and
exhaustive-proof sections below are kept as the historical record of what
was found and how — only its Status line changed.

---

## Finding F-01 — `kV2X` and `kUss` sensor faults have zero effect

`ComputeRequiredState()` never reads the fault bit for `SensorDomain::kV2X`
or `SensorDomain::kUss` — confirmed both by reading the source (it only
evaluates `lidarFailed`, `radarFailed`, `cameraFailed`, `gnssFailed`,
`imuFailed`) and by exhaustively driving the real class with both domains
reported `kFailed`: the resulting `SafeState` is identical to the baseline
(`kFullOperation`). This precisely confirms
`SafetyArbitrator.hpp`'s own `kV2X = 5U, ///< ... (future use)` comment — it
is not a guess about intent, it is a proof that the current implementation
matches that stated intent exactly. Not a defect; a scope boundary, now
precisely characterized rather than assumed.

**Severity:** informational. **Status:** confirmed, not a defect.

---

## Finding F-02 — Severity is not monotonic under compound sensor loss

**FIXED.** This was a real safety-relevant defect in the priority-ordered
if/else-return structure of `ComputeRequiredState()`, found by exhaustive
enumeration, independently re-derived in plain Python to rule out a harness
bug, and reproducible from the real vendored source alone. It has since
been corrected upstream in `autosar-soa-gateway` — see "The fix, applied"
below. The mechanism and exhaustive-proof sections that follow describe the
**pre-fix** behavior and are kept as the record of what was found.

### The mechanism

`ComputeRequiredState()` evaluates conditions in priority order and
`return`s on the first match. It never considers whether additional,
lower-priority conditions are *also* true. Concretely:

```
if (lidarFailed && !radarFailed) { return kRadarCameraFallback; }   // checked 3rd
...
if (cameraFailed)                 { return kLidarRadarFallback; }    // checked 5th
```

If **both** `lidar` and `camera` are failed (radar still healthy), the
3rd check fires first and returns `kRadarCameraFallback` — a state whose
own name claims the camera is one of the two sensors being relied on for
fallback, while the function's own input says the camera is *also* down.
The 5th check, which would have escalated further, is never reached.

### Exhaustive proof

Enumerating all 32 fault-bitmask combinations and checking every
subset/superset pair (211 pairs total: does adding more failed sensors ever
produce a *less* severe result?) against the real, running class finds
**43 violations** of the property "more simultaneous sensor faults must
never result in a less severe commanded state." Two representative
examples (full list is the harness's own stdout):

| Fewer faults (subset) | Result | More faults (superset) | Result | |
|---|---|---|---|---|
| Camera only | `kLidarRadarFallback` (sev. 3) | Camera + Lidar | `kRadarCameraFallback` (sev. 1) | severity **decreased** |
| GNSS only | `kDeadReckoningMode` (sev. 4) | GNSS + Lidar | `kRadarCameraFallback` (sev. 1) | severity **decreased** |

### Why this matters

The `SafeStateCommand` this function's result feeds into (`maxSpeedKph`,
`maxDecelMps2`) is set based on the *returned* state, not on which sensors
are actually down. In the camera+lidar example above, the vehicle would be
commanded the `kRadarCameraFallback` envelope (implying trust in a camera
that is not actually functioning) instead of a stricter one — a real
under-restriction, not a cosmetic labeling issue.

### The fix, applied

`ComputeRequiredState()` was corrected in `autosar-soa-gateway` to evaluate
every triggering condition and take the **most severe** result across all
that apply, instead of returning on the first match — exactly the
`escalate()` pattern this document's corrected reference model proposed. It
is a minimal, mechanical fix: the `if (...) return X;` chain became
`if (...) escalate(X);` calls against a single running `result`, plus the
`escalate` helper; nothing else about the function's structure changed.
The separate mandatory-domain fault-threshold path (a different signal —
accumulated fault count over time, not the instantaneous bitmask) was
outside this finding's scope and is untouched.

Post-fix, this repository's harness (`vendor/autosar-soa-gateway/src/
SafetyArbitrator.cpp` updated to the fixed version) proves, against the
real running class:
- **32/32** fault combinations now match the escalate/max-severity spec
  exactly (Property 1).
- **0/211** monotonicity violations (Property 3) — the defect is gone, not
  merely reduced.
- The fix changed output on **exactly 17/32** masks relative to the old
  priority-ordered behavior, and only ever *increased* severity on those —
  no unrelated behavior changed (Property 1b).

**What this fix does NOT claim to do:** decide whether a specific compound
failure (camera+lidar, radar still healthy) should reuse the highest
*existing* single-fault state (what the fix does) or actually warrant a
*new* target such as `kMinimalRiskCondition` (arguably correct for
camera+lidar specifically, since that leaves only radar — a similar
loss-of-primary-perception severity to the lidar+radar case that already
triggers MRC). That remains a HARA-level judgement requiring real
controllability/exposure analysis this document does not have the
authority or the input data to make unilaterally. What the fix delivers is
the provable **floor**: the result is now never *less* severe than the
worst single contributing fault, for every one of the 32 possible
combinations — not merely for the specific pairs originally checked by
hand.

One existing `autosar-soa-gateway` test
(`T5_LidarFailedAndCameraFailed_...`) encoded the old, incorrect
first-match behavior as its expected output and was corrected alongside
the fix; every other existing test was unaffected.

**Severity:** was real, reproducible, safety-relevant. **Status:** FIXED in
`autosar-soa-gateway` — see that repository's `CHANGELOG.md` and the commit
correcting `ComputeRequiredState()`.

---

## Finding F-03 — `SafeState::kEmergencyStop` is unreachable

`SafetyArbitrator.hpp`'s own class documentation states two triggers for
`kEmergencyStop`: "Any E2E counter error" and "Any ASIL-D internal
invariant fail." Grepping `SafetyArbitrator.cpp` for `kEmergencyStop` finds
exactly three references: a `case` label in the command-payload formatting
switch (what to send *if* the state were ever `kEmergencyStop`), a
once-entered latch guard (*if* current state is already `kEmergencyStop`,
stay there), and the enum declaration itself. **No code path anywhere sets
`currentState_` to `kEmergencyStop`.** `ComputeRequiredState()` — the only
function that determines the required state from sensor faults — has seven
possible return values, never the eighth. Exhaustively confirmed: none of
the 32 fault-bitmask combinations produce it (Property 2 in the harness).

Neither of the two documented triggers (E2E counter errors, ASIL-D
invariant failures) is a sensor-domain fault, so this finding is
independent of — and additional to — Finding F-02. It's possible E2E
violations are handled elsewhere in the real system (e.g. by
`IamSecurityController` or `IpcBridge` before a frame ever reaches
`SafetyArbitrator`), which this repository has not been asked to verify.
What is proven here is narrower and unambiguous: within
`SafetyArbitrator.cpp` itself, the documented emergency-stop behavior has
no implementation.

**Severity:** real gap between documented safety behavior and
implementation; needs a decision from norxs's team on whether the trigger
belongs in this class or is genuinely handled upstream. **Status:**
confirmed absence, exhaustively.

---

## Finding F-04 — `SensorHealth::kDegraded` never escalates on its own

`UpdateBitmasks()` only sets a fault bit on exact `SensorHealth::kFailed`;
`kDegraded` and `kUnknown` are both invisible to `ComputeRequiredState()`.
Confirmed by driving the real class with every domain reported `kDegraded`
— result is identical to all-`kNominal` (`kFullOperation`). A domain that
is degrading but not yet fully failed produces zero safe-state response.
This may be intentional (avoid nuisance escalation on transient
degradation) or may be a gap depending on what "Degraded" is meant to
represent operationally — not resolved here, since that requires the same
kind of domain input Finding F-02's full fix does.

**Severity:** informational / needs a product decision. **Status:**
confirmed behavior, not asserted as a defect.
