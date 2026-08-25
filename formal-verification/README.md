# formal-verification

Exhaustive state-space verification of `autosar-soa-gateway`'s real,
unmodified `SafetyArbitrator::ComputeRequiredState()` degradation matrix —
driving the actual compiled class through its real public API, not a
hand-written model of its logic.

**👉 [`docs/FINDINGS.md`](docs/FINDINGS.md) is the actual deliverable of
this module.** It documents four findings. One of them, F-02 — severity was
not monotonic under compound sensor loss (43 counter-examples found and
listed) — was a real, reproducible, safety-relevant defect in the real
code, and **has since been fixed upstream in `autosar-soa-gateway`**: this
harness now asserts the corrected behavior (32/32 spec match, 0/211
monotonicity violations) against the fixed, vendored source, rather than
merely documenting the pre-fix defect.

## Why exhaustive enumeration, not TLA+/TLC

No Java toolchain was available in the environment this was built in
(checked before choosing this method, not assumed). This is not a lesser
substitute for the property actually being checked here:
`ComputeRequiredState()` is a pure function of a 5-bit fault bitmask
(confirmed by reading the source), so exhaustive enumeration over all 32
inputs **is** a complete proof over that domain — the same thing a model
checker would do for a state space this size, regardless of which tool
runs it.

## What's here

- `harness/verify_safety_arbitrator.cpp` — the verifier. Six properties:
  1. Exhaustive spec-conformance against the escalate/max-severity model —
     **32/32 match**, post-fix.
  2. The fix changed output on exactly the 17/32 masks it should have,
     always upward in severity, and nowhere else (regression guard).
  3. `kEmergencyStop` unreachability via any of the 32 fault combinations
     (Finding F-03).
  4. Severity monotonicity — **0/211 violations**, post-fix (any `FAIL`
     here would mean Finding F-02 regressed).
  5. `SensorHealth::kDegraded` has no escalation effect (Finding F-04).
  6. `kV2X`/`kUss` faults have no effect (Finding F-01).
- `vendor/autosar-soa-gateway/` — real `SafetyArbitrator` (fixed version) +
  `IpcBridge` (headers + `.cpp`), vendored read-only. Not owned by this
  repository.
- `docs/FINDINGS.md` — the write-up, including F-02's pre-fix mechanism and
  proof (kept as the historical record) and the fix that closed it.

## What this does not do

- Does not modify `autosar-soa-gateway` files as part of this repository's
  own build or CI — the fix that closed Finding F-02 was applied directly
  in `autosar-soa-gateway`'s own repository (see its `CHANGELOG.md`), and
  the fixed file was then re-vendored here read-only, same as every other
  module in this project.
- Does not decide whether specific compound sensor-loss combinations should
  escalate to `kMinimalRiskCondition` rather than reusing the highest
  existing single-fault state — that remains a HARA-level judgement for
  norxs's real safety team, stated explicitly in `docs/FINDINGS.md` as out
  of this module's authority. The fix guarantees the monotonicity floor,
  not a specific HARA-derived target for every compound case.
- Does not verify the mandatory-domain fault-count threshold path (a
  temporal/sequential dimension — `faultCount` accumulates across calls)
  with the same exhaustiveness as the bitmask sweep; that path is exercised
  but not combinatorially proven here.
- Does not verify anything about the Cortex-M7 side (`SwcSafetyArbitrator`
  in `safety-supervisor`) — this module's scope is the A53-side
  `SafetyArbitrator` in `autosar-soa-gateway` only.

## Build & run

```sh
cd harness
g++ -std=c++14 -Wall -Wextra -Wshadow -Wconversion -Wcast-qual \
    -I../vendor/autosar-soa-gateway/include \
    -o verify verify_safety_arbitrator.cpp \
    ../vendor/autosar-soa-gateway/src/SafetyArbitrator.cpp \
    ../vendor/autosar-soa-gateway/src/IpcBridge.cpp
./verify
```

Exit code 0 means: the real (fixed) code matches the escalate/max-severity
spec exactly (32/32), is provably monotonic (0/211 violations), and the fix
changed behavior on exactly the 17/32 masks Finding F-02 identified — no
unrelated behavior change. A non-zero exit means either a genuine harness
problem or a regression of Finding F-02.
