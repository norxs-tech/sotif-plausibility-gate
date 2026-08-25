# sotif-gate

ISO 21448 (SOTIF) plausibility check for AI perception candidates, positioned
upstream of `autosar-soa-gateway`'s `SafetyArbitrator`. See the top-level
`README.md` for why this is not redundant with that class.

## What's here

- `include/norxs/SotifPlausibilityGate.hpp` / `src/SotifPlausibilityGate.cpp`
  — the gate itself: `PerceptionCandidateEvent` (new event type, IPC-aligned
  POD), three deterministic checks (cross-estimate confidence, calibration
  drift, freshness/replay), and an escalation path that packs a
  `SafeStateCommand` and sends it via the real `IpcBridge`.
- `vendor-autosar-soa-gateway/` — real headers and two `.cpp` files copied
  from `autosar-soa-gateway` for this build. **Not owned by this
  repository** — the actual dependency is that repository; these are vendored
  read-only for compilation, and must be re-synced if that repository's
  interfaces change.
- `tests/test_SotifPlausibilityGate.cpp` — 7 tests, including
  `test_rejection_produces_valid_e2e_protected_ipc_slot`, which links the
  real `IpcBridge.cpp` and asserts the real `IpcBridge::VerifyE2e()` accepts
  a slot this module produced. That is executed proof of interop, not a
  claim of it.

## What this does not do

- Does not modify `SafetyArbitrator.hpp`/`.cpp` — zero changes to that
  repository are required to deploy this.
- Does not implement TC-02 (out-of-distribution) or TC-04 (adversarial
  input) — same reasoning as `sotif-plausibility-monitor` in the earlier
  `sotif-asil-bridge` project: a learned check inside this gate would carry
  its own unresolved SOTIF problem.
- Does not implement the actual `SoaServiceManager::Subscribe()` wiring —
  `SetGlobalSotifGate()` / `SotifGateEventHandler()` are the integration
  points; connecting them to a live service ID is the integrator's job.

## Build & test

```sh
g++ -std=c++14 -Wall -Wextra -Werror -Wshadow -Wconversion -Wcast-qual \
    -Iinclude -Ivendor-autosar-soa-gateway/include \
    -o gate_test src/SotifPlausibilityGate.cpp \
    vendor-autosar-soa-gateway/src/IpcBridge.cpp \
    tests/test_SotifPlausibilityGate.cpp
./gate_test
```
