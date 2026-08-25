# Coverage Deviation Record

Real, measured `gcov` line coverage as of this writing (host-native, GCC 12.2.0,
`--coverage -O0`, `sotif-gate` test suite run against the vendored real
`autosar-soa-gateway` sources):

| Module | File | Line coverage | Gate |
|---|---|---|---|
| sotif-gate | `SotifPlausibilityGate.cpp` | **97.93%** (142/145 lines) | ≥ 90% (CI-enforced) |
| pqc-kem-extension | `PqcKemPlatformInterface.cpp` | **100.00%** (6/6 lines) | ≥ 90% (CI-enforced) |
| pqc-signature-extension | `HybridAuthGate.cpp` | **100.00%** (16/16 lines) | ≥ 90% (CI-enforced) |
| pqc-signature-extension | `PqcSignaturePlatformInterface.cpp` | **100.00%** (6/6 lines) | not separately gated — same file shape as `pqc-kem-extension`'s |
| v2x-trust-extension | `V2xTrustVerifier.cpp` | **94.87%** (37/39 lines) | ≥ 90% (CI-enforced) |
| v2x-trust-extension | `V2xNetworkAdapter.cpp` | **97.25%** (106/109 lines) | ≥ 90% (CI-enforced) |

This number moved from an initial 75.86% to 97.93% over several rounds of
adding tests for branches the first coverage run showed were never exercised
(`IngestSoaEvent`, `GetRejectCount`, the static `SoaServiceManager` adaptor
pair, `Init()`'s invalid-config path, non-finite-input rejection, the
low-confidence branch specifically isolated from the disagreement branch).
Three of those additions caught real test bugs before they shipped — see
`sotif-gate`'s test file history / commit log for what each one was.

## The remaining 3 uncovered lines in `SotifPlausibilityGate.cpp`, and why

| Line | What it is | Why it's not covered |
|---|---|---|
| `MonotonicMs()`'s `clock_gettime` failure branch | `if (clock_gettime(...) != 0) { return 0U; }` | `clock_gettime(CLOCK_MONOTONIC, ...)` failing on a running Linux/POSIX system is not practically triggerable from a unit test without either mocking the syscall (not done — would add a seam purely for this one line) or running under fault-injection tooling this repository doesn't have access to (matching `SafetyArbitrator`'s own documented approach: real fault injection is a `docs/`-level test-plan item, not something invented here to force one line green). |
| `EscalateToSafeState`'s `if (ipc_ == nullptr) { return; }` | Defensive early-return | **Currently unreachable given the class invariant**: `Init()` unconditionally rejects a null `ipc_` (checked first, before anything else), so `initialised_` can never become `true` while `ipc_` is null, and `EscalateToSafeState` is only ever called from `Evaluate()`, which itself requires `initialised_ == true` to reach this far. Kept anyway as defensive programming — a future refactor that decouples `ipc_` from the `Init()` invariant would silently reintroduce a real null-dereference risk here without it. |
| `Evaluate()`'s `if (ipc_ == nullptr) { return Err(kNullPointer); }` | Same defensive early-return | Same reasoning as above — unreachable under the current `Init()` invariant, kept for the same future-proofing reason. |

**This is a documented deviation, not a hidden gap.** Both "unreachable given
current invariant" lines are intentionally kept rather than removed, because
removing them would be optimizing for a coverage percentage rather than for
the actual property they protect (if the invariant between `Init()` and
`ipc_` non-nullness is ever broken by a future change, these lines are the
last line of defense against a null-pointer dereference in what would then be
a genuinely reachable path). ISO 26262-6 §9.4.5 and MISRA C++:2023 both
tolerate exactly this class of documented deviation over forcing artificial
line coverage.

## The remaining uncovered lines in `v2x-trust-extension`, and why

Both files' uncovered lines are `CryptoPlatformInterface::ComputeSha256`
failure branches:

| File | Line | Why it's not covered |
|---|---|---|
| `V2xTrustVerifier.cpp` | `VerifyCertSignature`'s `if (... ComputeSha256(...) != CryptoStatus::kOk) { return false; }` | The real, vendored `SoftwareCryptoProvider::ComputeSha256` only returns non-`kOk` for a null pointer or zero-length input (see `vendor/zonal-zero-trust-auth/src/CryptoPlatformInterface.cpp`). The 41-byte cert message buffer this function hashes is always a non-null, fixed-size stack array — this branch is unreachable with the software mock. It is retained because a production `HseCryptoProvider`/`TrustZoneCryptoProvider` backend can genuinely report a hardware/accelerator fault here (`CryptoStatus::kHwFault`), and this project's established practice (`sotif-gate`'s own deviation record above) is to keep such defensive checks rather than remove them for a coverage number. |
| `V2xTrustVerifier.cpp` | `VerifyChain`'s `if (... ComputeSha256(payload...) != CryptoStatus::kOk) { return kCryptoError; }` | Same reasoning — the payload buffer is non-null and non-zero-length by the time this line is reached (`kInvalidInput` is already returned earlier for a zero/oversized `payload_len`). |
| `V2xNetworkAdapter.cpp` | `Deserialise`'s `if (... ComputeSha256(pseudonym_cert.subject_public_key...) != CryptoStatus::kOk) { ...; return kUnknown; }` | Same reasoning — `subject_public_key` is a fixed 33-byte `std::array`, never null or zero-length. |

**This is a documented deviation, not a hidden gap**, for the same reason
`sotif-gate`'s two defensive-early-return lines above are: removing these
checks would optimize for a coverage percentage at the expense of the actual
property they protect against a different, real `CryptoPlatformInterface`
implementation. Two genuinely dead branches that this module's own logic
made structurally impossible (not merely hard to trigger with the current
mock) were found during this same review and removed rather than kept for
coverage padding: a redundant `V2xTrustStatus::kInvalidInput` check in
`V2xNetworkAdapter::Deserialise` (already unreachable because the function's
own `payload_len == kBsmCorePayloadBytes` gate immediately above it
guarantees `V2xTrustVerifier::VerifyChain` can never return that status),
and a `payloadLen > frame.data.size()` bounds check in
`V2xNetworkAdapter::Serialise` (`SoaEvent::payloadLen` is a `std::uint8_t`,
whose maximum value of 255 can never exceed `WireFrame::data`'s 1472-byte
capacity).

## What is NOT yet done here, unlike `safety-supervisor`'s coverage story

- No **function coverage** or **branch/MC-DC coverage** measurement — only
  line coverage. `safety-supervisor`'s README reports both line (81.8%) and
  function (89.7%) coverage; MC/DC specifically (condition-level, required
  for ASIL D per ISO 26262-6 Table 12) has not been measured for this
  repository at all, `gcov` alone does not produce it.
- No stack usage analysis (`.su` files) — this repository's code is
  host-native only; it has never been cross-compiled for the actual M7/A53
  targets `autosar-soa-gateway` ships to, so there is no real target binary
  to analyze stack usage for yet.
- No independent tool-qualification of GCC 12.2.0 or `gcov` itself per
  ISO 26262-8 clause 11.
