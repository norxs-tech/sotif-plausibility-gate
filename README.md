# norxs SOTIF Plausibility Gate & PQC Extensions

### Five additive extensions to the norxs SOA Gateway safety/security architecture

**norxs Technology LLC** | Safety Engineering, Built from the Ground Up.

[![CI](https://github.com/norxs-tech/sotif-plausibility-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/norxs-tech/sotif-plausibility-gate/actions)
[![License](https://img.shields.io/badge/license-norxs%20RI%20v1.0-blue)](LICENSE)
[![Standard](https://img.shields.io/badge/standard-AUTOSAR%20C%2B%2B14-green)]()
[![Safety](https://img.shields.io/badge/safety-ISO%2021448%20SOTIF-red)]()
[![Security](https://img.shields.io/badge/security-NIST%20FIPS%20203%2F204-orange)]()
[![Tests](https://img.shields.io/badge/tests-40%2F40%20passing-brightgreen)]()
[![Interop](https://img.shields.io/badge/interop-real%20IpcBridge%20%2B%20real%20SpdmProtocolEngine-blueviolet)]()

---

## What This Is

Five independent, additive extensions to companion repositories already
published under `norxs-tech` — not reimplementations of them, and not
duplicates of anything that already exists there:

1. **`sotif-gate/`** — an ISO 21448 (SOTIF) plausibility check inserted
   upstream of `autosar-soa-gateway`'s `SafetyArbitrator`, closing a gap that
   repository's own header documentation names but its implementation does
   not close (see below — this is not a guess, it's read directly from that
   repository's source).
2. **`pqc-kem-extension/`** — a post-quantum Key Encapsulation Mechanism
   (ML-KEM-768 / FIPS 203) extension point for `zonal-zero-trust-auth`'s
   `CryptoPlatformInterface`, which today defines exactly four classical
   primitives and no KEM at all.
3. **`pqc-signature-extension/`** — a hybrid ML-DSA-65 (FIPS 204) signature
   check composed on top of `zonal-zero-trust-auth`'s real
   `SpdmProtocolEngine`, closing the post-quantum gap in its pinned-public-key
   peer authentication (see below for why this is *not* "PQC-migrating an
   X.509 chain," a framing this document corrected once the real code was
   read).
4. **`formal-verification/`** — exhaustive state-space verification of
   `autosar-soa-gateway`'s real `SafetyArbitrator::ComputeRequiredState()`,
   which **found a real, reproducible severity-monotonicity defect** (43
   counter-examples: compound sensor loss could produce a *less* restrictive
   commanded state than a single sensor loss) — not a hypothetical risk, an
   exhaustively-proven property of the real, currently-shipping code. The
   defect has since been **fixed upstream in `autosar-soa-gateway`** (real
   code now provably monotonic, 0/211 violations); this module's harness
   was updated to assert the fix against the real class rather than merely
   document the defect.
5. **`v2x-trust-extension/`** — certificate-chain trust verification for V2X
   (Vehicle-to-Everything) messages, closing the gap
   `SafetyArbitrator.hpp`'s own `SensorDomain::kV2X = 5U, ///< Vehicle-to-
   Everything (future use)` comment names but that neither real repository
   implements. Includes the first concrete implementation of
   `autosar-soa-gateway`'s abstract `NetworkAdapter` interface anywhere in
   the norxs reference repos.

**This is exploratory reference work, not the production software norxs
builds for clients** (that is what `autosar-soa-gateway`, `safety-supervisor`,
`tsn-zonal-backbone`, `automotive-idps-agent`, and `zonal-zero-trust-auth`
already are). This repository exists to show where those systems' own
documented scope still has room to grow, and to prove — in compiled, tested,
real-interop code — exactly how far that growth path goes before it needs
norxs's production engineering to finish it.

---

## Why `sotif-gate/` is not redundant with `SafetyArbitrator`

`autosar-soa-gateway/include/SafetyArbitrator.hpp` documents its standards as:

```
@standards   AUTOSAR C++14, ISO 26262 Part 3/4/6, SOTIF ISO 21448, UN R155
```

Its actual mechanism — read directly from that header — is a
`SensorFaultMonitor` + `DegradationMatrix` + hardcoded `PhysicalEnvelope` ROM
invariants (`kMaxLateralAccelMps2`, `kMaxSteeringAngleDeg`, ...). Every one of
its `Validate*` methods asks *"is this number inside a fixed physical bound?"*
and every fault path asks *"is this sensor domain reporting Nominal, Degraded,
or Failed?"* Neither question is SOTIF's question. ISO 21448 exists for the
case where every sensor domain reports `kNominal`, every physical bound is
satisfied, and the AI's judgement is still wrong — because its own confidence
estimate is internally inconsistent, or its calibration has silently drifted.
`SafetyArbitrator` cannot see that; it was never designed to, and its own
class-level architecture diagram (in the same header) doesn't claim to.

`SotifPlausibilityGate` closes exactly that gap and nothing else. It does not
re-validate physical bounds — `SafetyArbitrator` already does that correctly
and this module never calls or duplicates `Validate*`. It does not touch
sensor fault handling. It sits upstream, and on rejection, sends its own
conservative `SafeStateCommand` through the *same* `IpcBridge`, using the
*same* reserved `serviceId`/`eventId` (`0xFF00`/`0xFF01`) `SafetyArbitrator`
uses — proven in `sotif-gate/tests/`, where a rejection produces a real
`IpcSlot` that the real `IpcBridge::VerifyE2e()` accepts. The M7 supervisor
needs zero changes to honour a SOTIF-triggered safe state.

## Why `pqc-kem-extension/` is not redundant with `CryptoPlatformInterface`

`zonal-zero-trust-auth/include/zzta/CryptoPlatformInterface.hpp` defines
exactly four pure-virtual primitives: `GenerateRandomNonce`, `ComputeSha256`,
`VerifyEccSignature`, `DeriveSessionKey`. All four are classical
(ECDSA-P256/SHA-256/HKDF). There is no encapsulation/decapsulation method
anywhere in that interface, confirmed by reading the header directly rather
than assumed. That's a reasonable scope for today's threat model — it is also
exactly the scope a harvest-now-decrypt-later adversary is betting stays
unchanged for the next decade of fielded vehicles.

## Why `pqc-signature-extension/` targets a pinned-key table, not "an X.509 chain"

`zonal-zero-trust-auth/include/zzta/SpdmProtocolEngine.hpp` documents its
peer trust model precisely: `KnownPeerEntry` is a compile-time `.rodata`
table of raw `{ClientId, EccPublicKey}` pairs. Its own comment says a
production system would generate this table from an OEM-signed certificate
chain during secure boot — but no chain-parsing or -verification code exists
anywhere in the repository to migrate. The real, narrower, verified gap: the
pinned ECDSA-P256 key and the `CHALLENGE_AUTH` signature it verifies have no
post-quantum equivalent. `HybridAuthGate` adds a second, independent ML-DSA-65
signature check on top of the real, unmodified `SpdmProtocolEngine` — proven
by a test that runs a complete classical handshake through the actual
vendored engine and then confirms a failed PQC check calls the engine's own
real `Revoke()`, observed via its own real `GetState()`.

## Why `formal-verification/` is not a hypothetical exercise

`SafetyArbitrator::ComputeRequiredState()` *used to be* a priority-ordered
chain of `if (...) return X;` statements — it returned on the **first**
matching condition and never checked whether other, lower-priority
conditions were *also* true. Exhaustively driving the real, compiled class
through all 32 possible combinations of its five relevant sensor-fault
inputs and checking "does adding more simultaneous faults ever produce a
less severe result?" found **43 cases where it did** — e.g. camera failing
alone correctly reached `kLidarRadarFallback` (severity 3), but camera
*and* lidar failing together reached `kRadarCameraFallback` (severity 1), a
**less** restrictive state, because the lidar check happened to come first
in the chain and returned before the camera condition was ever evaluated.
This was independently re-derived in plain Python (no C++, no shared code
with the harness) before being reported as a finding, specifically to rule
out a harness bug before calling it a defect in the real code.

**This has since been fixed.** `ComputeRequiredState()` now evaluates every
condition and escalates to the most severe match instead of returning on
the first one — the exact fix this module's exhaustively-verified corrected
model proposed. Re-running the harness against the fixed, re-vendored real
class confirms: 32/32 exact match against the escalate/max-severity spec,
0/211 monotonicity violations, and the fix changed output on exactly the
17/32 masks the finding identified — no unrelated behavior change. Full
detail, including the pre-fix mechanism (kept as the historical record) and
the fix itself, is in `formal-verification/docs/FINDINGS.md`.

## Why `v2x-trust-extension/` builds a certificate chain instead of reusing `zonal-zero-trust-auth`'s trust model

`SpdmProtocolEngine`'s `KnownPeerEntry` is a compile-time `.rodata` table of
raw pinned public keys — correct for a closed set of in-vehicle zonal ECUs
provisioned at manufacture time, structurally impossible for V2X, where the
vehicle must trust messages from other vehicles and infrastructure it has
never seen before. `v2x-trust-extension` implements the certificate-chain
shape real V2X (IEEE 1609.2, the standard SAE J2735 Basic Safety Messages
are signed under) actually uses — root → intermediate → rotating pseudonym
certificate → message signature — reusing `zonal-zero-trust-auth`'s real
`EccPublicKey`/`CryptoSignature`/`Sha256Digest` types and its real
`VerifyEccSignature`/`ComputeSha256` PAL calls for every cryptographic
operation. No signature primitive is implemented here.

Just as important is what a verified V2X message does **not** do: it is
never fed into `SafetyArbitrator::IngestFault()`. Authenticating a message
proves who plausibly sent it, not that its claimed position/speed/heading is
physically true — that is the same SOTIF-plausibility question
`sotif-gate` already asks of the vehicle's own perception stack. A verified
message becomes a `CooperativeAwarenessAdvisory` (an unconfirmed, externally
attributed input), never a `SensorFaultEvent` — see
`v2x-trust-extension/include/norxs/CooperativeAwarenessAdvisory.hpp` for
the full reasoning. `V2xNetworkAdapter` is also the first concrete
implementation of `autosar-soa-gateway`'s abstract `NetworkAdapter`
interface in the norxs reference repos — the real repository ships that
interface alone, with no concrete SOME/IP or DDS adapter to duplicate.

---

## System Architecture

```
┌──────────────────────────────────────────────────────────┐
│                 autosar-soa-gateway (existing)             │
│                                                            │
│   [Orin AI Domain] → NetworkAdapter → RateLimiter          │
│         → IamSecurityController → SoaServiceManager        │
│               │                                            │
│               │  SoaEvent (perception candidate)           │
│               ▼                                            │
│   ╔══════════════════════════════╗                        │
│   ║   SotifPlausibilityGate      ║ ← NEW (sotif-gate/)     │
│   ║   cross-estimate confidence  ║                         │
│   ║   calibration-drift check    ║                         │
│   ║   freshness / replay guard   ║                         │
│   ╚═══════════════╤═══════════════╝                        │
│         accepted   │        rejected → conservative        │
│         only       │          SafeStateCommand, same        │
│               ▼    │          IpcBridge channel             │
│   SafetyArbitrator::Validate* (unchanged, physical bounds)  │
│               │                                            │
│               ▼                                            │
│   IpcBridge → E2E Profile 5 → shared SRAM → M7 supervisor  │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│              zonal-zero-trust-auth (existing)               │
│                                                            │
│   SpdmProtocolEngine → CryptoPlatformInterface              │
│     (GenerateRandomNonce, ComputeSha256,                    │
│      VerifyEccSignature, DeriveSessionKey — classical)      │
│               │                                            │
│               │  extension point                           │
│               ▼                                            │
│   ╔══════════════════════════════╗                        │
│   ║  PqcKemPlatformInterface      ║ ← NEW (pqc-kem-ext/)    │
│   ║  GenerateKeyPair / Encaps /   ║                         │
│   ║  Decaps — ML-KEM-768 shape    ║                         │
│   ╚═══════════════╤═══════════════╝                        │
│                    │                                        │
│         UnavailablePqcKemProvider — fails closed,            │
│         no real backend linked (see that dir's README)      │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│         zonal-zero-trust-auth (existing) — SPDM side        │
│                                                            │
│   SpdmProtocolEngine (real, unmodified)                     │
│   ProcessAuthRequest → ProcessAuthResponse (classical        │
│   ECDSA-P256, verified via CryptoPlatformInterface)          │
│               │ kOk → state == kAuthenticated                │
│               ▼  (a live SpdmSessionToken now exists)        │
│   ╔══════════════════════════════╗                        │
│   ║  HybridAuthGate::ConfirmHybrid║ ← NEW (pqc-signature-ext/)│
│   ║  ML-DSA-65 verify over the    ║                         │
│   ║  same (nonce ‖ client_id)     ║                         │
│   ╚═══════════════╤═══════════════╝                        │
│      kOk │              │ verify fails                      │
│      only▼              ▼                                   │
│  session truly    engine.Revoke() — the engine's OWN         │
│  trusted          real API, called before returning          │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│      autosar-soa-gateway (existing) — V2X ingress side      │
│                                                            │
│   Remote vehicle / RSU  →  raw WireFrame (468 bytes:         │
│   payload_len + BSM core + pseudonym_cert +                  │
│   intermediate_cert + bsm_signature)                          │
│               │                                            │
│               ▼                                            │
│   ╔══════════════════════════════╗                        │
│   ║  V2xNetworkAdapter            ║ ← NEW (v2x-trust-ext/) │
│   ║  (first concrete               ║   implements the       │
│   ║   NetworkAdapter impl)         ║   real, abstract        │
│   ║  ::Deserialise()                ║   NetworkAdapter        │
│   ║    → V2xTrustVerifier           ║   interface             │
│   ║      ::VerifyChain()            ║                         │
│   ╚═══════════════╤═══════════════╝                        │
│      kTrusted only │            untrusted/malformed          │
│                    ▼                  → no event published   │
│   SoaEvent(CooperativeAwarenessAdvisory) — NOT               │
│   SafetyArbitrator::IngestFault() (see README "Why" section) │
│               │                                            │
│               ▼                                            │
│   SoaServiceManager::PublishEvent() (real, unmodified)       │
└──────────────────────────────────────────────────────────┘
```

---

## Module Inventory

| Module | Companion repository | Tests | Standard |
|---|---|---|---|
| [`sotif-gate/`](sotif-gate/) | [autosar-soa-gateway](https://github.com/norxs-tech/autosar-soa-gateway) | 16/16 (incl. real `IpcBridge` interop, 97.93% line coverage) | ISO 21448 |
| [`pqc-kem-extension/`](pqc-kem-extension/) | [zonal-zero-trust-auth](https://github.com/norxs-tech/zonal-zero-trust-auth) | 2/2 | NIST FIPS 203 (ML-KEM) |
| [`pqc-signature-extension/`](pqc-signature-extension/) | [zonal-zero-trust-auth](https://github.com/norxs-tech/zonal-zero-trust-auth) | 4/4 (incl. real `SpdmProtocolEngine` interop) | NIST FIPS 204 (ML-DSA) |
| [`formal-verification/`](formal-verification/) | [autosar-soa-gateway](https://github.com/norxs-tech/autosar-soa-gateway) | exhaustive (32/32 states, 211/211 monotonicity pairs) | found + fixed 1 real defect — see `FINDINGS.md` |
| [`v2x-trust-extension/`](v2x-trust-extension/) | [autosar-soa-gateway](https://github.com/norxs-tech/autosar-soa-gateway) + [zonal-zero-trust-auth](https://github.com/norxs-tech/zonal-zero-trust-auth) | 18/18 (incl. real `SoftwareCryptoProvider` interop, 94.87%/97.25% line coverage) | IEEE 1609.2 / SAE J2735 |

---

## ISO 21448 / Interop Compliance

| Measure | Status | Reference |
|---|---|---|
| No learned/statistical component in the SOTIF accept/reject path | ✅ | avoids the monitor-of-the-monitor regress |
| Fail-safe default (reject until every check passes) | ✅ | verified by unit test |
| Independent thresholds from any upstream monitor | ✅ | own `SotifPlausibilityConfig`, not shared constants |
| Real E2E Profile 5 interop with `autosar-soa-gateway` | ✅ **executed proof**, not claimed | `test_rejection_produces_valid_e2e_protected_ipc_slot` links and runs against the real `IpcBridge.cpp` |
| Real SPDM handshake interop with `zonal-zero-trust-auth` | ✅ **executed proof**, not claimed | `test_hybrid_auth_revokes_real_session_on_pqc_failure` runs a complete classical handshake through the real `SpdmProtocolEngine` and confirms its own real `Revoke()`/`GetState()` |
| PQC backend actually linked (KEM or signature) | 🔶 **Not yet** — see `pqc-kem-extension/README.md` and `pqc-signature-extension/README.md` | interfaces + fail-closed providers only |
| `SafetyArbitrator` severity-monotonicity | ✅ **Real defect found AND fixed** in the real file | `formal-verification/docs/FINDINGS.md` Finding F-02 — 43 exhaustively-proven counter-examples pre-fix; 0/211 violations post-fix |
| Real V2X certificate-chain verification against `zonal-zero-trust-auth`'s real crypto PAL | ✅ **executed proof**, not claimed | `test_deserialise_accepts_valid_frame_and_publishes_advisory` hand-packs raw wire bytes, runs them through the real `V2xNetworkAdapter::Deserialise()`, and confirms the real `SoftwareCryptoProvider` accepts the chain |
| V2X trust kept separate from `SafetyArbitrator::IngestFault()` | ✅ | by design — see `v2x-trust-extension/include/norxs/CooperativeAwarenessAdvisory.hpp` |
| Independent assessment | 🔶 Not performed | this is reference/exploratory work, not the production package |

---

## Assumptions of Use (AoU)

1. `SotifPlausibilityGate` must be wired as a `SoaServiceManager` subscriber
   for the AI perception-candidate service, upstream of whatever handler
   calls `SafetyArbitrator::Validate*` — integration wiring is the
   integrator's responsibility, not performed by this repository.
2. The reserved `serviceId 0xFF00` / `eventId 0xFF01` channel is shared with
   `SafetyArbitrator`'s own `SafeStateCommand` traffic by design; an
   integrator adding a third sender to this channel must preserve that
   contract or allocate a new reserved ID pair.
3. `pqc-kem-extension` must not be deployed with `UnavailablePqcKemProvider`
   or the test-only mock in any build that claims post-quantum protection —
   see that module's README for what a real backend requires.
4. `pqc-signature-extension`'s `HybridAuthGate::ConfirmHybrid()` must be
   called immediately after `SpdmProtocolEngine::ProcessAuthResponse()`
   returns `kOk`, before the caller does anything with the resulting
   `SpdmSessionToken` — see that module's README for the integrator-owned
   PQC public-key table this assumes exists.
5. `v2x-trust-extension`'s `V2xTrustVerifier` requires a `trusted_root_key`
   provisioned via a secure, out-of-band mechanism — this module does not
   address root key provisioning or rotation. Its placeholder SOME/IP
   service/event IDs (`0x1900`/`0x1901`) are not yet allocated in norxs's
   central service registry and must be reassigned before production
   integration. A `CooperativeAwarenessAdvisory` is cryptographically
   attributed but not physically confirmed — consumers must apply their own
   plausibility/fusion logic before acting on it.

---

## Build & Test

```sh
# sotif-gate — depends on autosar-soa-gateway's public headers; vendored
# copies under sotif-gate/vendor-autosar-soa-gateway/ are for this build only.
cd sotif-gate
g++ -std=c++14 -Wall -Wextra -Werror -Wshadow -Wconversion -Wcast-qual \
    -Iinclude -Ivendor-autosar-soa-gateway/include \
    -o gate_test src/SotifPlausibilityGate.cpp \
    vendor-autosar-soa-gateway/src/IpcBridge.cpp \
    tests/test_SotifPlausibilityGate.cpp
./gate_test

# pqc-kem-extension — depends on zonal-zero-trust-auth's CryptoPlatformInterface.hpp
cd ../pqc-kem-extension
g++ -std=c++14 -Wall -Wextra -Werror -Wshadow -Wconversion -Wcast-qual \
    -Iinclude -Ivendor/zonal-zero-trust-auth/include \
    -o pqc_test src/PqcKemPlatformInterface.cpp tests/test_PqcKemPlatformInterface.cpp
./pqc_test

# pqc-signature-extension — depends on zonal-zero-trust-auth's SpdmProtocolEngine
# and CryptoPlatformInterface; links the real vendored SpdmProtocolEngine.cpp
# and CryptoPlatformInterface.cpp to run a genuine classical handshake in tests.
cd ../pqc-signature-extension
g++ -std=c++14 -Wall -Wextra -Werror -Wshadow -Wconversion -Wcast-qual \
    -Iinclude -Ivendor/zonal-zero-trust-auth/include \
    -o hybrid_test \
    src/PqcSignaturePlatformInterface.cpp src/HybridAuthGate.cpp \
    vendor/zonal-zero-trust-auth/src/CryptoPlatformInterface.cpp \
    vendor/zonal-zero-trust-auth/src/SpdmProtocolEngine.cpp \
    tests/test_HybridAuthGate.cpp
./hybrid_test

# formal-verification — depends on autosar-soa-gateway's real SafetyArbitrator
# and IpcBridge; exit code 0 means findings matched the documented count.
cd ../formal-verification/harness
g++ -std=c++14 -Wall -Wextra -Wshadow -Wconversion -Wcast-qual \
    -I../vendor/autosar-soa-gateway/include \
    -o verify verify_safety_arbitrator.cpp \
    ../vendor/autosar-soa-gateway/src/SafetyArbitrator.cpp \
    ../vendor/autosar-soa-gateway/src/IpcBridge.cpp
./verify

# v2x-trust-extension — depends on autosar-soa-gateway's NetworkAdapter/
# SoaServiceManager headers and zonal-zero-trust-auth's CryptoPlatformInterface;
# links the real vendored CryptoPlatformInterface.cpp for genuine crypto interop.
cd ../v2x-trust-extension
g++ -std=c++14 -Wall -Wextra -Werror -Wshadow -Wconversion -Wcast-qual \
    -Iinclude -Ivendor/autosar-soa-gateway/include -Ivendor/zonal-zero-trust-auth/include \
    -o verifier_test src/V2xTrustVerifier.cpp \
    vendor/zonal-zero-trust-auth/src/CryptoPlatformInterface.cpp \
    tests/test_V2xTrustVerifier.cpp
./verifier_test

g++ -std=c++14 -Wall -Wextra -Werror -Wshadow -Wconversion -Wcast-qual \
    -Iinclude -Ivendor/autosar-soa-gateway/include -Ivendor/zonal-zero-trust-auth/include \
    -o adapter_test src/V2xNetworkAdapter.cpp src/V2xTrustVerifier.cpp \
    vendor/zonal-zero-trust-auth/src/CryptoPlatformInterface.cpp \
    tests/test_V2xNetworkAdapter.cpp
./adapter_test
```

40/40 tests passing across the four test-suite-based modules, plus the
formal-verification harness exhaustively confirming the fixed real code
(0/211 monotonicity violations — Finding F-02's fix holds, not merely
documented) — all verified in a fresh rebuild immediately before
publication.

---

## Related Repositories

👉 [**autosar-soa-gateway**](https://github.com/norxs-tech/autosar-soa-gateway) — `sotif-gate/`, `formal-verification/`, and `v2x-trust-extension/` are all companions to this repository; none replaces or duplicates anything in it. `formal-verification/` found a real severity-monotonicity defect in its `SafetyArbitrator` (Finding F-02) and the fix was applied directly in `autosar-soa-gateway`'s own repository — see that repository's `CHANGELOG.md` and `formal-verification/docs/FINDINGS.md` here for the full record.
👉 [**zonal-zero-trust-auth**](https://github.com/norxs-tech/zonal-zero-trust-auth) — `pqc-kem-extension/`, `pqc-signature-extension/`, and `v2x-trust-extension/` are all companions to this repository (`CryptoPlatformInterface`, `SpdmProtocolEngine`, and `CryptoPlatformInterface` again, respectively).
👉 [**safety-supervisor**](https://github.com/norxs-tech/safety-supervisor) — the M7-side consumer of `SafeStateCommand` traffic, unchanged by this repository.

---

## Commercial Licensing & Services

This reference implementation is published under the
**norxs Reference Implementation License v1.0**.
Commercial use requires a separate license agreement.

**norxs Technology LLC** offers:
- Production integration of `SotifPlausibilityGate` into a live SOA Gateway deployment
- A real ML-KEM-768 and ML-DSA-65 backend (HSE-accelerated or liboqs-based) for `pqc-kem-extension` and `pqc-signature-extension`
- ISO 21448 SOTIF validation target derivation and triggering-condition catalogue expansion
- ISO/SAE 21434 TARA covering the new PQC key-exchange and signature attack surface
- HARA-level resolution of the remaining open question from Finding F-02 (the monotonicity fix is applied; which compound sensor-loss combinations warrant a *new* escalation target, such as `kMinimalRiskCondition`, vs. reusing the highest existing single-fault severity is still a real controllability/exposure judgement for norxs's safety team)
- SCMS-integrated V2X pseudonym-certificate provisioning, CRL/CTL revocation checking, and a real DSRC/C-V2X (PC5) radio binding for `v2x-trust-extension`

**Contact:** https://www.norxs.com/ · contact@norxs.com

---

## Standards

ISO 21448 (SOTIF) · ISO 26262 · AUTOSAR C++14 · NIST FIPS 203 (ML-KEM) · NIST FIPS 204 (ML-DSA) · ISO/SAE 21434 · IEEE 1609.2 · SAE J2735 · exhaustive formal verification

---

*(c) 2026 norxs Technology LLC. All rights reserved.*
