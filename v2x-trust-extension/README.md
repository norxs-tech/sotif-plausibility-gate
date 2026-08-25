# v2x-trust-extension

Certificate-chain trust verification for V2X (Vehicle-to-Everything) messages -
the extension `autosar-soa-gateway`'s own `SafetyArbitrator.hpp` names
(`SensorDomain::kV2X = 5U, ///< Vehicle-to-Everything (future use)`) but that
nothing in the real, published `autosar-soa-gateway` or `zonal-zero-trust-auth`
repositories implements.

## Why this is not redundant with `zonal-zero-trust-auth`

`zonal-zero-trust-auth`'s `SpdmProtocolEngine` authenticates peers via
`KnownPeerEntry`: a compile-time `.rodata` table of raw pinned ECC public
keys (read directly from `zzta/SpdmProtocolEngine.hpp`). That model is
correct and sufficient for a closed set of in-vehicle zonal ECUs
provisioned at manufacture time - it is structurally impossible to reuse
for V2X, where the vehicle must trust messages from other vehicles and
roadside infrastructure it has never seen before and cannot pre-provision a
key for. Real V2X (IEEE 1609.2, the security standard SAE J2735 Basic
Safety Messages are signed under) solves this with a certificate **chain**
instead: a short-lived, rotating pseudonym certificate signed by an
intermediate CA, whose own certificate is signed by a root CA the receiver
trusts a priori.

This module implements exactly that chain shape and its verification -
reusing `zonal-zero-trust-auth`'s existing `EccPublicKey` / `CryptoSignature`
/ `Sha256Digest` types and its real `CryptoPlatformInterface::
VerifyEccSignature` / `ComputeSha256` PAL calls for every cryptographic
operation. No signature primitive is implemented here; none of
`zonal-zero-trust-auth`'s real files are modified.

## Why this is not fed into `SafetyArbitrator`

See `include/norxs/CooperativeAwarenessAdvisory.hpp` for the full reasoning
(reproduced in summary):

1. **Domain mismatch.** `SafetyArbitrator`'s `SensorDomain` enum models the
   vehicle's own onboard sensors. Losing a camera or lidar degrades the
   vehicle's own perception and correctly drives a degraded-capability
   state. A remote vehicle's V2X beacon failing chain verification does not
   affect the ego vehicle's own sensing at all - it is a different hazard
   with a different mitigation, and conflating the two through
   `IngestFault()` would be a modeling error, not a safety improvement.
2. **What authentication actually proves.** `V2xTrustVerifier::VerifyChain()`
   proves a message was signed by a certificate chaining to a trusted root -
   i.e. *who* plausibly sent it. It says nothing about whether the claimed
   position/speed/heading is physically true. That is the same
   SOTIF-plausibility question `sotif-gate`'s `SotifPlausibilityGate` already
   asks of the vehicle's own perception stack (ISO 21448). A
   `CooperativeAwarenessAdvisory` is therefore an unconfirmed, externally
   attributed input that downstream fusion logic must independently assess -
   this module deliberately stops at "cryptographically attributed," not
   "physically confirmed."

## What this does not do

Deliberately out of scope (see `include/norxs/V2xCertificate.hpp` for the
same list in context):

- **Butterfly key expansion** - the SCMS technique for deriving large
  numbers of pseudonym certificates from a small provisioning request.
- **CRL/CTL revocation checking** - a revoked-but-not-yet-expired
  certificate in an otherwise valid chain is currently accepted.
- **The SCMS provisioning protocol itself** - how a vehicle originally
  obtains its pseudonym certificates.
- **PSID/SSP permission fields** - real 1609.2 certificates scope what
  services/message types a certificate may sign for; not modelled.
- **Geographic validity regions** - real 1609.2 certificates can be scoped
  to a geographic area; not modelled.
- **Full SAE J2735 ASN.1 BSM encoding** - `CooperativeAwarenessAdvisory`
  decodes a deliberately minimal, fixed 16-byte core (lat/lon/speed/heading/
  timestamp), not the full BSM data frame (path history, event flags,
  vehicle size, brake status, etc.).
- **Outbound V2X signing** - `V2xNetworkAdapter::Transmit()`/`Receive()` are
  honestly not implemented; this module verifies inbound chains, it does not
  bind to a real DSRC/C-V2X (PC5) radio or hold the vehicle's own V2X
  signing key. `Serialise()` only repacks an already-verified advisory for
  in-vehicle redistribution, which needs no signing key.

This is the trust-chain-verification core, not a full 1609.2 stack.

## System Architecture

```
  Remote vehicle / RSU                    This vehicle's SOA gateway
  ┌──────────────────┐                    ┌───────────────────────────────┐
  │ V2X radio (DSRC / │  raw WireFrame     │  V2xNetworkAdapter             │
  │ C-V2X / PC5)       │──────────────────▶│  (norxs::soa::NetworkAdapter)  │
  └──────────────────┘   (468-byte frame:  │  ::Deserialise()                │
                          payload_len +     │    1. UnpackWireFrame()         │
                          BSM core +        │    2. V2xTrustVerifier          │
                          pseudonym_cert +  │       ::VerifyChain()           │
                          intermediate_cert │         │                        │
                          + bsm_signature)  │         ▼ kTrusted only          │
                                            │    3. decode advisory fields    │
                                            │    4. publish SoaEvent          │
                                            └───────────┬─────────────────────┘
                                                         │ CooperativeAwarenessAdvisory
                                                         ▼ (serviceId 0x1900 / eventId 0x1901)
                                            SoaServiceManager::PublishEvent()
                                            (real, unmodified - subscribers
                                             apply their own fusion/plausibility
                                             logic; NOT routed to
                                             SafetyArbitrator::IngestFault())
```

Trust-chain shape (`V2xCertificate.hpp`):

```
  trusted_root_key (provisioned out of band)
        │ verifies
        ▼
  intermediate_cert  (signed by root)
        │ verifies (via intermediate_cert.subject_public_key)
        ▼
  pseudonym_cert     (signed by intermediate)
        │ verifies (via pseudonym_cert.subject_public_key)
        ▼
  bsm_signature      (signs SHA-256(payload))
```

Fail-safe default throughout: the first failed step returns immediately
with that step's specific `V2xTrustStatus` reason; nothing downstream of a
failed step is evaluated.

## Module Inventory

| File | Purpose |
|---|---|
| `include/norxs/V2xCertificate.hpp` | `V2xCertificate`, `V2xSignedBsm`, `V2xTrustStatus` - the chain data model. |
| `include/norxs/V2xTrustVerifier.hpp` / `src/V2xTrustVerifier.cpp` | `VerifyChain()` - root→intermediate→pseudonym→message verification. |
| `include/norxs/CooperativeAwarenessAdvisory.hpp` | The compact, chain-verified output type; documents why it is not a `SensorFaultEvent`. |
| `include/norxs/V2xNetworkAdapter.hpp` / `src/V2xNetworkAdapter.cpp` | Concrete `norxs::soa::NetworkAdapter` implementation - the first concrete implementation of that abstract interface in the norxs reference repos. |
| `tests/test_V2xTrustVerifier.cpp` | 8 tests of `VerifyChain()` against the real vendored `SoftwareCryptoProvider`. |
| `tests/test_V2xNetworkAdapter.cpp` | 10 tests of the adapter end to end, from hand-packed raw wire bytes through to the published `SoaEvent`. |

## Interop Evidence

Every cryptographic call in `V2xTrustVerifier` and `V2xNetworkAdapter` runs
against `zonal-zero-trust-auth`'s real, vendored, unmodified
`SoftwareCryptoProvider` (`ComputeSha256` / `VerifyEccSignature`) - not a
reimplementation. Tests construct valid signatures using the same
technique `zonal-zero-trust-auth`'s own tests use for its mock (documented
in each test file's header): the mock's `VerifyEccSignature` derives the
expected signature deterministically from the digest and a fixed salt
copied verbatim from the vendored source, so a valid signature can be
constructed without a real private key. This also means every certificate
level in these tests necessarily shares one test-vector public key - a
disclosed limitation of the shared mock (see the test files' header
comments), not of `V2xTrustVerifier`.

18/18 tests pass. Line coverage: `V2xTrustVerifier.cpp` 94.87%,
`V2xNetworkAdapter.cpp` 97.25% (uncovered lines are `ComputeSha256`
hardware-fault branches unreachable with the software mock - see
`docs/COVERAGE_DEVIATIONS.md`).

## Assumptions of Use (AoU)

- The `trusted_root_key` supplied to `V2xTrustVerifier`'s constructor is
  provisioned via a secure, out-of-band mechanism (e.g. OEM manufacturing
  step) - this module does not address root key provisioning or rotation.
- `nowEpochS` is supplied by the caller (not read internally), matching
  `sotif-gate::Evaluate()`'s injectable-clock discipline; the caller is
  responsible for supplying a trustworthy time source.
- A `CooperativeAwarenessAdvisory` is cryptographically attributed but not
  physically confirmed; consumers must apply their own plausibility/fusion
  logic before acting on it.
- Placeholder SOME/IP service/event IDs (`0x1900`/`0x1901`) are not yet
  allocated in norxs's central service registry and must be reassigned
  before production integration.

## Build & Test

```sh
g++ -std=c++14 -Wall -Wextra -O0 -g \
  -Iinclude -Ivendor/autosar-soa-gateway/include -Ivendor/zonal-zero-trust-auth/include \
  tests/test_V2xTrustVerifier.cpp src/V2xTrustVerifier.cpp \
  vendor/zonal-zero-trust-auth/src/CryptoPlatformInterface.cpp \
  -o test_V2xTrustVerifier && ./test_V2xTrustVerifier

g++ -std=c++14 -Wall -Wextra -O0 -g \
  -Iinclude -Ivendor/autosar-soa-gateway/include -Ivendor/zonal-zero-trust-auth/include \
  tests/test_V2xNetworkAdapter.cpp src/V2xNetworkAdapter.cpp src/V2xTrustVerifier.cpp \
  vendor/zonal-zero-trust-auth/src/CryptoPlatformInterface.cpp \
  -o test_V2xNetworkAdapter && ./test_V2xNetworkAdapter
```

## Standards

AUTOSAR C++14, IEEE 1609.2, SAE J2735, ISO 21448, ISO/SAE 21434.
