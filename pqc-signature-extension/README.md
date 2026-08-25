# pqc-signature-extension

Hybrid ML-DSA-65 (FIPS 204) signature check composed on top of
`zonal-zero-trust-auth`'s real, unmodified `SpdmProtocolEngine`.

## Read this before the corrections below make sense

This was first described (in an earlier conversation with the user, not in
this file's own history) as "PQC migration of the X.509/DevID certificate
chain." **That framing was wrong**, corrected after actually reading
`SpdmProtocolEngine.hpp`: there is no X.509 chain anywhere in
`zonal-zero-trust-auth`. The real trust model is a compile-time `.rodata`
table of raw pinned `{ClientId, EccPublicKey}` pairs
(`KnownPeerEntry`) — production deployment is documented as generating that
table from an OEM-signed chain during secure boot, but no chain-parsing or
-verification code exists in this codebase to migrate. The real, narrower
gap: the pinned ECDSA-P256 key and the CHALLENGE_AUTH signature have no
post-quantum equivalent. This module adds one.

## What's here

- `include/zzta/PqcSignaturePlatformInterface.hpp` / `src/...cpp` — ML-DSA-65
  sized types and the same PAL idiom as `CryptoPlatformInterface`.
  `UnavailablePqcSignatureProvider` is the only shipped provider; fails
  closed.
- `include/norxs/HybridAuthGate.hpp` / `src/...cpp` — composes a second,
  independent PQC signature check on top of a real `SpdmProtocolEngine`
  instance, without modifying that class. Closes the one real hazard a
  bolt-on check creates: a classical-only-authenticated session existing
  before the PQC check runs. `ConfirmHybrid()` calls the engine's own real
  `Revoke()` itself on PQC failure — proven by test, not just documented.
- `vendor/zonal-zero-trust-auth/` — real `CryptoPlatformInterface` and
  `SpdmProtocolEngine` (headers + `.cpp`), vendored read-only for this
  build. Not owned by this repository.
- `tests/test_HybridAuthGate.cpp` — runs a **real, complete classical SPDM
  handshake** through the actual vendored `SpdmProtocolEngine` (using the
  same `MakeValidAuthResponse` construction `zonal-zero-trust-auth`'s own
  test suite uses, copied from their real `tests/test_zzta_core.cpp` so the
  signature this test constructs is genuinely valid against their real mock
  provider — not faked). 4/4 tests, 100% line coverage on both new source
  files.

## What this does not do

- Does not modify `KnownPeerEntry`, `SpdmProtocolEngine`, or
  `CryptoPlatformInterface` — zero changes required in
  `zonal-zero-trust-auth` to deploy this.
- Does not implement a PQC public-key table for `zonal-zero-trust-auth`'s
  peer table — the integrator owns a separate `ClientId -> PqcSigPublicKey`
  lookup (see Assumptions of Use below), parallel to but not part of
  `KnownPeerEntry`.
- Does not implement real ML-DSA math — see
  `UnavailablePqcSignatureProvider` and the top-level `pqc-kem-extension`
  README for the same rule applied to the KEM side.

## Assumptions of Use

1. The integrator maintains a `ClientId -> PqcSigPublicKey` table separate
   from `KnownPeerEntry`, provisioned with the same rigor (secure boot /
   write-protected flash) the real peer table's own documentation requires.
2. `HybridAuthGate::ConfirmHybrid()` is called **immediately** after
   `SpdmProtocolEngine::ProcessAuthResponse()` returns `kOk`, before the
   caller does anything else with the resulting `SpdmSessionToken` — the
   token is not actually trustworthy until `ConfirmHybrid()` also returns
   `kOk`.
3. The peer signs the same message shape (`session_nonce ∥ client_id`) with
   its PQC key that it signs classically — this module does not renegotiate
   message framing with the peer.

## Build & test

```sh
g++ -std=c++14 -Wall -Wextra -Werror -Wshadow -Wconversion -Wcast-qual \
    -Iinclude -Ivendor/zonal-zero-trust-auth/include \
    -o hybrid_test \
    src/PqcSignaturePlatformInterface.cpp src/HybridAuthGate.cpp \
    vendor/zonal-zero-trust-auth/src/CryptoPlatformInterface.cpp \
    vendor/zonal-zero-trust-auth/src/SpdmProtocolEngine.cpp \
    tests/test_HybridAuthGate.cpp
./hybrid_test
```
