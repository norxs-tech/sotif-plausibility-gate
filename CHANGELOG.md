# Changelog

All notable changes to the **norxs SOTIF Plausibility Gate & PQC KEM Extension**
are documented here. This project follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added

- `v2x-trust-extension/`: `V2xTrustVerifier` (root → intermediate →
  pseudonym → message certificate-chain verification) and
  `V2xNetworkAdapter` — the first concrete implementation of
  `autosar-soa-gateway`'s abstract `NetworkAdapter` interface anywhere in
  the norxs reference repos (the real repo ships the interface only, no
  concrete SOME/IP or DDS adapter). Closes the gap `SafetyArbitrator.hpp`'s
  own `SensorDomain::kV2X = 5U, ///< Vehicle-to-Everything (future use)`
  comment names but that neither real repo implements. Deliberately does
  NOT reuse `zonal-zero-trust-auth`'s pinned-public-key trust model (works
  for known in-vehicle ECUs, structurally impossible for previously-unseen
  V2X peers) and deliberately does NOT feed verified V2X content into
  `SafetyArbitrator::IngestFault()` — see `CooperativeAwarenessAdvisory.hpp`
  for the two independent reasons (domain mismatch between onboard sensor
  loss and remote-peer authentication; authentication proves who sent a
  message, not that its content is physically true). 18/18 tests pass
  against the real, vendored, unmodified `SoftwareCryptoProvider`
  (`V2xTrustVerifier.cpp` 94.87%, `V2xNetworkAdapter.cpp` 97.25% line
  coverage — remaining lines are hardware-fault branches unreachable with
  the software mock, documented in `docs/COVERAGE_DEVIATIONS.md`). CI
  matrix, SBOM, and top-level README updated.

- `formal-verification/`: exhaustive state-space verification of
  `autosar-soa-gateway`'s real `SafetyArbitrator::ComputeRequiredState()`,
  driving the actual compiled class through its real public API (not a
  hand-written model). **Found a real, reproducible defect**: severity was
  not monotonic under compound sensor loss — 43 exhaustively-proven
  counter-examples (e.g. camera+lidar both failing reached a *less*
  restrictive state than camera failing alone, because the priority-ordered
  if/else-return structure stopped checking after the first match).
  Independently re-derived in plain Python before being reported, to rule
  out a harness bug. See `formal-verification/docs/FINDINGS.md` for this and
  three further findings (F-01, F-03, F-04). No Java/TLA+ toolchain was
  available in this environment (checked before choosing exhaustive
  enumeration instead — a complete method here, not a fallback, since the
  function under test is a pure 5-bit-input function). CI matrix, SBOM, and
  top-level README updated. **This defect was subsequently fixed — see the
  `### Fixed` entry below.**

- `pqc-signature-extension/`: `PqcSignaturePlatformInterface` (ML-DSA-65 /
  FIPS 204) and `HybridAuthGate`, composing a second, independent PQC
  signature check on top of `zonal-zero-trust-auth`'s real, unmodified
  `SpdmProtocolEngine`. Corrects an earlier imprecise description of this
  gap as "PQC-migrating an X.509 chain" — the real code has no certificate
  chain, only a pinned-public-key table; the actual gap is narrower and is
  what this module addresses. 4/4 tests, including one that runs a complete
  classical SPDM handshake through the real vendored engine and confirms a
  failed PQC check calls the engine's own real `Revoke()`. 100% line
  coverage on both new source files. CI matrix, SBOM, and top-level README
  updated to include it (22/22 tests across all three modules now).

### Fixed

- **`formal-verification` Finding F-02 (severity non-monotonicity) fixed
  upstream in `autosar-soa-gateway`.** `ComputeRequiredState()` now
  evaluates every triggering condition and escalates to the most severe
  match instead of returning on the first one — the exact fix this
  repository's exhaustively-verified corrected reference model proposed.
  This repository's `formal-verification/vendor/autosar-soa-gateway/src/
  SafetyArbitrator.cpp` was updated to the fixed version and its harness
  rewritten to assert the fix (32/32 spec match, 0/211 monotonicity
  violations, fix changed exactly the expected 17/32 masks) rather than
  merely document the pre-fix defect. `docs/FINDINGS.md` and both READMEs
  updated to reflect Finding F-02 as fixed, not open.

- CI coverage-gate step failed on the real runner (passed locally): the
  `.gcda` filename guess and the bare-filename grep pattern both broke on
  the runner's actual output (`File 'src/SotifPlausibilityGate.cpp'` with a
  path prefix; a suffix-wildcard glob matching `test_X.gcda` instead of
  `X.gcda`). Now runs `gcov` over every `.gcda` file at once and matches the
  file section with a path-anchored regex. Reproduced the exact failure
  locally (compiling from `src/`/`tests/`/`vendor-*/` paths instead of a
  flattened directory) before shipping the fix this time.

---

## [0.1.0] — 2026-08-25

### Added

- `sotif-gate/`: `SotifPlausibilityGate`, closing the ISO 21448 gap in
  `autosar-soa-gateway`'s `SafetyArbitrator` (documented `SOTIF ISO 21448` in
  its `@standards` line without an implementation that addresses it). Three
  deterministic checks (cross-estimate confidence, calibration drift,
  freshness/replay), real E2E Profile 5 interop with the vendored real
  `IpcBridge.cpp`, 15/15 tests, 97.93% line coverage.
- `pqc-kem-extension/`: `PqcKemPlatformInterface` companion to
  `zonal-zero-trust-auth`'s `CryptoPlatformInterface` (which defines zero KEM
  primitives). Ships `UnavailablePqcKemProvider` (fails closed, no real
  backend linked) and a test-only mock proving interface plumbing. 2/2 tests,
  100% line coverage.
- CI: unit tests, coverage gate (≥90% line coverage per module), cppcheck
  static analysis, and supply-chain compliance checks (SBOM presence,
  per-file copyright headers).
- SPDX 2.3 SBOM (`tools/generate_sbom.py`), `docs/COMPLIANCE.md`,
  `docs/COVERAGE_DEVIATIONS.md`.

### Known gaps (see `docs/` for full detail)

- No independent assessment.
- No MC/DC coverage measurement (line coverage only).
- No ASan/UBSan instrumentation in CI.
- No real ML-KEM backend linked in `pqc-kem-extension`.
- No cross-compilation to the actual M7/A53 targets — host-native build only.
