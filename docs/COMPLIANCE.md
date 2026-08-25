# Compliance Mapping

Same disclosure discipline as everywhere else in this repository: states what
is actually true today, not an aspirational target dressed up as a status.

## OpenChain ISO/IEC 5230:2020 (license compliance)

- SPDX 2.3 SBOM with per-file SHA-256 checksums: [`sbom/sotif-plausibility-gate.spdx.json`](../sbom/sotif-plausibility-gate.spdx.json), regenerable via `tools/generate_sbom.py`.
- Per-file `@copyright` headers on every source/header/test file (CI-enforced — see `.github/workflows/ci.yml`'s `supply-chain-compliance` job).
- Zero third-party runtime dependencies (this repository links nothing at
  runtime — `vendor*/` content is a **build-time** dependency on
  `autosar-soa-gateway` and `zonal-zero-trust-auth`, whose own SBOMs cover
  those files; this repository's SBOM explicitly excludes them rather than
  silently omitting them).

## OpenChain ISO/IEC 18974:2023 (security assurance)

- Coordinated vulnerability disclosure policy with a real, verified contact
  channel: [`SECURITY.md`](../SECURITY.md).
- Static analysis (cppcheck, CI-enforced, zero findings on error/warning
  level) and strict compiler warnings-as-errors on every commit.
- **Not yet done**: ASan/UBSan runtime instrumentation (safety-supervisor's
  real CI does this; this repository's CI does not yet — tracked as a gap,
  not silently skipped).

## ISO 21448 (SOTIF)

- `sotif-gate/` implements three deterministic triggering-condition checks
  (cross-estimate confidence, calibration drift, freshness/replay).
- **Not yet done**: a derived SOTIF validation target (residual-risk
  acceptance criterion) — see `docs/COVERAGE_DEVIATIONS.md` for the parallel
  disclosure on test coverage, and `sotif-asil-bridge`'s `ARCHITECTURE.md` §5
  for the methodology this would need to follow (Validation Target,
  triggering-condition catalogue expansion from field data). Nothing in this
  repository invents that number.

## NIST Cybersecurity Framework 2.0

| Function | How this repository addresses it |
|---|---|
| Govern | This document + `LICENSE` + `SECURITY.md` |
| Identify | SBOM (`sbom/`), dependency boundary documented (`vendor*/` = build-time only) |
| Protect | `UnavailablePqcKemProvider` fails closed rather than degrading silently; `SotifPlausibilityGate` fail-safe-defaults to reject |
| Detect | `SotifPlausibilityGate`'s reject-reason counters (`GetRejectCount()`, `GetLastRejectReason()`) — no alerting/telemetry pipeline wired up, that's an integrator responsibility |
| Respond | `SECURITY.md` coordinated disclosure process |
| Recover | Not applicable — this repository ships no runtime state to recover |

## What this repository is not

Not an independently assessed safety case, not a certified ASIL-D/CAL
deliverable, not a claim that `pqc-kem-extension` provides real post-quantum
security in its shipped form. See the top-level `README.md`'s "What This Is"
section and `LICENSE`'s disclaimer of warranties.
