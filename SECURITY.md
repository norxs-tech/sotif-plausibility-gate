# Security Policy — norxs SOTIF Plausibility Gate & PQC KEM Extension

**norxs Technology LLC** | Safety Engineering, Built from the Ground Up.

This project extends safety- and security-critical automotive infrastructure
subject to **ISO 21448**, **ISO/SAE 21434**, and **UN R155** obligations.
Responsible disclosure is taken seriously and handled with urgency.

---

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.x     | ✅ Active support (pre-release) |

---

## Reporting a Vulnerability

**Do NOT use the public GitHub issue tracker for security vulnerabilities.**

### Contact

| Channel | Details |
|---------|---------|
| **Email** | contact@norxs.com |
| **Subject line** | `[SECURITY] sotif-plausibility-gate — <brief one-line description>` |
| **Web** | https://norxs.com/contact |

All security reports are handled under **Non-Disclosure Agreement**. We do
not require you to sign an NDA before submitting a report — we will propose
one as part of the coordinated disclosure process.

---

## Scope note specific to this repository

`pqc-kem-extension/` ships **no working cryptography** — `UnavailablePqcKemProvider`
fails closed on every call by design, and `MockKemProvider_TestOnly_NotSecure`
is explicitly non-cryptographic test plumbing. Please still report design or
interface-contract issues found there; a flaw in the extension point itself
is cheaper to fix before a real backend is wired in than after.

`sotif-gate/` interoperates with `autosar-soa-gateway`'s real `IpcBridge` and
`SafetyArbitrator` types by depending on their public headers. A vulnerability
report that touches that boundary should be reported to both repositories.
