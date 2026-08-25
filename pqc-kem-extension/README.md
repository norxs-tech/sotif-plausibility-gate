# pqc-kem-extension

Post-quantum Key Encapsulation Mechanism (ML-KEM-768 / FIPS 203) extension
point for `zonal-zero-trust-auth`'s `CryptoPlatformInterface`. See the
top-level `README.md` for why this gap is real (confirmed by reading that
interface's header, not assumed).

## Read this before anything else

**This module ships no working post-quantum cryptography.** Two classes exist:

- `PqcKemPlatformInterface` — the real, usable interface contract (same idiom
  as `CryptoPlatformInterface`: `[[nodiscard]]`, `noexcept`, `std::array`
  fixed buffers, zero heap).
- `UnavailablePqcKemProvider` — the **only provider shipped here**. Every
  method returns `CryptoStatus::kNotSupported` and touches no output buffer.
  This is deliberate fail-closed behaviour, not a placeholder someone forgot
  to finish.

The test suite additionally includes `MockKemProvider_TestOnly_NotSecure`, an
XOR-based toy construction that proves the *interface contract* round-trips
correctly (`GenerateKeyPair` → `Encapsulate` → `Decapsulate` reaches the same
shared secret). **This has zero cryptographic hardness.** It exists in
`tests/`, not `src/`, specifically so it cannot be linked into anything but
the test binary.

## How to make it real

Wire a real backend by implementing `PqcKemPlatformInterface` against a
vetted library:

- **liboqs**, `OQS_KEM_ml_kem_768` — the reference open-source ML-KEM
  implementation.
- **OpenSSL 3.5+** with the `oqs-provider`, via `EVP_PKEY_encapsulate()` /
  `EVP_PKEY_decapsulate()`.

Either way: do not implement the lattice math by hand. That is not a style
preference — it is the same hard rule the rest of this project applies to
every cryptographic primitive, and it applies at least as strongly to a
post-quantum scheme, where the implementation-mistake safety margin is less
well understood than for classical ECDSA.

## Build & test

```sh
g++ -std=c++14 -Wall -Wextra -Werror -Wshadow -Wconversion -Wcast-qual \
    -Iinclude -Ivendor/zonal-zero-trust-auth/include \
    -o pqc_test src/PqcKemPlatformInterface.cpp tests/test_PqcKemPlatformInterface.cpp
./pqc_test
```

2/2 tests pass: fail-closed behaviour of the shipped provider, and interface
plumbing correctness via the clearly-labeled mock.
