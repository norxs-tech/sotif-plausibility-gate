/**
 * @copyright (c) 2026 norxs Technology LLC. All rights reserved.
 *
 * Tests for PqcKemPlatformInterface.
 *
 * Two things are proven here, and they are different claims:
 *   1. UnavailablePqcKemProvider (the only provider shipped in this repo)
 *      fails closed on every call — no cryptography happens, on purpose.
 *   2. A TEST-ONLY, NOT-CRYPTOGRAPHICALLY-SECURE mock backend proves the
 *      INTERFACE CONTRACT itself is usable end-to-end (GenerateKeyPair ->
 *      Encapsulate -> Decapsulate reaching the same shared secret) — this is
 *      a plumbing proof, not a security proof. See the mock's own comments.
 */
#include "zzta/PqcKemPlatformInterface.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>

using namespace zzta;

static void test_unavailable_provider_fails_closed() {
    UnavailablePqcKemProvider provider;
    PqcKemPlatformInterface&  iface = provider; // exercised via the base interface, not the concrete type

    PqcPublicKey    pub{};
    PqcSecretKey    sec{};
    PqcCiphertext   ct{};
    PqcSharedSecret ss1{};
    PqcSharedSecret ss2{};

    assert(iface.GenerateKeyPair(pub, sec) == CryptoStatus::kNotSupported);
    assert(iface.Encapsulate(pub, ct, ss1) == CryptoStatus::kNotSupported);
    assert(iface.Decapsulate(sec, ct, ss2) == CryptoStatus::kNotSupported);

    std::printf("PASS: test_unavailable_provider_fails_closed\n");
}

// ---------------------------------------------------------------------------
// TEST-ONLY MOCK. NOT CRYPTOGRAPHICALLY SECURE. XOR-based toy construction,
// exists solely to prove PqcKemPlatformInterface's contract round-trips
// correctly through a concrete implementation. Never link this outside a
// test binary — see pqc-kem-extension/README.md.
// ---------------------------------------------------------------------------
namespace {
constexpr std::uint8_t kMockMask1{0xA5U};
constexpr std::uint8_t kMockMask2{0x3CU};

class MockKemProvider_TestOnly_NotSecure final : public PqcKemPlatformInterface {
public:
    [[nodiscard]] CryptoStatus GenerateKeyPair(PqcPublicKey& pub, PqcSecretKey& sec) noexcept override {
        for (std::size_t i = 0U; i < kMlKem768SecretKeyLen; ++i) {
            sec[i] = static_cast<std::uint8_t>((i * 7U) + 13U);
        }
        for (std::size_t i = 0U; i < kMlKem768PublicKeyLen; ++i) {
            pub[i] = static_cast<std::uint8_t>(sec[i % kMlKem768SecretKeyLen] ^ kMockMask1);
        }
        return CryptoStatus::kOk;
    }

    [[nodiscard]] CryptoStatus Encapsulate(const PqcPublicKey& pub, PqcCiphertext& ct,
                                            PqcSharedSecret& ss) noexcept override {
        for (std::size_t i = 0U; i < kMlKem768CiphertextLen; ++i) {
            ct[i] = static_cast<std::uint8_t>(pub[i % kMlKem768PublicKeyLen] ^ kMockMask2);
        }
        for (std::size_t i = 0U; i < kMlKem768SharedSecretLen; ++i) {
            ss[i] = static_cast<std::uint8_t>(pub[i] ^ kMockMask1);
        }
        return CryptoStatus::kOk;
    }

    [[nodiscard]] CryptoStatus Decapsulate(const PqcSecretKey& sec, const PqcCiphertext& ct,
                                            PqcSharedSecret& ss) noexcept override {
        for (std::size_t i = 0U; i < kMlKem768SharedSecretLen; ++i) {
            std::uint8_t const recoveredPubByte = static_cast<std::uint8_t>(ct[i] ^ kMockMask2);
            ss[i] = static_cast<std::uint8_t>(recoveredPubByte ^ kMockMask1);
        }
        (void)sec;
        return CryptoStatus::kOk;
    }
};
} // namespace

static void test_mock_backend_round_trip_via_interface() {
    MockKemProvider_TestOnly_NotSecure concrete;
    PqcKemPlatformInterface&           iface = concrete;

    PqcPublicKey    pub{};
    PqcSecretKey    sec{};
    PqcCiphertext   ct{};
    PqcSharedSecret ssEncaps{};
    PqcSharedSecret ssDecaps{};

    assert(iface.GenerateKeyPair(pub, sec) == CryptoStatus::kOk);
    assert(iface.Encapsulate(pub, ct, ssEncaps) == CryptoStatus::kOk);
    assert(iface.Decapsulate(sec, ct, ssDecaps) == CryptoStatus::kOk);

    assert(std::memcmp(ssEncaps.data(), ssDecaps.data(), kMlKem768SharedSecretLen) == 0);

    std::printf("PASS: test_mock_backend_round_trip_via_interface "
                "(interface plumbing only — see mock's own NOT-SECURE warning)\n");
}

int main() {
    test_unavailable_provider_fails_closed();
    test_mock_backend_round_trip_via_interface();
    std::printf("All tests passed.\n");
    return 0;
}
