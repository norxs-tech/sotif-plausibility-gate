/**
 * =====================================================================================
 * @file        PqcKemPlatformInterface.hpp
 * @brief       Companion Platform Abstraction Layer (PAL) extending
 *              zonal-zero-trust-authenticator's CryptoPlatformInterface with a
 *              post-quantum Key Encapsulation Mechanism (KEM). Not a modification of
 *              CryptoPlatformInterface.hpp — that file is owned by
 *              zonal-zero-trust-auth and unchanged. This is an additive companion
 *              interface in the same `zzta` namespace, following the exact same
 *              idiom (CryptoStatus reuse, std::array fixed buffers, [[nodiscard]]
 *              noexcept pure virtuals, zero heap allocation) so it reads as a natural
 *              extension rather than a parallel, inconsistent API.
 *
 *              Why this exists: CryptoPlatformInterface.hpp defines exactly four
 *              primitives — GenerateRandomNonce, ComputeSha256, VerifyEccSignature,
 *              DeriveSessionKey — all classical. There is no KEM operation anywhere
 *              in zonal-zero-trust-auth; SPDM session-key establishment there is
 *              ECDSA/HKDF-only. That is fine for today's threat model, but it is a
 *              real, present gap against a harvest-now-decrypt-later adversary
 *              targeting long-lived vehicle fleets — the session keys this
 *              authenticator derives need to still be unrecoverable a decade from
 *              now. This interface is the extension point for that; it does not
 *              replace the classical path, it is meant to sit alongside it in a
 *              hybrid classical+PQC key exchange (both secrets combined into the
 *              final HKDF, so a break of either alone is insufficient).
 *
 *              Sizes below are FIPS 203 ML-KEM-768 (public key 1184B, secret key
 *              2400B, ciphertext 1088B, shared secret 32B) — chosen as NIST's
 *              standardised, moderate-parameter-set KEM, not an arbitrary guess.
 *
 * @project     zzta-pqc-kem-extension (companion to zonal-zero-trust-authenticator)
 * @standards   AUTOSAR C++14, ISO/SAE 21434, NIST FIPS 203 (ML-KEM)
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        UnavailablePqcKemProvider below is the ONLY provider shipped here. It
 *              fails closed (kNotSupported) on every call. No ML-KEM math is
 *              implemented in this repository — see README.md for exactly why and
 *              what wiring a real backend (liboqs / OpenSSL 3.5+) requires.
 * =====================================================================================
 */

#ifndef ZZTA_PQC_KEM_PLATFORM_INTERFACE_HPP
#define ZZTA_PQC_KEM_PLATFORM_INTERFACE_HPP

#include "zzta/CryptoPlatformInterface.hpp"
#include <array>
#include <cstdint>
#include <cstddef>

namespace zzta {

// ─────────────────────────────────────────────────────────────────────────────
// ML-KEM-768 (FIPS 203) compile-time sizes. Changing the parameter set is a
// safety/security-relevant decision requiring TARA re-assessment, same
// discipline CryptoPlatformInterface.hpp applies to its own constants.
// ─────────────────────────────────────────────────────────────────────────────

static constexpr std::size_t kMlKem768PublicKeyLen{1184U};
static constexpr std::size_t kMlKem768SecretKeyLen{2400U};
static constexpr std::size_t kMlKem768CiphertextLen{1088U};
static constexpr std::size_t kMlKem768SharedSecretLen{32U};

using PqcPublicKey    = std::array<uint8_t, kMlKem768PublicKeyLen>;
using PqcSecretKey    = std::array<uint8_t, kMlKem768SecretKeyLen>;
using PqcCiphertext   = std::array<uint8_t, kMlKem768CiphertextLen>;
using PqcSharedSecret = std::array<uint8_t, kMlKem768SharedSecretLen>;

// ─────────────────────────────────────────────────────────────────────────────
// PqcKemPlatformInterface — pure virtual PAL contract, same shape as
// CryptoPlatformInterface: no data members, [[nodiscard]] status returns,
// noexcept everywhere, virtual destructor for polymorphic destruction.
// ─────────────────────────────────────────────────────────────────────────────

class PqcKemPlatformInterface
{
public:
    PqcKemPlatformInterface()                                          = default;
    PqcKemPlatformInterface(const PqcKemPlatformInterface&)            = delete;
    PqcKemPlatformInterface& operator=(const PqcKemPlatformInterface&) = delete;
    PqcKemPlatformInterface(PqcKemPlatformInterface&&)                 = delete;
    PqcKemPlatformInterface& operator=(PqcKemPlatformInterface&&)      = delete;
    virtual ~PqcKemPlatformInterface()                                 = default;

    /**
     * @brief Generate an ML-KEM-768 key pair.
     * @return CryptoStatus::kOk on success; kNotSupported if no real backend
     *         is linked; kHwFault on entropy/accelerator failure.
     */
    [[nodiscard]] virtual CryptoStatus GenerateKeyPair(
        PqcPublicKey& public_key_out,
        PqcSecretKey& secret_key_out) noexcept = 0;

    /**
     * @brief Encapsulate against a peer's public key, producing a ciphertext
     *        to send and a shared secret to keep.
     */
    [[nodiscard]] virtual CryptoStatus Encapsulate(
        const PqcPublicKey& peer_public_key,
        PqcCiphertext&      ciphertext_out,
        PqcSharedSecret&    shared_secret_out) noexcept = 0;

    /**
     * @brief Decapsulate a received ciphertext using the local secret key,
     *        recovering the same shared secret the sender's Encapsulate()
     *        produced.
     */
    [[nodiscard]] virtual CryptoStatus Decapsulate(
        const PqcSecretKey&  secret_key,
        const PqcCiphertext& ciphertext,
        PqcSharedSecret&     shared_secret_out) noexcept = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
// UnavailablePqcKemProvider — the only provider in this repository.
// Fails closed on every call. Deliberately does NOT return plausible-looking
// zeroed output; every method sets kNotSupported and leaves outputs
// untouched, so a caller that forgets to check the return code gets garbage
// stack memory rather than a silent, confident-looking zero key.
// ─────────────────────────────────────────────────────────────────────────────

class UnavailablePqcKemProvider final : public PqcKemPlatformInterface
{
public:
    UnavailablePqcKemProvider()  noexcept = default;
    ~UnavailablePqcKemProvider() override = default;

    UnavailablePqcKemProvider(const UnavailablePqcKemProvider&)            = delete;
    UnavailablePqcKemProvider& operator=(const UnavailablePqcKemProvider&) = delete;
    UnavailablePqcKemProvider(UnavailablePqcKemProvider&&)                 = delete;
    UnavailablePqcKemProvider& operator=(UnavailablePqcKemProvider&&)      = delete;

    [[nodiscard]] CryptoStatus GenerateKeyPair(
        PqcPublicKey& public_key_out,
        PqcSecretKey& secret_key_out) noexcept override;

    [[nodiscard]] CryptoStatus Encapsulate(
        const PqcPublicKey& peer_public_key,
        PqcCiphertext&      ciphertext_out,
        PqcSharedSecret&    shared_secret_out) noexcept override;

    [[nodiscard]] CryptoStatus Decapsulate(
        const PqcSecretKey&  secret_key,
        const PqcCiphertext& ciphertext,
        PqcSharedSecret&     shared_secret_out) noexcept override;
};

} // namespace zzta

#endif // ZZTA_PQC_KEM_PLATFORM_INTERFACE_HPP
