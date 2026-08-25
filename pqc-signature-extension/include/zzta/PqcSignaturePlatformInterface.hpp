/**
 * =====================================================================================
 * @file        PqcSignaturePlatformInterface.hpp
 * @brief       Companion Platform Abstraction Layer (PAL) adding a post-quantum
 *              signature scheme (ML-DSA-65 / FIPS 204) to zonal-zero-trust-auth's
 *              SPDM challenge-response handshake. Not a modification of
 *              CryptoPlatformInterface.hpp or SpdmProtocolEngine.hpp/.cpp — both are
 *              owned by zonal-zero-trust-auth and unchanged.
 *
 *              Precision correction versus how this was first described: the real
 *              trust model in SpdmProtocolEngine.hpp is a compile-time `.rodata`
 *              table of raw pinned {ClientId, EccPublicKey} pairs (see
 *              KnownPeerEntry) — there is no X.509 certificate chain anywhere in
 *              zonal-zero-trust-auth to "migrate to PQC". The real, precise gap is
 *              narrower and more concrete: the pinned ECDSA-P256 public key and the
 *              CHALLENGE_AUTH response's ECC signature have no post-quantum
 *              equivalent, so a future cryptographically-relevant quantum computer
 *              could forge a valid CHALLENGE_AUTH response for any pinned peer.
 *              This extension adds a SECOND, independent ML-DSA-65 signature
 *              alongside the existing ECDSA one — both must verify, so breaking
 *              either algorithm alone is insufficient (hybrid signature composition,
 *              the same defence-in-depth principle already used for the ML-KEM
 *              hybrid key exchange in pqc-kem-extension/).
 *
 *              Sizes below are FIPS 204 ML-DSA-65 (public key 1952B, secret key
 *              4032B, signature 3309B) — NIST Level 3, matching the security level
 *              already chosen for ML-KEM-768 in pqc-kem-extension, not picked
 *              independently.
 *
 * @project     zzta-pqc-signature-extension (companion to zonal-zero-trust-authenticator)
 * @standards   AUTOSAR C++14, ISO/SAE 21434, NIST FIPS 204 (ML-DSA)
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        UnavailablePqcSignatureProvider below is the ONLY provider shipped
 *              here. It fails closed on every call. No ML-DSA math is implemented in
 *              this repository — see README.md for what wiring a real backend
 *              (liboqs / OpenSSL 3.5+) requires.
 * =====================================================================================
 */

#ifndef ZZTA_PQC_SIGNATURE_PLATFORM_INTERFACE_HPP
#define ZZTA_PQC_SIGNATURE_PLATFORM_INTERFACE_HPP

#include "zzta/CryptoPlatformInterface.hpp"
#include <array>
#include <cstdint>
#include <cstddef>

namespace zzta {

// ─────────────────────────────────────────────────────────────────────────────
// ML-DSA-65 (FIPS 204) compile-time sizes.
// ─────────────────────────────────────────────────────────────────────────────

static constexpr std::size_t kMlDsa65PublicKeyLen{1952U};
static constexpr std::size_t kMlDsa65SecretKeyLen{4032U};
static constexpr std::size_t kMlDsa65SignatureLen{3309U};

using PqcSigPublicKey = std::array<uint8_t, kMlDsa65PublicKeyLen>;
using PqcSigSecretKey = std::array<uint8_t, kMlDsa65SecretKeyLen>;
using PqcSignature    = std::array<uint8_t, kMlDsa65SignatureLen>;

// ─────────────────────────────────────────────────────────────────────────────
// PqcSignaturePlatformInterface — same shape as CryptoPlatformInterface.
// ─────────────────────────────────────────────────────────────────────────────

class PqcSignaturePlatformInterface
{
public:
    PqcSignaturePlatformInterface()                                              = default;
    PqcSignaturePlatformInterface(const PqcSignaturePlatformInterface&)            = delete;
    PqcSignaturePlatformInterface& operator=(const PqcSignaturePlatformInterface&) = delete;
    PqcSignaturePlatformInterface(PqcSignaturePlatformInterface&&)                 = delete;
    PqcSignaturePlatformInterface& operator=(PqcSignaturePlatformInterface&&)      = delete;
    virtual ~PqcSignaturePlatformInterface()                                      = default;

    [[nodiscard]] virtual CryptoStatus GenerateKeyPair(
        PqcSigPublicKey& public_key_out,
        PqcSigSecretKey& secret_key_out) noexcept = 0;

    [[nodiscard]] virtual CryptoStatus Sign(
        const PqcSigSecretKey& secret_key,
        const uint8_t*         message,
        std::size_t            message_len,
        PqcSignature&          signature_out) noexcept = 0;

    [[nodiscard]] virtual CryptoStatus Verify(
        const PqcSigPublicKey& public_key,
        const uint8_t*         message,
        std::size_t            message_len,
        const PqcSignature&    signature) noexcept = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
// UnavailablePqcSignatureProvider — the only provider in this repository.
// Fails closed on every call, same discipline as UnavailablePqcKemProvider
// in pqc-kem-extension.
// ─────────────────────────────────────────────────────────────────────────────

class UnavailablePqcSignatureProvider final : public PqcSignaturePlatformInterface
{
public:
    UnavailablePqcSignatureProvider()  noexcept = default;
    ~UnavailablePqcSignatureProvider() override = default;

    UnavailablePqcSignatureProvider(const UnavailablePqcSignatureProvider&)            = delete;
    UnavailablePqcSignatureProvider& operator=(const UnavailablePqcSignatureProvider&) = delete;
    UnavailablePqcSignatureProvider(UnavailablePqcSignatureProvider&&)                 = delete;
    UnavailablePqcSignatureProvider& operator=(UnavailablePqcSignatureProvider&&)      = delete;

    [[nodiscard]] CryptoStatus GenerateKeyPair(
        PqcSigPublicKey& public_key_out,
        PqcSigSecretKey& secret_key_out) noexcept override;

    [[nodiscard]] CryptoStatus Sign(
        const PqcSigSecretKey& secret_key,
        const uint8_t*         message,
        std::size_t            message_len,
        PqcSignature&          signature_out) noexcept override;

    [[nodiscard]] CryptoStatus Verify(
        const PqcSigPublicKey& public_key,
        const uint8_t*         message,
        std::size_t            message_len,
        const PqcSignature&    signature) noexcept override;
};

} // namespace zzta

#endif // ZZTA_PQC_SIGNATURE_PLATFORM_INTERFACE_HPP
