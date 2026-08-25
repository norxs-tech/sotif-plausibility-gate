/**
 * @copyright (c) 2026 norxs Technology LLC. All rights reserved.
 */

#include "norxs/V2xTrustVerifier.hpp"
#include <cstring>

namespace norxs {
namespace v2x {

namespace {
// Portable (endianness-independent) little-endian byte packing for the
// two uint32 validity fields, same discipline autosar-soa-gateway's own
// E2E code uses rather than relying on memcpy of the raw struct layout.
void PackU32Le(std::uint32_t value, std::uint8_t* out) noexcept {
    out[0] = static_cast<std::uint8_t>(value & 0xFFU);
    out[1] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
    out[2] = static_cast<std::uint8_t>((value >> 16U) & 0xFFU);
    out[3] = static_cast<std::uint8_t>((value >> 24U) & 0xFFU);
}

constexpr std::size_t kCertSignedMsgLen = 33U /* EccPublicKey */ + 4U + 4U;
} // namespace

V2xTrustVerifier::V2xTrustVerifier(CryptoPlatformInterface& crypto_pal,
                                     const EccPublicKey&      trusted_root_key) noexcept
    : crypto_pal_(crypto_pal), trusted_root_key_(trusted_root_key) {
}

bool V2xTrustVerifier::WithinValidity(const V2xCertificate& cert, std::uint32_t nowEpochS) noexcept {
    return (nowEpochS >= cert.valid_from_epoch_s) && (nowEpochS < cert.valid_until_epoch_s);
}

bool V2xTrustVerifier::VerifyCertSignature(const V2xCertificate& cert,
                                             const EccPublicKey&   issuerPublicKey) noexcept {
    std::array<std::uint8_t, kCertSignedMsgLen> msg{};
    std::memcpy(&msg[0], cert.subject_public_key.data(), 33U);
    PackU32Le(cert.valid_from_epoch_s, &msg[33]);
    PackU32Le(cert.valid_until_epoch_s, &msg[37]);

    Sha256Digest digest{};
    if (crypto_pal_.ComputeSha256(msg.data(), msg.size(), digest) != CryptoStatus::kOk) {
        return false;
    }

    return crypto_pal_.VerifyEccSignature(digest, cert.issuer_signature, issuerPublicKey) == CryptoStatus::kOk;
}

V2xTrustStatus V2xTrustVerifier::VerifyChain(const V2xSignedBsm& bsm, std::uint32_t nowEpochS) noexcept {
    if (bsm.payload_len == 0U || bsm.payload_len > kMaxBsmPayloadBytes) {
        return V2xTrustStatus::kInvalidInput;
    }

    // Step 1: intermediate cert's signature must verify against the
    // a-priori-trusted root key. Nothing downstream is checked if this
    // fails - fail-safe default, first failure wins.
    if (!VerifyCertSignature(bsm.intermediate_cert, trusted_root_key_)) {
        return V2xTrustStatus::kRootSignatureInvalid;
    }

    // Step 2: intermediate cert must be within its validity window NOW.
    if (!WithinValidity(bsm.intermediate_cert, nowEpochS)) {
        return V2xTrustStatus::kIntermediateExpired;
    }

    // Step 3: pseudonym (leaf) cert's signature must verify against the
    // now-trusted intermediate cert's public key.
    if (!VerifyCertSignature(bsm.pseudonym_cert, bsm.intermediate_cert.subject_public_key)) {
        return V2xTrustStatus::kLeafSignatureInvalid;
    }

    // Step 4: pseudonym cert must be within its validity window NOW.
    if (!WithinValidity(bsm.pseudonym_cert, nowEpochS)) {
        return V2xTrustStatus::kLeafExpired;
    }

    // Step 5: the BSM payload's signature must verify against the
    // now-trusted pseudonym cert's public key.
    Sha256Digest payloadDigest{};
    if (crypto_pal_.ComputeSha256(bsm.payload.data(), bsm.payload_len, payloadDigest) != CryptoStatus::kOk) {
        return V2xTrustStatus::kCryptoError;
    }
    if (crypto_pal_.VerifyEccSignature(payloadDigest, bsm.bsm_signature,
                                        bsm.pseudonym_cert.subject_public_key) != CryptoStatus::kOk) {
        return V2xTrustStatus::kBsmSignatureInvalid;
    }

    return V2xTrustStatus::kTrusted;
}

} // namespace v2x
} // namespace norxs
