/**
 * =====================================================================================
 * @file        V2xCertificate.hpp
 * @brief       Minimal, standards-grounded pseudonym certificate types for V2X
 *              (Vehicle-to-Everything) trust — the extension SafetyArbitrator.hpp's
 *              own `kV2X = 5U, ///< Vehicle-to-Everything (future use)` comment names
 *              but nothing in autosar-soa-gateway or zonal-zero-trust-auth implements.
 *
 *              Why this can't reuse zonal-zero-trust-auth's trust model directly:
 *              SpdmProtocolEngine's KnownPeerEntry is a compile-time `.rodata` table
 *              of raw pinned public keys — workable for a closed set of in-vehicle
 *              zonal ECUs provisioned at manufacture time, structurally impossible
 *              for V2X, where the vehicle must trust messages from other vehicles and
 *              infrastructure it has never seen before and cannot pre-provision. Real
 *              V2X (IEEE 1609.2, the security standard SAE J2735 Basic Safety
 *              Messages are signed under) uses a certificate CHAIN instead: a
 *              short-lived, rotating pseudonym certificate (privacy-preserving - it
 *              does not identify the specific vehicle) signed by an intermediate CA,
 *              whose own certificate is signed by a root CA the receiver trusts a
 *              priori. This file models that chain shape, reusing
 *              zonal-zero-trust-auth's existing EccPublicKey/CryptoSignature/
 *              Sha256Digest types and VerifyEccSignature/ComputeSha256 PAL calls for
 *              the actual cryptography - no signature primitive is implemented here.
 *
 *              What's deliberately NOT modelled (see README.md for the full list):
 *              butterfly key expansion, CRL/CTL revocation checking, the SCMS
 *              provisioning protocol itself, and the geographic/PSID permission
 *              region fields IEEE 1609.2 certificates actually carry. This is the
 *              trust-chain-verification core, not a full 1609.2 stack.
 *
 * @project     v2x-trust-extension (companion to autosar-soa-gateway and
 *              zonal-zero-trust-authenticator)
 * @standards   AUTOSAR C++14, IEEE 1609.2, SAE J2735, ISO/SAE 21434
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * =====================================================================================
 */

#ifndef NORXS_V2X_CERTIFICATE_HPP
#define NORXS_V2X_CERTIFICATE_HPP

#include "zzta/CryptoPlatformInterface.hpp"
#include <array>
#include <cstdint>
#include <cstddef>

namespace norxs {
namespace v2x {

using zzta::EccPublicKey;
using zzta::CryptoSignature;
using zzta::Sha256Digest;
using zzta::CryptoStatus;
using zzta::CryptoPlatformInterface;

// ─────────────────────────────────────────────────────────────────────────────
// Wire-size constants
// ─────────────────────────────────────────────────────────────────────────────

/** @brief Maximum SAE J2735 Basic Safety Message payload this module handles. */
static constexpr std::size_t kMaxBsmPayloadBytes{192U};

// ─────────────────────────────────────────────────────────────────────────────
// Pseudonym certificate (leaf) and CA certificate (intermediate) — same
// shape, since a chain is built from the same certificate structure at each
// level in IEEE 1609.2's explicit certificate format.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Minimal IEEE-1609.2-shaped certificate: a public key, a validity
 *        window, and the issuer's signature over (public_key || validity).
 *
 * Real 1609.2 certificates also carry PSID/SSP permission fields (which
 * services this certificate may sign for) and a geographic validity region.
 * Neither is modelled here — see README.md "What this does not do".
 */
struct V2xCertificate {
    EccPublicKey    subject_public_key; ///< This certificate's own public key.
    std::uint32_t   valid_from_epoch_s; ///< Validity window start (Unix epoch seconds).
    std::uint32_t   valid_until_epoch_s;///< Validity window end (exclusive).
    CryptoSignature issuer_signature;   ///< Issuer's signature over SHA-256(subject_public_key || valid_from || valid_until).
};

/**
 * @brief A received, signed Basic Safety Message plus the pseudonym
 *        certificate chain the sender attached to it.
 */
struct V2xSignedBsm {
    std::array<std::uint8_t, kMaxBsmPayloadBytes> payload;      ///< Raw SAE J2735 BSM bytes.
    std::uint16_t                                  payload_len;  ///< Bytes actually used.
    V2xCertificate                                 pseudonym_cert; ///< Leaf cert (signs the BSM).
    V2xCertificate                                 intermediate_cert; ///< Signs the pseudonym cert.
    CryptoSignature                                bsm_signature; ///< Pseudonym cert's signature over SHA-256(payload).
};

// ─────────────────────────────────────────────────────────────────────────────
// Trust verification result — distinct rejection reasons, matching this
// project's established fail-safe-default / evidence-log discipline.
// ─────────────────────────────────────────────────────────────────────────────

enum class V2xTrustStatus : std::uint8_t {
    kTrusted                  = 0U, ///< Full chain verified, message signature valid, both certs in validity window.
    kInvalidInput              = 1U, ///< Null pointer or malformed input.
    kRootSignatureInvalid      = 2U, ///< Intermediate cert's signature does not verify against the trusted root key.
    kIntermediateExpired       = 3U, ///< Intermediate cert outside its validity window at check time.
    kLeafSignatureInvalid      = 4U, ///< Pseudonym cert's signature does not verify against the (now-trusted) intermediate key.
    kLeafExpired                = 5U, ///< Pseudonym cert outside its validity window at check time.
    kBsmSignatureInvalid       = 6U, ///< BSM payload signature does not verify against the (now-trusted) pseudonym key.
    kCryptoError                = 7U  ///< PAL reported a hardware/derivation fault.
};

} // namespace v2x
} // namespace norxs

#endif // NORXS_V2X_CERTIFICATE_HPP
