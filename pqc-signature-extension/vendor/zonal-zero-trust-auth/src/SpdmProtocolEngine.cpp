/**
 * =====================================================================================
 * @file        SpdmProtocolEngine.cpp
 * @brief       Implements the SpdmProtocolEngine four-state finite state machine that
 *              executes the SPDM DSP0274 v1.1 Challenge-Response authentication
 *              handshake for Zonal ECU peer-to-peer authentication over SOME/IP.
 *              The implementation enforces strict state-transition guards so that any
 *              out-of-sequence protocol message is rejected with SpdmStatus::kInvalidState,
 *              satisfying the Authentication Bypass threat (THREAT-03) identified in the
 *              project TARA. All cryptographic operations (nonce generation, SHA-256
 *              digest, ECC-P256 verification, HKDF key derivation) are delegated to the
 *              injected CryptoPlatformInterface PAL, keeping this file free of any
 *              hardware or OS dependency. Secret material is sanitised via volatile
 *              byte-write loops on both session termination paths (Revoke and Reset),
 *              preventing residual key material in RAM as required by UN R155 §7.2.2.
 * @project     zonal-zero-trust-authenticator
 * @standards   AUTOSAR C++14, ISO/SAE 21434, UN R155, ISO 26262 ASIL-D
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        This is a reference implementation showcasing norxs's SOA architecture.
 * =====================================================================================
 */

#include "zzta/SpdmProtocolEngine.hpp"

#include <cstring>  // std::memcpy, std::memset

namespace zzta {

// Out-of-line definition required for ODR use of static constexpr member
// (C++14 §9.4.2/3 — inline variable semantics not available until C++17)
constexpr std::array<uint8_t, 4U> SpdmProtocolEngine::kSupportedVersion;

// ─────────────────────────────────────────────────────────────────────────────
// Constructor
// ─────────────────────────────────────────────────────────────────────────────

SpdmProtocolEngine::SpdmProtocolEngine(
    CryptoPlatformInterface& crypto_pal,
    const KnownPeerEntry*    peer_table,
    std::size_t              peer_count) noexcept
    : crypto_pal_{crypto_pal}
    , peer_table_{peer_table}
    , peer_count_{(peer_count <= kMaxKnownPeers) ? peer_count : kMaxKnownPeers}
    , state_{State::kUnauthenticated}
    , pending_nonce_{}
    , pending_client_id_{}
    , authenticated_client_id_{}
{
    // Initialise all sensitive buffers to zero at construction.
    pending_nonce_.fill(0x00U);
    pending_client_id_.fill(0x00U);
    authenticated_client_id_.fill(0x00U);
}

// ─────────────────────────────────────────────────────────────────────────────
// ProcessAuthRequest
// ─────────────────────────────────────────────────────────────────────────────

SpdmStatus SpdmProtocolEngine::ProcessAuthRequest(
    const SpdmAuthRequest& request) noexcept
{
    // ── Guard: only valid from kUnauthenticated ───────────────────────────────
    if (state_ != State::kUnauthenticated)
    {
        return (state_ == State::kAuthenticated)
            ? SpdmStatus::kAlreadyAuthenticated
            : SpdmStatus::kInvalidState;
    }

    // ── Version check ─────────────────────────────────────────────────────────
    // Only SPDM v1.1 ({0x01, 0x10, 0x00, 0x00}) is supported in this release.
    bool version_ok{true};
    for (std::size_t i{0U}; i < request.version.size(); ++i)
    {
        if (request.version[i] != kSupportedVersion[i])
        {
            version_ok = false;
            break;
        }
    }
    if (!version_ok)
    {
        return SpdmStatus::kVersionMismatch;
    }

    // ── Peer registration check ───────────────────────────────────────────────
    // The requesting client must appear in the .rodata peer table.
    // An unknown peer is rejected without generating a nonce (prevents
    // oracle attacks on the RNG — THREAT-07).
    EccPublicKey dummy_key{};
    if (!FindPeerPublicKey(request.client_id, dummy_key))
    {
        // Not in the known-peer table — silently drop.
        return SpdmStatus::kSignatureInvalid;
    }

    // ── Generate 256-bit challenge nonce ──────────────────────────────────────
    const CryptoStatus rng_status{crypto_pal_.GenerateRandomNonce(pending_nonce_)};
    if (rng_status != CryptoStatus::kOk)
    {
        return SpdmStatus::kCryptoError;
    }

    // ── Latch client identity ─────────────────────────────────────────────────
    std::memcpy(pending_client_id_.data(),
                request.client_id.data(),
                kClientIdLen);

    // ── Advance state ─────────────────────────────────────────────────────────
    state_ = State::kChallengeSent;
    return SpdmStatus::kOk;
}

// ─────────────────────────────────────────────────────────────────────────────
// ProcessAuthResponse
// ─────────────────────────────────────────────────────────────────────────────

SpdmStatus SpdmProtocolEngine::ProcessAuthResponse(
    const SpdmAuthResponse& response,
    SpdmSessionToken&       session_token_out) noexcept
{
    // ── Guard: only valid from kChallengeSent ─────────────────────────────────
    if (state_ != State::kChallengeSent)
    {
        return SpdmStatus::kInvalidState;
    }

    // ── Client ID continuity check ────────────────────────────────────────────
    // The response must originate from exactly the node that sent the request.
    // A constant-time comparison prevents timing side-channel leakage.
    volatile uint8_t id_diff{0U};
    for (std::size_t i{0U}; i < kClientIdLen; ++i)
    {
        id_diff = static_cast<uint8_t>(id_diff | (response.client_id[i] ^ pending_client_id_[i]));
    }
    if (id_diff != 0U)
    {
        // Mismatch — this is a protocol-level anomaly; revoke immediately.
        Revoke();
        return SpdmStatus::kClientIdMismatch;
    }

    // ── Look up peer public key from .rodata table ───────────────────────────
    EccPublicKey peer_public_key{};
    if (!FindPeerPublicKey(response.client_id, peer_public_key))
    {
        // Should not reach here if ProcessAuthRequest ran correctly, but
        // defensive programming is mandated under ISO 26262 Part 6 §7.4.7.
        Revoke();
        return SpdmStatus::kSignatureInvalid;
    }

    // ── Compute challenge digest: SHA-256(nonce ∥ client_id) ─────────────────
    Sha256Digest challenge_digest{};
    const CryptoStatus digest_status{
        ComputeChallengeDigest(pending_nonce_, response.client_id, challenge_digest)};
    if (digest_status != CryptoStatus::kOk)
    {
        Revoke();
        return SpdmStatus::kCryptoError;
    }

    // ── Verify ECC-P256 signature ─────────────────────────────────────────────
    const CryptoStatus verify_status{
        crypto_pal_.VerifyEccSignature(challenge_digest, response.signature, peer_public_key)};
    if (verify_status != CryptoStatus::kOk)
    {
        // Invalid signature — revoke session and force re-auth.
        Revoke();
        return (verify_status == CryptoStatus::kVerifyFailed)
            ? SpdmStatus::kSignatureInvalid
            : SpdmStatus::kCryptoError;
    }

    // ── Derive HKDF session key ───────────────────────────────────────────────
    SessionKey derived_key{};
    const CryptoStatus kdf_status{
        crypto_pal_.DeriveSessionKey(pending_nonce_, response.client_id, derived_key)};
    if (kdf_status != CryptoStatus::kOk)
    {
        Revoke();
        return SpdmStatus::kCryptoError;
    }

    // ── Populate session token output ─────────────────────────────────────────
    std::memcpy(session_token_out.client_id.data(),
                response.client_id.data(),
                kClientIdLen);
    std::memcpy(session_token_out.session_nonce.data(),
                pending_nonce_.data(),
                kNonceLen);
    std::memcpy(session_token_out.session_key.data(),
                derived_key.data(),
                kSessionKeyLen);

    // ── Latch authenticated identity ──────────────────────────────────────────
    std::memcpy(authenticated_client_id_.data(),
                response.client_id.data(),
                kClientIdLen);

    // ── Sanitise intermediate derived key from local stack ────────────────────
    // The session token output already carries the key; the local copy must die.
    volatile uint8_t* p{reinterpret_cast<volatile uint8_t*>(derived_key.data())};
    for (std::size_t i{0U}; i < kSessionKeyLen; ++i) { p[i] = 0U; }

    // ── Advance state ─────────────────────────────────────────────────────────
    state_ = State::kAuthenticated;
    return SpdmStatus::kOk;
}

// ─────────────────────────────────────────────────────────────────────────────
// Revoke
// ─────────────────────────────────────────────────────────────────────────────

void SpdmProtocolEngine::Revoke() noexcept
{
    SanitiseSecretMaterial();
    state_ = State::kRevoked;
}

// ─────────────────────────────────────────────────────────────────────────────
// Reset
// ─────────────────────────────────────────────────────────────────────────────

void SpdmProtocolEngine::Reset() noexcept
{
    SanitiseSecretMaterial();
    authenticated_client_id_.fill(0x00U);
    state_ = State::kUnauthenticated;
}

// ─────────────────────────────────────────────────────────────────────────────
// FindPeerPublicKey
// ─────────────────────────────────────────────────────────────────────────────

bool SpdmProtocolEngine::FindPeerPublicKey(
    const ClientId& client_id,
    EccPublicKey&   key_out) const noexcept
{
    if (peer_table_ == nullptr)
    {
        return false;
    }

    for (std::size_t i{0U}; i < peer_count_; ++i)
    {
        // Constant-time comparison to prevent oracle-based client enumeration.
        volatile uint8_t diff{0U};
        for (std::size_t j{0U}; j < kClientIdLen; ++j)
        {
            diff = static_cast<uint8_t>(diff | (client_id[j] ^ peer_table_[i].client_id[j]));
        }
        if (diff == 0U)
        {
            key_out = peer_table_[i].public_key;
            return true;
        }
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// ComputeChallengeDigest — SHA-256(nonce ∥ client_id)
// ─────────────────────────────────────────────────────────────────────────────

CryptoStatus SpdmProtocolEngine::ComputeChallengeDigest(
    const Nonce&    nonce,
    const ClientId& client_id,
    Sha256Digest&   digest_out) noexcept
{
    // Concatenate nonce ∥ client_id into a stack-local fixed buffer.
    constexpr std::size_t kMsgLen{kNonceLen + kClientIdLen};
    std::array<uint8_t, kMsgLen> msg{};
    std::memcpy(&msg[0],        nonce.data(),     kNonceLen);
    std::memcpy(&msg[kNonceLen], client_id.data(), kClientIdLen);

    return crypto_pal_.ComputeSha256(msg.data(), kMsgLen, digest_out);
}

// ─────────────────────────────────────────────────────────────────────────────
// SanitiseSecretMaterial
// ─────────────────────────────────────────────────────────────────────────────

void SpdmProtocolEngine::SanitiseSecretMaterial() noexcept
{
    // Volatile byte-write loop prevents dead-store elimination by the compiler.
    // This is the approved AUTOSAR pattern for zeroing sensitive key material.
    volatile uint8_t* nonce_p{pending_nonce_.data()};
    for (std::size_t i{0U}; i < kNonceLen; ++i)       { nonce_p[i]   = 0U; }

    volatile uint8_t* id_p{pending_client_id_.data()};
    for (std::size_t i{0U}; i < kClientIdLen; ++i)     { id_p[i]      = 0U; }
}

} // namespace zzta
