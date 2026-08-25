/**
 * @copyright (c) 2026 norxs Technology LLC. All rights reserved.
 */

#include "norxs/HybridAuthGate.hpp"
#include <array>
#include <cstring>

namespace norxs {
namespace hybridauth {

HybridAuthGate::HybridAuthGate(PqcSignaturePlatformInterface& pqc_pal) noexcept
    : pqc_pal_(pqc_pal) {
}

SpdmStatus HybridAuthGate::ConfirmHybrid(
    SpdmProtocolEngine&    engine,
    const ClientId&        client_id,
    const PqcSigPublicKey& peer_pqc_public_key,
    const PqcSignature&    peer_pqc_signature,
    const Nonce&           session_nonce) noexcept
{
    // Defensive precondition check: this module is only meaningful applied
    // to an engine that JUST completed classical authentication for THIS
    // handshake. Calling it in any other state is a caller ordering bug,
    // not a normal outcome - reject rather than guess intent.
    if (engine.GetState() != SpdmProtocolEngine::State::kAuthenticated) {
        return SpdmStatus::kInvalidState;
    }

    // Same message shape the classical signature covers (nonce || client_id),
    // per SpdmProtocolEngine.hpp's ComputeChallengeDigest documentation -
    // kept consistent for clarity, not because the two algorithms need to
    // agree on byte layout to be independently secure.
    std::array<std::uint8_t, zzta::kNonceLen + zzta::kClientIdLen> message{};
    std::memcpy(&message[0], session_nonce.data(), zzta::kNonceLen);
    std::memcpy(&message[zzta::kNonceLen], client_id.data(), zzta::kClientIdLen);

    zzta::CryptoStatus const pqcStatus = pqc_pal_.Verify(
        peer_pqc_public_key, message.data(), message.size(), peer_pqc_signature);

    SpdmStatus result;

    if (pqcStatus == zzta::CryptoStatus::kOk) {
        result = SpdmStatus::kOk;
    } else {
        // The classical-only session must not outlive a failed PQC check.
        // Revoke through the engine's own real, unmodified public API -
        // this repository does not reach into its private state.
        engine.Revoke();
        result = SpdmStatus::kSignatureInvalid;
    }

    return result;
}

} // namespace hybridauth
} // namespace norxs
