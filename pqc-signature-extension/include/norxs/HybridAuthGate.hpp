/**
 * =====================================================================================
 * @file        HybridAuthGate.hpp
 * @brief       Composes a second, independent ML-DSA-65 signature check on top of
 *              zonal-zero-trust-auth's real, unmodified SpdmProtocolEngine, so a
 *              CHALLENGE_AUTH handshake is only truly trusted once BOTH the existing
 *              classical ECDSA-P256 signature AND a companion post-quantum signature
 *              verify over the same challenge material.
 *
 *              This is deliberately a composition, not a fork: SpdmProtocolEngine's
 *              source is untouched. The one real correctness hazard a bolt-on second
 *              check creates is a window where ProcessAuthResponse() has already
 *              returned kOk (state == kAuthenticated, a live SpdmSessionToken exists)
 *              before the PQC check runs. ConfirmHybrid() closes that window itself:
 *              on a PQC verification failure, it calls the engine's own real
 *              Revoke() before returning - the caller never has to remember to do
 *              this, and there is no code path in this module that returns success
 *              without both signatures having verified.
 *
 *              Required call order (enforced defensively, not just documented):
 *              1. engine.ProcessAuthRequest(...)
 *              2. engine.ProcessAuthResponse(...) -> must return SpdmStatus::kOk
 *              3. HybridAuthGate::ConfirmHybrid(engine, ...) -> only THIS result is
 *                 the real authentication decision.
 *
 * @project     zzta-pqc-signature-extension (companion to zonal-zero-trust-authenticator)
 * @standards   AUTOSAR C++14, ISO/SAE 21434, NIST FIPS 204 (ML-DSA)
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        The PQC public key table (ClientId -> PqcSigPublicKey) is a NEW,
 *              separate table this module does not own the storage of - it is not
 *              part of zonal-zero-trust-auth's KnownPeerEntry, since this repository
 *              does not modify that struct. See README.md Assumptions of Use.
 * =====================================================================================
 */

#ifndef NORXS_HYBRID_AUTH_GATE_HPP
#define NORXS_HYBRID_AUTH_GATE_HPP

#include "zzta/SpdmProtocolEngine.hpp"
#include "zzta/PqcSignaturePlatformInterface.hpp"

namespace norxs {
namespace hybridauth {

using zzta::SpdmProtocolEngine;
using zzta::SpdmStatus;
using zzta::ClientId;
using zzta::Nonce;
using zzta::PqcSignaturePlatformInterface;
using zzta::PqcSigPublicKey;
using zzta::PqcSignature;

class HybridAuthGate final
{
public:
    explicit HybridAuthGate(PqcSignaturePlatformInterface& pqc_pal) noexcept;
    ~HybridAuthGate() noexcept = default;

    HybridAuthGate(const HybridAuthGate&)            = delete;
    HybridAuthGate& operator=(const HybridAuthGate&) = delete;
    HybridAuthGate(HybridAuthGate&&)                 = delete;
    HybridAuthGate& operator=(HybridAuthGate&&)      = delete;

    /**
     * @brief Perform the second, PQC half of the hybrid check.
     *
     * @param engine                An SpdmProtocolEngine that has JUST returned
     *                               SpdmStatus::kOk from ProcessAuthResponse() for
     *                               this same handshake (state must currently be
     *                               kAuthenticated - checked defensively).
     * @param client_id              The same client_id from the handshake.
     * @param peer_pqc_public_key    Looked up by the caller from a table this
     *                               module does not own (see README AoU).
     * @param peer_pqc_signature     ML-DSA-65 signature over (session_nonce ||
     *                               client_id), the same message shape the
     *                               classical signature covers.
     * @param session_nonce          The nonce from the just-completed handshake
     *                               (engine.GetPendingChallenge() before
     *                               ProcessAuthResponse() consumed it, or captured
     *                               by the caller at ProcessAuthRequest() time).
     *
     * @return SpdmStatus::kOk only if the PQC signature also verifies.
     *         SpdmStatus::kInvalidState if engine wasn't already kAuthenticated.
     *         SpdmStatus::kSignatureInvalid if the PQC check fails - engine.Revoke()
     *         has ALREADY been called in this case, before returning.
     */
    [[nodiscard]] SpdmStatus ConfirmHybrid(
        SpdmProtocolEngine&    engine,
        const ClientId&        client_id,
        const PqcSigPublicKey& peer_pqc_public_key,
        const PqcSignature&    peer_pqc_signature,
        const Nonce&           session_nonce) noexcept;

private:
    PqcSignaturePlatformInterface& pqc_pal_;
};

} // namespace hybridauth
} // namespace norxs

#endif // NORXS_HYBRID_AUTH_GATE_HPP
