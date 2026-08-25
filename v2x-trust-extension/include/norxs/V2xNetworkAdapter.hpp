/**
 * =====================================================================================
 * @file        V2xNetworkAdapter.hpp
 * @brief       Concrete norxs::soa::NetworkAdapter implementation for V2X BSM ingress:
 *              the first concrete implementation of that abstract interface anywhere
 *              in the norxs reference repos (autosar-soa-gateway itself ships the
 *              interface only - no SOME/IP or DDS concrete adapter is provided
 *              there either, so this class does not displace or duplicate anything).
 *
 *              Deserialise() is where this module's real work happens: it unpacks a
 *              raw WireFrame into a V2xSignedBsm, runs it through V2xTrustVerifier,
 *              and - only on a fully-trusted result - packs the decoded content into
 *              a CooperativeAwarenessAdvisory and publishes it as a SoaEvent. An
 *              untrusted or malformed frame never produces a SoaEvent at all
 *              (fail-safe default, matching V2xTrustVerifier's own discipline).
 *
 *              Receive()/Transmit() are honestly NOT implemented: binding to a real
 *              DSRC/C-V2X (PC5) radio is a deployment-specific transport concern
 *              this module does not model, exactly as autosar-soa-gateway's own
 *              NetworkAdapter interface leaves transport binding to each concrete
 *              adapter. Serialise() IS implemented, for the narrower, in-scope case
 *              of re-packing an already-verified CooperativeAwarenessAdvisory for
 *              distribution to other in-vehicle ECUs over the existing SOA gateway -
 *              this requires no signing key and stays within what this module
 *              actually verifies.
 *
 * @project     v2x-trust-extension
 * @standards   AUTOSAR C++14, IEEE 1609.2, SAE J2735
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * =====================================================================================
 */

#ifndef NORXS_V2X_NETWORK_ADAPTER_HPP
#define NORXS_V2X_NETWORK_ADAPTER_HPP

#include "NetworkAdapter.hpp"
#include "norxs/CooperativeAwarenessAdvisory.hpp"
#include "norxs/V2xTrustVerifier.hpp"

namespace norxs {
namespace v2x {

/**
 * @brief Fixed on-wire size of one V2xSignedBsm frame this adapter accepts:
 *        payload_len(2) + payload(kMaxBsmPayloadBytes) + pseudonym_cert(105)
 *        + intermediate_cert(105) + bsm_signature(64). A frame of any other
 *        length is rejected as malformed (kInvalidArgument) before any
 *        cryptographic operation is attempted.
 */
static constexpr std::size_t kV2xWireFrameBytes{2U + kMaxBsmPayloadBytes + 105U + 105U + 64U};

/** @brief Fixed size of this module's simplified BSM core payload (see CooperativeAwarenessAdvisory.hpp). */
static constexpr std::size_t kBsmCorePayloadBytes{16U};

/** @brief Plain function-pointer clock source (no std::function, matching soa::EventHandler's no-heap idiom). Returns Unix epoch seconds. */
using NowEpochSFn = std::uint32_t (*)();

/** @brief Placeholder SOME/IP service/event IDs for this advisory - not yet allocated in norxs's central service registry; MUST be reassigned real IDs before production integration. */
static constexpr std::uint16_t kV2xAdvisoryServiceId{0x1900U};
static constexpr std::uint16_t kV2xAdvisoryEventId{0x1901U};

class V2xNetworkAdapter final : public soa::NetworkAdapter {
public:
    /**
     * @param crypto_pal        Real CryptoPlatformInterface used for all verification.
     * @param trusted_root_key  Root CA public key this adapter trusts a priori.
     * @param now_fn            Clock source for certificate validity checks; injectable for deterministic testing.
     */
    V2xNetworkAdapter(zzta::CryptoPlatformInterface& crypto_pal,
                       const zzta::EccPublicKey&      trusted_root_key,
                       NowEpochSFn                     now_fn) noexcept;

    ~V2xNetworkAdapter() noexcept override = default;

    V2xNetworkAdapter(const V2xNetworkAdapter&)            = delete;
    V2xNetworkAdapter& operator=(const V2xNetworkAdapter&) = delete;
    V2xNetworkAdapter(V2xNetworkAdapter&&)                 = delete;
    V2xNetworkAdapter& operator=(V2xNetworkAdapter&&)      = delete;

    soa::VoidResult Init() noexcept override;

    /** @brief Not implemented - see file header. Always returns kNotInitialized. */
    soa::VoidResult Receive(soa::WireFrame& frame) noexcept override;

    /**
     * @brief Unpack, cryptographically verify, and (on success only) publish
     *        the decoded content as a SoaEvent carrying a
     *        CooperativeAwarenessAdvisory payload.
     * @return kOk with event populated on a fully-trusted frame;
     *         kInvalidArgument on a malformed frame (wrong length, bad payload_len);
     *         kUnauthorized if V2xTrustVerifier rejects the chain (see
     *         GetLastTrustStatus() for the specific reason);
     *         kUnknown on a PAL crypto error.
     */
    soa::VoidResult Deserialise(soa::WireFrame const& frame, soa::SoaEvent& event) noexcept override;

    /** @brief Packs a CooperativeAwarenessAdvisory-carrying SoaEvent back into wire bytes for in-vehicle redistribution. No signing performed. */
    soa::VoidResult Serialise(soa::SoaEvent const& event, soa::WireFrame& frame) noexcept override;

    /** @brief Not implemented - see file header. Always returns kNotInitialized. */
    soa::VoidResult Transmit(soa::WireFrame const& frame) noexcept override;

    char const* ProtocolName() const noexcept override;

    /** @brief Reason the most recent Deserialise() call rejected a frame's chain, if any. */
    [[nodiscard]] V2xTrustStatus GetLastTrustStatus() const noexcept { return last_trust_status_; }

private:
    static bool UnpackWireFrame(soa::WireFrame const& frame, V2xSignedBsm& bsm_out) noexcept;
    static void PackAdvisory(CooperativeAwarenessAdvisory const& advisory, soa::SoaEvent& event) noexcept;

    V2xTrustVerifier verifier_;
    zzta::CryptoPlatformInterface& crypto_pal_;
    NowEpochSFn       now_fn_;
    V2xTrustStatus    last_trust_status_;
    bool              initialised_;
};

} // namespace v2x
} // namespace norxs

#endif // NORXS_V2X_NETWORK_ADAPTER_HPP
