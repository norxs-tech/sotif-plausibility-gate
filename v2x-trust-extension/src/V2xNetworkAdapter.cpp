/**
 * @copyright (c) 2026 norxs Technology LLC. All rights reserved.
 */

#include "norxs/V2xNetworkAdapter.hpp"
#include <cstring>

namespace norxs {
namespace v2x {

namespace {

void PackU16Le(std::uint16_t value, std::uint8_t* out) noexcept {
    out[0] = static_cast<std::uint8_t>(value & 0xFFU);
    out[1] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
}

std::uint16_t UnpackU16Le(std::uint8_t const* in) noexcept {
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(in[0]) |
                                       (static_cast<std::uint16_t>(in[1]) << 8U));
}

void PackU32Le(std::uint32_t value, std::uint8_t* out) noexcept {
    out[0] = static_cast<std::uint8_t>(value & 0xFFU);
    out[1] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
    out[2] = static_cast<std::uint8_t>((value >> 16U) & 0xFFU);
    out[3] = static_cast<std::uint8_t>((value >> 24U) & 0xFFU);
}

std::uint32_t UnpackU32Le(std::uint8_t const* in) noexcept {
    return static_cast<std::uint32_t>(in[0]) |
           (static_cast<std::uint32_t>(in[1]) << 8U) |
           (static_cast<std::uint32_t>(in[2]) << 16U) |
           (static_cast<std::uint32_t>(in[3]) << 24U);
}

constexpr std::size_t kCertWireBytes = 33U + 4U + 4U + 64U;

void UnpackCert(std::uint8_t const* in, V2xCertificate& cert_out) noexcept {
    std::memcpy(cert_out.subject_public_key.data(), &in[0], 33U);
    cert_out.valid_from_epoch_s  = UnpackU32Le(&in[33]);
    cert_out.valid_until_epoch_s = UnpackU32Le(&in[37]);
    std::memcpy(cert_out.issuer_signature.data(), &in[41], 64U);
}

} // namespace

V2xNetworkAdapter::V2xNetworkAdapter(zzta::CryptoPlatformInterface& crypto_pal,
                                       const zzta::EccPublicKey&      trusted_root_key,
                                       NowEpochSFn                     now_fn) noexcept
    : verifier_(crypto_pal, trusted_root_key),
      crypto_pal_(crypto_pal),
      now_fn_(now_fn),
      last_trust_status_(V2xTrustStatus::kInvalidInput),
      initialised_(false) {
}

soa::VoidResult V2xNetworkAdapter::Init() noexcept {
    initialised_ = true;
    return soa::VoidResult::Ok();
}

soa::VoidResult V2xNetworkAdapter::Receive(soa::WireFrame& frame) noexcept {
    static_cast<void>(frame);
    // No transport binding modelled - see file header. A concrete deployment
    // must supply its own DSRC/C-V2X radio binding and feed frames directly
    // into Deserialise().
    return soa::VoidResult::Err(soa::ErrorCode::kNotInitialized);
}

bool V2xNetworkAdapter::UnpackWireFrame(soa::WireFrame const& frame, V2xSignedBsm& bsm_out) noexcept {
    if (frame.length != static_cast<std::uint16_t>(kV2xWireFrameBytes)) {
        return false;
    }

    std::uint8_t const* p = frame.data.data();
    std::uint16_t payloadLen = UnpackU16Le(&p[0]);
    if (payloadLen > kMaxBsmPayloadBytes) {
        return false;
    }

    bsm_out.payload_len = payloadLen;
    std::memcpy(bsm_out.payload.data(), &p[2], kMaxBsmPayloadBytes);
    UnpackCert(&p[2U + kMaxBsmPayloadBytes], bsm_out.pseudonym_cert);
    UnpackCert(&p[2U + kMaxBsmPayloadBytes + kCertWireBytes], bsm_out.intermediate_cert);
    std::memcpy(bsm_out.bsm_signature.data(),
                &p[2U + kMaxBsmPayloadBytes + (2U * kCertWireBytes)], 64U);
    return true;
}

void V2xNetworkAdapter::PackAdvisory(CooperativeAwarenessAdvisory const& advisory, soa::SoaEvent& event) noexcept {
    event.serviceId = kV2xAdvisoryServiceId;
    event.eventId   = kV2xAdvisoryEventId;
    event.sessionId = advisory.msg_timestamp_epoch_s;

    std::uint8_t* out = event.payload;
    PackU32Le(static_cast<std::uint32_t>(advisory.latitude_1e7), &out[0]);
    PackU32Le(static_cast<std::uint32_t>(advisory.longitude_1e7), &out[4]);
    PackU16Le(static_cast<std::uint16_t>(advisory.speed_cm_s), &out[8]);
    PackU16Le(static_cast<std::uint16_t>(advisory.heading_decidegrees), &out[10]);
    PackU32Le(advisory.msg_timestamp_epoch_s, &out[12]);
    std::memcpy(&out[16], advisory.pseudonym_correlation_hash.data(), kPseudonymCorrelationHashLen);
    out[16U + kPseudonymCorrelationHashLen] = static_cast<std::uint8_t>(advisory.trust_status);

    event.payloadLen = static_cast<std::uint8_t>(17U + kPseudonymCorrelationHashLen);
}

soa::VoidResult V2xNetworkAdapter::Deserialise(soa::WireFrame const& frame, soa::SoaEvent& event) noexcept {
    if (!initialised_) {
        return soa::VoidResult::Err(soa::ErrorCode::kNotInitialized);
    }

    V2xSignedBsm bsm{};
    if (!UnpackWireFrame(frame, bsm)) {
        last_trust_status_ = V2xTrustStatus::kInvalidInput;
        return soa::VoidResult::Err(soa::ErrorCode::kInvalidArgument);
    }

    if (bsm.payload_len != static_cast<std::uint16_t>(kBsmCorePayloadBytes)) {
        last_trust_status_ = V2xTrustStatus::kInvalidInput;
        return soa::VoidResult::Err(soa::ErrorCode::kInvalidArgument);
    }

    std::uint32_t const nowEpochS = now_fn_();
    // The payload_len == kBsmCorePayloadBytes gate above already guarantees
    // bsm.payload_len is non-zero and within kMaxBsmPayloadBytes, so
    // VerifyChain's own kInvalidInput case is structurally unreachable here.
    last_trust_status_ = verifier_.VerifyChain(bsm, nowEpochS);

    if (last_trust_status_ == V2xTrustStatus::kCryptoError) {
        return soa::VoidResult::Err(soa::ErrorCode::kUnknown);
    }
    if (last_trust_status_ != V2xTrustStatus::kTrusted) {
        return soa::VoidResult::Err(soa::ErrorCode::kUnauthorized);
    }

    CooperativeAwarenessAdvisory advisory{};
    std::uint8_t const* pl = bsm.payload.data();
    advisory.latitude_1e7          = static_cast<std::int32_t>(UnpackU32Le(&pl[0]));
    advisory.longitude_1e7         = static_cast<std::int32_t>(UnpackU32Le(&pl[4]));
    advisory.speed_cm_s            = static_cast<std::int16_t>(UnpackU16Le(&pl[8]));
    advisory.heading_decidegrees   = static_cast<std::int16_t>(UnpackU16Le(&pl[10]));
    advisory.msg_timestamp_epoch_s = UnpackU32Le(&pl[12]);
    advisory.trust_status          = V2xTrustStatus::kTrusted;

    Sha256Digest pubKeyDigest{};
    if (crypto_pal_.ComputeSha256(bsm.pseudonym_cert.subject_public_key.data(),
                                   bsm.pseudonym_cert.subject_public_key.size(),
                                   pubKeyDigest) != CryptoStatus::kOk) {
        last_trust_status_ = V2xTrustStatus::kCryptoError;
        return soa::VoidResult::Err(soa::ErrorCode::kUnknown);
    }
    std::memcpy(advisory.pseudonym_correlation_hash.data(), pubKeyDigest.data(), kPseudonymCorrelationHashLen);

    PackAdvisory(advisory, event);
    return soa::VoidResult::Ok();
}

soa::VoidResult V2xNetworkAdapter::Serialise(soa::SoaEvent const& event, soa::WireFrame& frame) noexcept {
    if (!initialised_) {
        return soa::VoidResult::Err(soa::ErrorCode::kNotInitialized);
    }
    if (event.serviceId != kV2xAdvisoryServiceId || event.eventId != kV2xAdvisoryEventId) {
        return soa::VoidResult::Err(soa::ErrorCode::kInvalidArgument);
    }
    // No payloadLen > frame.data.size() guard: SoaEvent::payloadLen is a
    // std::uint8_t (max 255), which can never exceed WireFrame::data's
    // kMaxWireFrameBytes (1472) - that comparison is unreachable by
    // construction, not merely untested, so it is omitted rather than
    // carried as dead code.

    std::memcpy(frame.data.data(), event.payload, event.payloadLen);
    frame.length = event.payloadLen;
    return soa::VoidResult::Ok();
}

soa::VoidResult V2xNetworkAdapter::Transmit(soa::WireFrame const& frame) noexcept {
    static_cast<void>(frame);
    // No transport binding modelled - see file header.
    return soa::VoidResult::Err(soa::ErrorCode::kNotInitialized);
}

char const* V2xNetworkAdapter::ProtocolName() const noexcept {
    return "V2X-BSM-1609.2-subset";
}

} // namespace v2x
} // namespace norxs
