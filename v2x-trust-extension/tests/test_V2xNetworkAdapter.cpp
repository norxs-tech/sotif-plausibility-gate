/**
 * @copyright (c) 2026 norxs Technology LLC. All rights reserved.
 *
 * Tests V2xNetworkAdapter - the concrete norxs::soa::NetworkAdapter
 * implementation - end to end: hand-packs raw wire bytes exactly as a real
 * DSRC/C-V2X radio would deliver them, feeds them through the real
 * Deserialise(), and checks both the real SoaEvent this module's own logic
 * produces AND (for the reject paths) that no event is fabricated on an
 * untrusted or malformed frame. Reuses the same mock-signature construction
 * proven in test_V2xTrustVerifier.cpp (same disclosed single-key-pair mock
 * limitation applies here - see that file's header comment).
 */
#include "zzta/CryptoPlatformInterface.hpp"
#include "norxs/V2xNetworkAdapter.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <array>

using namespace zzta;
using namespace norxs::v2x;
using namespace norxs::soa;

// ---------------------------------------------------------------------------
// Copied verbatim from vendor/zonal-zero-trust-auth/src/CryptoPlatformInterface.cpp
// (see test_V2xTrustVerifier.cpp's header comment for why this is necessary).
// ---------------------------------------------------------------------------
static constexpr EccPublicKey kMockPublicKey{{
    0x02U, 0x6BU, 0x17U, 0xD1U, 0xF2U, 0xE1U, 0x2CU, 0x42U,
    0x47U, 0xF8U, 0xBCU, 0xE6U, 0xE5U, 0x63U, 0xA4U, 0x40U,
    0xF2U, 0x77U, 0x03U, 0x7DU, 0x81U, 0x2DU, 0xEBU, 0x33U,
    0xA0U, 0xF4U, 0xA1U, 0x39U, 0x45U, 0xD8U, 0x98U, 0xC2U, 0x96U
}};
static constexpr std::array<uint8_t, 32U> kMockMasterSalt{{
    0xA3U,0x7FU,0x92U,0xD1U,0xE4U,0x05U,0xB8U,0xC6U,
    0x2AU,0xF3U,0x19U,0x88U,0x4EU,0xD7U,0x60U,0x3BU,
    0x11U,0xFCU,0x22U,0x59U,0x87U,0xAEU,0xD4U,0xC0U,
    0x53U,0x7AU,0xE9U,0xB2U,0x6EU,0x14U,0xF8U,0x9DU
}};

static CryptoSignature SignDigestMock(SoftwareCryptoProvider& provider, Sha256Digest const& digest) {
    std::array<uint8_t, 64U> combined{};
    std::memcpy(&combined[0],  digest.data(),          32U);
    std::memcpy(&combined[32], kMockMasterSalt.data(), 32U);
    Sha256Digest r_part{};
    (void)provider.ComputeSha256(combined.data(), 64U, r_part);

    std::memcpy(&combined[0],  kMockMasterSalt.data(), 32U);
    std::memcpy(&combined[32], digest.data(),           32U);
    Sha256Digest s_part{};
    (void)provider.ComputeSha256(combined.data(), 64U, s_part);

    CryptoSignature sig{};
    std::memcpy(&sig[0],  r_part.data(), 32U);
    std::memcpy(&sig[32], s_part.data(), 32U);
    return sig;
}

static void PackU16Le(std::uint16_t value, std::uint8_t* out) {
    out[0] = static_cast<std::uint8_t>(value & 0xFFU);
    out[1] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
}

static void PackU32Le(std::uint32_t value, std::uint8_t* out) {
    out[0] = static_cast<std::uint8_t>(value & 0xFFU);
    out[1] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
    out[2] = static_cast<std::uint8_t>((value >> 16U) & 0xFFU);
    out[3] = static_cast<std::uint8_t>((value >> 24U) & 0xFFU);
}

static V2xCertificate MakeValidCert(SoftwareCryptoProvider& provider,
                                     std::uint32_t validFrom,
                                     std::uint32_t validUntil) {
    V2xCertificate cert{};
    cert.subject_public_key  = kMockPublicKey;
    cert.valid_from_epoch_s  = validFrom;
    cert.valid_until_epoch_s = validUntil;

    std::array<uint8_t, 41U> msg{};
    std::memcpy(&msg[0], cert.subject_public_key.data(), 33U);
    PackU32Le(validFrom, &msg[33]);
    PackU32Le(validUntil, &msg[37]);

    Sha256Digest digest{};
    (void)provider.ComputeSha256(msg.data(), msg.size(), digest);
    cert.issuer_signature = SignDigestMock(provider, digest);
    return cert;
}

// Packs a cert into the 105-byte on-wire layout V2xNetworkAdapter expects:
// subject_public_key(33) || valid_from(4 LE) || valid_until(4 LE) || issuer_signature(64).
static void PackCertWire(V2xCertificate const& cert, std::uint8_t* out) {
    std::memcpy(&out[0], cert.subject_public_key.data(), 33U);
    PackU32Le(cert.valid_from_epoch_s, &out[33]);
    PackU32Le(cert.valid_until_epoch_s, &out[37]);
    std::memcpy(&out[41], cert.issuer_signature.data(), 64U);
}

struct BsmCorePayload {
    std::int32_t  latitude_1e7;
    std::int32_t  longitude_1e7;
    std::int16_t  speed_cm_s;
    std::int16_t  heading_decidegrees;
    std::uint32_t msg_timestamp_epoch_s;
};

// Hand-packs a full 468-byte wire frame exactly as V2xNetworkAdapter::
// UnpackWireFrame expects: payload_len(2 LE) || payload(192) ||
// pseudonym_cert(105) || intermediate_cert(105) || bsm_signature(64).
static WireFrame MakeValidWireFrame(SoftwareCryptoProvider& provider,
                                     BsmCorePayload const&   core,
                                     std::uint32_t           certValidFrom,
                                     std::uint32_t           certValidUntil) {
    V2xCertificate const pseudonymCert    = MakeValidCert(provider, certValidFrom, certValidUntil);
    V2xCertificate const intermediateCert = MakeValidCert(provider, certValidFrom, certValidUntil);

    std::array<std::uint8_t, kBsmCorePayloadBytes> payloadBytes{};
    PackU32Le(static_cast<std::uint32_t>(core.latitude_1e7), &payloadBytes[0]);
    PackU32Le(static_cast<std::uint32_t>(core.longitude_1e7), &payloadBytes[4]);
    PackU16Le(static_cast<std::uint16_t>(core.speed_cm_s), &payloadBytes[8]);
    PackU16Le(static_cast<std::uint16_t>(core.heading_decidegrees), &payloadBytes[10]);
    PackU32Le(core.msg_timestamp_epoch_s, &payloadBytes[12]);

    Sha256Digest payloadDigest{};
    (void)provider.ComputeSha256(payloadBytes.data(), payloadBytes.size(), payloadDigest);
    CryptoSignature const bsmSignature = SignDigestMock(provider, payloadDigest);

    WireFrame frame{};
    std::uint8_t* p = frame.data.data();
    PackU16Le(static_cast<std::uint16_t>(kBsmCorePayloadBytes), &p[0]);
    std::memcpy(&p[2], payloadBytes.data(), payloadBytes.size());
    PackCertWire(pseudonymCert, &p[2U + kMaxBsmPayloadBytes]);
    PackCertWire(intermediateCert, &p[2U + kMaxBsmPayloadBytes + 105U]);
    std::memcpy(&p[2U + kMaxBsmPayloadBytes + 210U], bsmSignature.data(), 64U);
    frame.length = static_cast<std::uint16_t>(kV2xWireFrameBytes);
    return frame;
}

static std::uint32_t FixedClock1500() { return 1500U; }
static std::uint32_t FixedClock9999() { return 9999U; }

static void test_deserialise_accepts_valid_frame_and_publishes_advisory() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xNetworkAdapter adapter(crypto, kMockPublicKey, &FixedClock1500);
    assert(adapter.Init().ok);

    BsmCorePayload core{};
    core.latitude_1e7            = 240500000;  // 24.05 deg N (Taipei-ish)
    core.longitude_1e7           = 1214500000; // 121.45 deg E
    core.speed_cm_s              = 1500;       // 15 m/s
    core.heading_decidegrees     = 900;        // 90.0 deg (east)
    core.msg_timestamp_epoch_s   = 1499U;

    WireFrame const frame = MakeValidWireFrame(crypto, core, 1000U, 2000U);

    SoaEvent event{};
    VoidResult const result = adapter.Deserialise(frame, event);

    assert(result.ok);
    assert(adapter.GetLastTrustStatus() == V2xTrustStatus::kTrusted);
    assert(event.serviceId == kV2xAdvisoryServiceId);
    assert(event.eventId == kV2xAdvisoryEventId);
    assert(event.payloadLen == 17U + kPseudonymCorrelationHashLen);

    std::int32_t lat{};
    std::memcpy(&lat, &event.payload[0], 4U);
    assert(lat == core.latitude_1e7);
    assert(event.payload[24] == static_cast<std::uint8_t>(V2xTrustStatus::kTrusted));

    std::printf("PASS: test_deserialise_accepts_valid_frame_and_publishes_advisory\n");
}

static void test_deserialise_rejects_wrong_frame_length() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xNetworkAdapter adapter(crypto, kMockPublicKey, &FixedClock1500);
    assert(adapter.Init().ok);

    WireFrame frame{};
    frame.length = 10U; // nowhere near kV2xWireFrameBytes

    SoaEvent event{};
    VoidResult const result = adapter.Deserialise(frame, event);

    assert(!result.ok);
    assert(result.error == ErrorCode::kInvalidArgument);
    assert(adapter.GetLastTrustStatus() == V2xTrustStatus::kInvalidInput);
    std::printf("PASS: test_deserialise_rejects_wrong_frame_length\n");
}

static void test_deserialise_rejects_untrusted_chain_and_produces_no_event() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xNetworkAdapter adapter(crypto, kMockPublicKey, &FixedClock1500);
    assert(adapter.Init().ok);

    BsmCorePayload core{};
    core.msg_timestamp_epoch_s = 1499U;
    WireFrame frame = MakeValidWireFrame(crypto, core, 1000U, 2000U);
    frame.data[2U + kMaxBsmPayloadBytes + 41U] ^= 0xFFU; // corrupt pseudonym cert's issuer_signature

    SoaEvent event{};
    event.serviceId = 0xABCDU; // sentinel - must NOT be overwritten on rejection
    VoidResult const result = adapter.Deserialise(frame, event);

    assert(!result.ok);
    assert(result.error == ErrorCode::kUnauthorized);
    assert(adapter.GetLastTrustStatus() == V2xTrustStatus::kLeafSignatureInvalid);
    assert(event.serviceId == 0xABCDU); // untouched - fail-safe default, no fabricated event
    std::printf("PASS: test_deserialise_rejects_untrusted_chain_and_produces_no_event\n");
}

static void test_deserialise_rejects_expired_chain_at_later_time() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xNetworkAdapter adapter(crypto, kMockPublicKey, &FixedClock9999); // now=9999, past validity
    assert(adapter.Init().ok);

    BsmCorePayload core{};
    core.msg_timestamp_epoch_s = 1499U;
    WireFrame const frame = MakeValidWireFrame(crypto, core, 1000U, 2000U);

    SoaEvent event{};
    VoidResult const result = adapter.Deserialise(frame, event);

    assert(!result.ok);
    assert(result.error == ErrorCode::kUnauthorized);
    assert(adapter.GetLastTrustStatus() == V2xTrustStatus::kIntermediateExpired);
    std::printf("PASS: test_deserialise_rejects_expired_chain_at_later_time\n");
}

static void test_deserialise_fails_before_init() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xNetworkAdapter adapter(crypto, kMockPublicKey, &FixedClock1500);
    // Deliberately never call Init().

    BsmCorePayload core{};
    WireFrame const frame = MakeValidWireFrame(crypto, core, 1000U, 2000U);
    SoaEvent event{};
    VoidResult const result = adapter.Deserialise(frame, event);

    assert(!result.ok);
    assert(result.error == ErrorCode::kNotInitialized);
    std::printf("PASS: test_deserialise_fails_before_init\n");
}

static void test_deserialise_rejects_oversized_declared_payload_len() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xNetworkAdapter adapter(crypto, kMockPublicKey, &FixedClock1500);
    assert(adapter.Init().ok);

    BsmCorePayload core{};
    WireFrame frame = MakeValidWireFrame(crypto, core, 1000U, 2000U);
    // Correct overall frame length, but the embedded payload_len field
    // itself claims more than kMaxBsmPayloadBytes - malformed at the
    // structural level, must be rejected before any crypto is attempted.
    PackU16Le(300U, &frame.data[0]);

    SoaEvent event{};
    VoidResult const result = adapter.Deserialise(frame, event);

    assert(!result.ok);
    assert(result.error == ErrorCode::kInvalidArgument);
    assert(adapter.GetLastTrustStatus() == V2xTrustStatus::kInvalidInput);
    std::printf("PASS: test_deserialise_rejects_oversized_declared_payload_len\n");
}

static void test_deserialise_rejects_wrong_bsm_core_length() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xNetworkAdapter adapter(crypto, kMockPublicKey, &FixedClock1500);
    assert(adapter.Init().ok);

    BsmCorePayload core{};
    WireFrame frame = MakeValidWireFrame(crypto, core, 1000U, 2000U);
    // Structurally well-formed (payload_len <= kMaxBsmPayloadBytes) but not
    // this module's fixed 16-byte BSM core size - rejected before any
    // chain verification is attempted.
    PackU16Le(20U, &frame.data[0]);

    SoaEvent event{};
    VoidResult const result = adapter.Deserialise(frame, event);

    assert(!result.ok);
    assert(result.error == ErrorCode::kInvalidArgument);
    assert(adapter.GetLastTrustStatus() == V2xTrustStatus::kInvalidInput);
    std::printf("PASS: test_deserialise_rejects_wrong_bsm_core_length\n");
}

static void test_serialise_fails_before_init() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xNetworkAdapter adapter(crypto, kMockPublicKey, &FixedClock1500);
    // Deliberately never call Init().

    SoaEvent event{};
    event.serviceId = kV2xAdvisoryServiceId;
    event.eventId   = kV2xAdvisoryEventId;
    WireFrame frame{};
    VoidResult const result = adapter.Serialise(event, frame);

    assert(!result.ok);
    assert(result.error == ErrorCode::kNotInitialized);
    std::printf("PASS: test_serialise_fails_before_init\n");
}

static void test_serialise_round_trips_advisory_event() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xNetworkAdapter adapter(crypto, kMockPublicKey, &FixedClock1500);
    assert(adapter.Init().ok);

    SoaEvent event{};
    event.serviceId  = kV2xAdvisoryServiceId;
    event.eventId    = kV2xAdvisoryEventId;
    event.payloadLen = 25U;
    for (std::uint8_t i = 0U; i < event.payloadLen; ++i) {
        event.payload[i] = static_cast<std::uint8_t>(i + 1U);
    }

    WireFrame frame{};
    VoidResult const result = adapter.Serialise(event, frame);

    assert(result.ok);
    assert(frame.length == 25U);
    assert(std::memcmp(frame.data.data(), event.payload, 25U) == 0);
    std::printf("PASS: test_serialise_round_trips_advisory_event\n");
}

static void test_serialise_rejects_wrong_service_id() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xNetworkAdapter adapter(crypto, kMockPublicKey, &FixedClock1500);
    assert(adapter.Init().ok);

    SoaEvent event{};
    event.serviceId = 0x0001U; // not kV2xAdvisoryServiceId
    WireFrame frame{};
    VoidResult const result = adapter.Serialise(event, frame);

    assert(!result.ok);
    assert(result.error == ErrorCode::kInvalidArgument);
    std::printf("PASS: test_serialise_rejects_wrong_service_id\n");
}

static void test_receive_and_transmit_not_implemented() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xNetworkAdapter adapter(crypto, kMockPublicKey, &FixedClock1500);
    assert(adapter.Init().ok);

    WireFrame frame{};
    assert(adapter.Receive(frame).error == ErrorCode::kNotInitialized);
    assert(adapter.Transmit(frame).error == ErrorCode::kNotInitialized);
    assert(adapter.ProtocolName() != nullptr);
    std::printf("PASS: test_receive_and_transmit_not_implemented\n");
}

int main() {
    test_deserialise_accepts_valid_frame_and_publishes_advisory();
    test_deserialise_rejects_wrong_frame_length();
    test_deserialise_rejects_untrusted_chain_and_produces_no_event();
    test_deserialise_rejects_expired_chain_at_later_time();
    test_deserialise_fails_before_init();
    test_deserialise_rejects_oversized_declared_payload_len();
    test_deserialise_rejects_wrong_bsm_core_length();
    test_serialise_fails_before_init();
    test_serialise_round_trips_advisory_event();
    test_serialise_rejects_wrong_service_id();
    test_receive_and_transmit_not_implemented();
    std::printf("All tests passed.\n");
    return 0;
}
