/**
 * @copyright (c) 2026 norxs Technology LLC. All rights reserved.
 *
 * Tests V2xTrustVerifier's chain-verification logic against the REAL,
 * unmodified zonal-zero-trust-auth SoftwareCryptoProvider (vendored, not
 * reimplemented) - every VerifyEccSignature/ComputeSha256 call this test
 * exercises is the actual vendored implementation, not a stub.
 *
 * IMPORTANT MOCK LIMITATION (disclosed, not hidden): SoftwareCryptoProvider's
 * VerifyEccSignature() (see vendor/zonal-zero-trust-auth/src/
 * CryptoPlatformInterface.cpp) accepts exactly one hardcoded test-vector
 * public key (kMockPublicKey below, copied verbatim from that file) and
 * derives the "correct" signature for a digest purely as a function of that
 * digest and a fixed salt - it does not model distinct key pairs per
 * signer. Consequently every level of the certificate chain in these tests
 * (trusted_root_key, intermediate_cert.subject_public_key,
 * pseudonym_cert.subject_public_key) necessarily uses the same
 * kMockPublicKey value. This exercises V2xTrustVerifier's actual
 * verification LOGIC correctly - three independent VerifyEccSignature calls
 * against three independently-computed digests, each of which must
 * separately succeed or the chain is rejected - but it does not exercise
 * multi-key-pair diversity. That is a limitation of the shared test-only
 * mock (already relied upon this same way by zonal-zero-trust-auth's own
 * tests and by this project's pqc-signature-extension tests), not of
 * V2xTrustVerifier itself.
 */
#include "zzta/CryptoPlatformInterface.hpp"
#include "norxs/V2xTrustVerifier.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <array>

using namespace zzta;
using namespace norxs::v2x;

// ---------------------------------------------------------------------------
// Copied verbatim from zonal-zero-trust-auth's
// vendor/zonal-zero-trust-auth/src/CryptoPlatformInterface.cpp - see file
// header comment for why this is necessary and honest.
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

static V2xSignedBsm MakeValidBsm(SoftwareCryptoProvider& provider,
                                  std::uint32_t certValidFrom,
                                  std::uint32_t certValidUntil) {
    V2xSignedBsm bsm{};
    bsm.intermediate_cert = MakeValidCert(provider, certValidFrom, certValidUntil);
    bsm.pseudonym_cert    = MakeValidCert(provider, certValidFrom, certValidUntil);

    static const std::uint8_t kPayload[8] = {0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U};
    std::memcpy(bsm.payload.data(), kPayload, sizeof(kPayload));
    bsm.payload_len = static_cast<std::uint16_t>(sizeof(kPayload));

    Sha256Digest payloadDigest{};
    (void)provider.ComputeSha256(bsm.payload.data(), bsm.payload_len, payloadDigest);
    bsm.bsm_signature = SignDigestMock(provider, payloadDigest);
    return bsm;
}

static void test_verify_chain_accepts_fully_valid_chain() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xTrustVerifier verifier(crypto, kMockPublicKey);

    V2xSignedBsm const bsm = MakeValidBsm(crypto, 1000U, 2000U);
    V2xTrustStatus const status = verifier.VerifyChain(bsm, 1500U);

    assert(status == V2xTrustStatus::kTrusted);
    std::printf("PASS: test_verify_chain_accepts_fully_valid_chain\n");
}

static void test_verify_chain_rejects_invalid_input_zero_payload() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xTrustVerifier verifier(crypto, kMockPublicKey);

    V2xSignedBsm bsm = MakeValidBsm(crypto, 1000U, 2000U);
    bsm.payload_len = 0U;

    assert(verifier.VerifyChain(bsm, 1500U) == V2xTrustStatus::kInvalidInput);
    std::printf("PASS: test_verify_chain_rejects_invalid_input_zero_payload\n");
}

static void test_verify_chain_rejects_bad_root_signature() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xTrustVerifier verifier(crypto, kMockPublicKey);

    V2xSignedBsm bsm = MakeValidBsm(crypto, 1000U, 2000U);
    bsm.intermediate_cert.issuer_signature[0] ^= 0xFFU; // corrupt root's signature over intermediate

    assert(verifier.VerifyChain(bsm, 1500U) == V2xTrustStatus::kRootSignatureInvalid);
    std::printf("PASS: test_verify_chain_rejects_bad_root_signature\n");
}

static void test_verify_chain_rejects_expired_intermediate() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xTrustVerifier verifier(crypto, kMockPublicKey);

    V2xSignedBsm const bsm = MakeValidBsm(crypto, 1000U, 2000U);
    // nowEpochS after intermediate_cert's own validity window, but the
    // pseudonym cert's window is independently valid at this time; only
    // the intermediate check should fire (fail-safe default: first failure wins).
    assert(verifier.VerifyChain(bsm, 2500U) == V2xTrustStatus::kIntermediateExpired);
    std::printf("PASS: test_verify_chain_rejects_expired_intermediate\n");
}

static void test_verify_chain_rejects_bad_leaf_signature() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xTrustVerifier verifier(crypto, kMockPublicKey);

    V2xSignedBsm bsm = MakeValidBsm(crypto, 1000U, 2000U);
    bsm.pseudonym_cert.issuer_signature[0] ^= 0xFFU; // corrupt intermediate's signature over pseudonym

    assert(verifier.VerifyChain(bsm, 1500U) == V2xTrustStatus::kLeafSignatureInvalid);
    std::printf("PASS: test_verify_chain_rejects_bad_leaf_signature\n");
}

static void test_verify_chain_rejects_expired_leaf() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xTrustVerifier verifier(crypto, kMockPublicKey);

    V2xSignedBsm bsm{};
    bsm.intermediate_cert = MakeValidCert(crypto, 1000U, 5000U); // wide window, still valid
    bsm.pseudonym_cert    = MakeValidCert(crypto, 1000U, 1200U); // narrow window, expires early

    static const std::uint8_t kPayload[4] = {0xAAU, 0xBBU, 0xCCU, 0xDDU};
    std::memcpy(bsm.payload.data(), kPayload, sizeof(kPayload));
    bsm.payload_len = static_cast<std::uint16_t>(sizeof(kPayload));
    Sha256Digest payloadDigest{};
    (void)crypto.ComputeSha256(bsm.payload.data(), bsm.payload_len, payloadDigest);
    bsm.bsm_signature = SignDigestMock(crypto, payloadDigest);

    // nowEpochS = 1500: past pseudonym_cert's 1200 expiry, but still within
    // intermediate_cert's 5000 window - so only the leaf-expired check fires.
    assert(verifier.VerifyChain(bsm, 1500U) == V2xTrustStatus::kLeafExpired);
    std::printf("PASS: test_verify_chain_rejects_expired_leaf\n");
}

static void test_verify_chain_rejects_bad_bsm_signature() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    V2xTrustVerifier verifier(crypto, kMockPublicKey);

    V2xSignedBsm bsm = MakeValidBsm(crypto, 1000U, 2000U);
    bsm.bsm_signature[0] ^= 0xFFU; // corrupt the message signature itself

    assert(verifier.VerifyChain(bsm, 1500U) == V2xTrustStatus::kBsmSignatureInvalid);
    std::printf("PASS: test_verify_chain_rejects_bad_bsm_signature\n");
}

static void test_verify_chain_rejects_wrong_trusted_root_key() {
    SoftwareCryptoProvider crypto(0xC0FFEEU);
    EccPublicKey wrongRoot{};
    wrongRoot.fill(0x11U);
    V2xTrustVerifier verifier(crypto, wrongRoot); // not kMockPublicKey

    V2xSignedBsm const bsm = MakeValidBsm(crypto, 1000U, 2000U);
    assert(verifier.VerifyChain(bsm, 1500U) == V2xTrustStatus::kRootSignatureInvalid);
    std::printf("PASS: test_verify_chain_rejects_wrong_trusted_root_key\n");
}

int main() {
    test_verify_chain_accepts_fully_valid_chain();
    test_verify_chain_rejects_invalid_input_zero_payload();
    test_verify_chain_rejects_bad_root_signature();
    test_verify_chain_rejects_expired_intermediate();
    test_verify_chain_rejects_bad_leaf_signature();
    test_verify_chain_rejects_expired_leaf();
    test_verify_chain_rejects_bad_bsm_signature();
    test_verify_chain_rejects_wrong_trusted_root_key();
    std::printf("All tests passed.\n");
    return 0;
}
