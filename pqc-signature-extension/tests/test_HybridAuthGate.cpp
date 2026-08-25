/**
 * @copyright (c) 2026 norxs Technology LLC. All rights reserved.
 *
 * End-to-end interop test: runs a REAL classical SPDM handshake to
 * completion using zonal-zero-trust-auth's real, unmodified
 * SpdmProtocolEngine + SoftwareCryptoProvider (vendored, not reimplemented),
 * then layers HybridAuthGate's PQC check on top - including the critical
 * property that a failed PQC check actually revokes the session through the
 * engine's own real Revoke(), observed via its own real GetState().
 *
 * The classical valid-response construction below (MakeValidAuthResponse,
 * kMockPublicKey, kTestClientId, the salt constant) is copied from
 * zonal-zero-trust-auth's own tests/test_zzta_core.cpp - it is how THEY
 * prove their mock crypto provider's signatures are valid; reusing it here
 * is what makes this an executed interop proof rather than a hand-waved one.
 */
#include "zzta/CryptoPlatformInterface.hpp"
#include "zzta/SpdmProtocolEngine.hpp"
#include "zzta/PqcSignaturePlatformInterface.hpp"
#include "norxs/HybridAuthGate.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <array>

using namespace zzta;
using namespace norxs::hybridauth;

// ---------------------------------------------------------------------------
// Copied from zonal-zero-trust-auth/tests/test_zzta_core.cpp - see file
// header comment for why.
// ---------------------------------------------------------------------------
static constexpr ClientId kTestClientId{{
    0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U
}};
static constexpr EccPublicKey kMockPublicKey{{
    0x02U, 0x6BU, 0x17U, 0xD1U, 0xF2U, 0xE1U, 0x2CU, 0x42U,
    0x47U, 0xF8U, 0xBCU, 0xE6U, 0xE5U, 0x63U, 0xA4U, 0x40U,
    0xF2U, 0x77U, 0x03U, 0x7DU, 0x81U, 0x2DU, 0xEBU, 0x33U,
    0xA0U, 0xF4U, 0xA1U, 0x39U, 0x45U, 0xD8U, 0x98U, 0xC2U, 0x96U
}};
static const KnownPeerEntry kTestPeerTable[1] = { { kTestClientId, kMockPublicKey } };

static SpdmAuthResponse MakeValidClassicalAuthResponse(
    SoftwareCryptoProvider& provider,
    const ClientId&         client_id,
    const Nonce&            nonce)
{
    constexpr std::size_t kMsgLen{kNonceLen + kClientIdLen};
    std::array<uint8_t, kMsgLen> msg{};
    std::memcpy(&msg[0], nonce.data(), kNonceLen);
    std::memcpy(&msg[kNonceLen], client_id.data(), kClientIdLen);

    Sha256Digest digest{};
    (void)provider.ComputeSha256(msg.data(), kMsgLen, digest);

    static constexpr std::array<uint8_t, 32U> kSalt{{
        0xA3U,0x7FU,0x92U,0xD1U,0xE4U,0x05U,0xB8U,0xC6U,
        0x2AU,0xF3U,0x19U,0x88U,0x4EU,0xD7U,0x60U,0x3BU,
        0x11U,0xFCU,0x22U,0x59U,0x87U,0xAEU,0xD4U,0xC0U,
        0x53U,0x7AU,0xE9U,0xB2U,0x6EU,0x14U,0xF8U,0x9DU
    }};
    std::array<uint8_t, 64U> combined{};
    std::memcpy(&combined[0],  digest.data(), 32U);
    std::memcpy(&combined[32], kSalt.data(),  32U);
    Sha256Digest r_part{};
    (void)provider.ComputeSha256(combined.data(), 64U, r_part);
    std::memcpy(&combined[0],  kSalt.data(),  32U);
    std::memcpy(&combined[32], digest.data(), 32U);
    Sha256Digest s_part{};
    (void)provider.ComputeSha256(combined.data(), 64U, s_part);

    SpdmAuthResponse resp{};
    resp.client_id = client_id;
    std::memcpy(&resp.signature[0],  r_part.data(), 32U);
    std::memcpy(&resp.signature[32], s_part.data(), 32U);
    return resp;
}

// ---------------------------------------------------------------------------
// TEST-ONLY MOCK PQC signature provider. NOT CRYPTOGRAPHICALLY SECURE.
// Same XOR-toy discipline as pqc-kem-extension's mock - proves
// HybridAuthGate's composition logic, not any real signature scheme.
// ---------------------------------------------------------------------------
namespace {
constexpr std::uint8_t kMockSigMask{0x7EU};

class MockPqcSignatureProvider_TestOnly_NotSecure final : public PqcSignaturePlatformInterface {
public:
    [[nodiscard]] CryptoStatus GenerateKeyPair(PqcSigPublicKey& pub, PqcSigSecretKey& sec) noexcept override {
        for (std::size_t i = 0U; i < kMlDsa65SecretKeyLen; ++i) {
            sec[i] = static_cast<std::uint8_t>((i * 3U) + 7U);
        }
        for (std::size_t i = 0U; i < kMlDsa65PublicKeyLen; ++i) {
            pub[i] = static_cast<std::uint8_t>(sec[i % kMlDsa65SecretKeyLen] ^ kMockSigMask);
        }
        return CryptoStatus::kOk;
    }

    [[nodiscard]] CryptoStatus Sign(const PqcSigSecretKey& sec, const uint8_t* message,
                                     std::size_t message_len, PqcSignature& sig) noexcept override {
        // Indexed modulo kMlDsa65PublicKeyLen, NOT kMlDsa65SecretKeyLen - it
        // must only ever touch sec[0..PublicKeyLen), because that is the
        // only range GenerateKeyPair() actually encoded into pub. Indexing
        // modulo the (larger) secret-key length here would read sec bytes
        // Verify() can never recover from pub alone, and the two would
        // silently disagree for any signature byte past index
        // kMlDsa65PublicKeyLen - exactly the bug this comment replaced.
        for (std::size_t i = 0U; i < kMlDsa65SignatureLen; ++i) {
            std::uint8_t const msgByte = (message_len > 0U) ? message[i % message_len] : 0U;
            sig[i] = static_cast<std::uint8_t>(sec[i % kMlDsa65PublicKeyLen] ^ msgByte);
        }
        return CryptoStatus::kOk;
    }

    [[nodiscard]] CryptoStatus Verify(const PqcSigPublicKey& pub, const uint8_t* message,
                                       std::size_t message_len, const PqcSignature& sig) noexcept override {
        for (std::size_t i = 0U; i < kMlDsa65SignatureLen; ++i) {
            std::uint8_t const msgByte = (message_len > 0U) ? message[i % message_len] : 0U;
            std::uint8_t const expectedSecByte = static_cast<std::uint8_t>(pub[i % kMlDsa65PublicKeyLen] ^ kMockSigMask);
            std::uint8_t const expectedSigByte = static_cast<std::uint8_t>(expectedSecByte ^ msgByte);
            if (sig[i] != expectedSigByte) {
                return CryptoStatus::kVerifyFailed;
            }
        }
        return CryptoStatus::kOk;
    }
};
} // namespace

static void test_hybrid_auth_succeeds_when_both_signatures_valid() {
    SoftwareCryptoProvider classicalProvider(0xC0FFEEU);
    SpdmProtocolEngine engine(classicalProvider, kTestPeerTable, 1U);

    SpdmAuthRequest req{};
    req.client_id = kTestClientId;
    req.version   = {{0x01U, 0x10U, 0x00U, 0x00U}};
    assert(engine.ProcessAuthRequest(req) == SpdmStatus::kOk);

    Nonce const nonce = engine.GetPendingChallenge();
    SpdmAuthResponse const resp = MakeValidClassicalAuthResponse(classicalProvider, kTestClientId, nonce);

    SpdmSessionToken token{};
    assert(engine.ProcessAuthResponse(resp, token) == SpdmStatus::kOk);
    assert(engine.GetState() == SpdmProtocolEngine::State::kAuthenticated);

    // Real classical handshake done. Now the PQC half.
    MockPqcSignatureProvider_TestOnly_NotSecure pqcProvider;
    PqcSigPublicKey pqcPub{};
    PqcSigSecretKey pqcSec{};
    assert(pqcProvider.GenerateKeyPair(pqcPub, pqcSec) == CryptoStatus::kOk);

    std::array<uint8_t, kNonceLen + kClientIdLen> message{};
    std::memcpy(&message[0], nonce.data(), kNonceLen);
    std::memcpy(&message[kNonceLen], kTestClientId.data(), kClientIdLen);

    PqcSignature pqcSig{};
    assert(pqcProvider.Sign(pqcSec, message.data(), message.size(), pqcSig) == CryptoStatus::kOk);

    HybridAuthGate gate(pqcProvider);
    SpdmStatus const hybridResult = gate.ConfirmHybrid(engine, kTestClientId, pqcPub, pqcSig, nonce);

    assert(hybridResult == SpdmStatus::kOk);
    assert(engine.GetState() == SpdmProtocolEngine::State::kAuthenticated); // still authenticated

    std::printf("PASS: test_hybrid_auth_succeeds_when_both_signatures_valid\n");
}

static void test_hybrid_auth_revokes_real_session_on_pqc_failure() {
    SoftwareCryptoProvider classicalProvider(0xC0FFEEU);
    SpdmProtocolEngine engine(classicalProvider, kTestPeerTable, 1U);

    SpdmAuthRequest req{};
    req.client_id = kTestClientId;
    req.version   = {{0x01U, 0x10U, 0x00U, 0x00U}};
    assert(engine.ProcessAuthRequest(req) == SpdmStatus::kOk);

    Nonce const nonce = engine.GetPendingChallenge();
    SpdmAuthResponse const resp = MakeValidClassicalAuthResponse(classicalProvider, kTestClientId, nonce);

    SpdmSessionToken token{};
    // Classical check succeeds - the exact "live session before PQC check"
    // window this module exists to close.
    assert(engine.ProcessAuthResponse(resp, token) == SpdmStatus::kOk);
    assert(engine.GetState() == SpdmProtocolEngine::State::kAuthenticated);

    MockPqcSignatureProvider_TestOnly_NotSecure pqcProvider;
    PqcSigPublicKey pqcPub{};
    PqcSigSecretKey pqcSec{};
    assert(pqcProvider.GenerateKeyPair(pqcPub, pqcSec) == CryptoStatus::kOk);

    PqcSignature garbageSig{}; // wrong signature - never produced by Sign()
    garbageSig.fill(0xFFU);

    HybridAuthGate gate(pqcProvider);
    SpdmStatus const hybridResult = gate.ConfirmHybrid(engine, kTestClientId, pqcPub, garbageSig, nonce);

    assert(hybridResult == SpdmStatus::kSignatureInvalid);
    // The real, unmodified engine's own state - not a flag this module
    // invented - proves the classical-only session did not survive.
    assert(engine.GetState() == SpdmProtocolEngine::State::kRevoked);

    std::printf("PASS: test_hybrid_auth_revokes_real_session_on_pqc_failure "
                "(engine.GetState() == kRevoked, via the engine's own real Revoke())\n");
}

static void test_confirm_hybrid_rejects_when_engine_not_yet_authenticated() {
    SoftwareCryptoProvider classicalProvider(0xC0FFEEU);
    SpdmProtocolEngine engine(classicalProvider, kTestPeerTable, 1U);
    // Deliberately never call ProcessAuthRequest/ProcessAuthResponse.

    MockPqcSignatureProvider_TestOnly_NotSecure pqcProvider;
    PqcSigPublicKey pqcPub{};
    PqcSignature    sig{};
    Nonce           nonce{};

    HybridAuthGate gate(pqcProvider);
    SpdmStatus const result = gate.ConfirmHybrid(engine, kTestClientId, pqcPub, sig, nonce);

    assert(result == SpdmStatus::kInvalidState);
    std::printf("PASS: test_confirm_hybrid_rejects_when_engine_not_yet_authenticated\n");
}

static void test_unavailable_provider_fails_closed() {
    UnavailablePqcSignatureProvider provider;
    PqcSigPublicKey pub{};
    PqcSigSecretKey sec{};
    PqcSignature    sig{};
    uint8_t const   msg[4] = {1U, 2U, 3U, 4U};

    assert(provider.GenerateKeyPair(pub, sec) == CryptoStatus::kNotSupported);
    assert(provider.Sign(sec, msg, 4U, sig) == CryptoStatus::kNotSupported);
    assert(provider.Verify(pub, msg, 4U, sig) == CryptoStatus::kNotSupported);

    std::printf("PASS: test_unavailable_provider_fails_closed\n");
}

int main() {
    test_hybrid_auth_succeeds_when_both_signatures_valid();
    test_hybrid_auth_revokes_real_session_on_pqc_failure();
    test_confirm_hybrid_rejects_when_engine_not_yet_authenticated();
    test_unavailable_provider_fails_closed();
    std::printf("All tests passed.\n");
    return 0;
}
