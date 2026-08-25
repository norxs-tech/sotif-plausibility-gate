/**
 * =====================================================================================
 * @file        CryptoPlatformInterface.cpp
 * @brief       Provides the concrete SoftwareCryptoProvider implementation of the
 *              CryptoPlatformInterface PAL for host-native CI and protocol-level
 *              simulation. All cryptographic primitives are implemented in portable
 *              C++14 with zero heap allocation, zero OS dependencies, and zero
 *              hardware peripherals: SHA-256 follows FIPS PUB 180-4; the ECC
 *              signature mock uses a constant-time byte-comparison gate keyed on a
 *              compile-time test vector; HKDF key derivation follows RFC 5869
 *              using the software SHA-256 engine. This file MUST NOT be linked
 *              into any production binary — the compile-time guard enforces this
 *              constraint. Production targets must link against HseCryptoProvider
 *              or TrustZoneCryptoProvider instead.
 * @project     zonal-zero-trust-authenticator
 * @standards   AUTOSAR C++14, ISO/SAE 21434, UN R155, ISO 26262 ASIL-D
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        This is a reference implementation showcasing norxs's SOA architecture.
 * =====================================================================================
 */

#include "zzta/CryptoPlatformInterface.hpp"

#include <cstring>   // std::memcpy, std::memset
#include <cstdint>

// ─────────────────────────────────────────────────────────────────────────────
// Production build guard
// ─────────────────────────────────────────────────────────────────────────────
#ifdef ZZTA_PRODUCTION_BUILD
static_assert(false,
    "SoftwareCryptoProvider must NOT be compiled in a production build. "
    "Link HseCryptoProvider or TrustZoneCryptoProvider instead.");
#endif

namespace zzta {

// ─────────────────────────────────────────────────────────────────────────────
// SHA-256 constants (FIPS 180-4 §4.2.2)
// Stored in .rodata — no heap, no stack-local init cost.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

/** @brief First 32 bits of the fractional parts of the cube roots of the first
 *         64 prime numbers (K constants for SHA-256). */
static constexpr std::array<uint32_t, 64U> kSha256K{{
    0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U,
    0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,
    0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U,
    0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,
    0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU,
    0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
    0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,
    0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,
    0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U,
    0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,
    0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U,
    0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
    0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U,
    0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
    0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U,
    0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U
}};

/** @brief SHA-256 initial hash values H0..H7 (FIPS 180-4 §5.3.3). */
static constexpr std::array<uint32_t, 8U> kSha256InitHash{{
    0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
    0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U
}};

/** @brief
 * HKDF application-specific info label (ASCII "zzta-session-v1", no NUL).
 * Placed in .rodata. Used as the `info` parameter for session key derivation.
 */
static constexpr std::array<uint8_t, 15U> kHkdfInfo{{
    'z','z','t','a','-','s','e','s','s','i','o','n','-','v','1'
}};

/**
 * @brief 256-bit HKDF salt / platform master secret placeholder.
 *
 * In production this value is read from OTP fuses or HSE key store slot 0.
 * For the software mock it is a compile-time constant stored in .rodata.
 *
 * THREAT-MODEL NOTE (ISO/SAE 21434 §15): If an attacker can read this value
 * from flash, all session keys derived from it are compromised. Production
 * systems MUST provision this value via a secure OEM manufacturing step and
 * protect it with at least ASIL-B SEooC isolation.
 */
static constexpr std::array<uint8_t, 32U> kMockMasterSalt{{
    0xA3U,0x7FU,0x92U,0xD1U,0xE4U,0x05U,0xB8U,0xC6U,
    0x2AU,0xF3U,0x19U,0x88U,0x4EU,0xD7U,0x60U,0x3BU,
    0x11U,0xFCU,0x22U,0x59U,0x87U,0xAEU,0xD4U,0xC0U,
    0x53U,0x7AU,0xE9U,0xB2U,0x6EU,0x14U,0xF8U,0x9DU
}};

/**
 * @brief Known-good ECC-P256 public key for mock signature verification.
 *
 * Paired with kMockSignatureR and kMockSignatureS below. In a real deployment
 * these keys are provisioned into HSE key store during Tier-1 EOL programming
 * and referenced by key handle, never embedded in .rodata as raw bytes.
 */
static constexpr std::array<uint8_t, 33U> kMockEccPublicKey{{
    0x02U, // Compressed point prefix (even Y)
    0x6BU,0x17U,0xD1U,0xF2U,0xE1U,0x2CU,0x42U,0x47U,
    0xF8U,0xBCU,0xE6U,0xE5U,0x63U,0xA4U,0x40U,0xF2U,
    0x77U,0x03U,0x7DU,0x81U,0x2DU,0xEBU,0x33U,0xA0U,
    0xF4U,0xA1U,0x39U,0x45U,0xD8U,0x98U,0xC2U,0x96U
}};

// ─────────────────────────────────────────────────────────────────────────────
// Portable bit-rotation helpers (AUTOSAR C++14 [A4-7-1] — no UB shift)
// ─────────────────────────────────────────────────────────────────────────────

inline uint32_t Rotr32(uint32_t x, uint32_t n) noexcept
{
    return (x >> n) | (x << (32U - n));
}

inline uint32_t Bswap32(uint32_t x) noexcept
{
    return ((x & 0x000000FFU) << 24U)
         | ((x & 0x0000FF00U) <<  8U)
         | ((x & 0x00FF0000U) >>  8U)
         | ((x & 0xFF000000U) >> 24U);
}

/**
 * @brief Loads a big-endian 32-bit word from an unaligned byte pointer.
 * Avoids strict-aliasing UB (AUTOSAR C++14 [A5-2-4]).
 */
inline uint32_t LoadBe32(const uint8_t* p) noexcept
{
    uint32_t w{};
    std::memcpy(&w, p, sizeof(w));
    return Bswap32(w);
}

/**
 * @brief Stores a 32-bit word in big-endian order to an unaligned pointer.
 */
inline void StoreBe32(uint8_t* p, uint32_t w) noexcept
{
    w = Bswap32(w);
    std::memcpy(p, &w, sizeof(w));
}

} // anonymous namespace

// ─────────────────────────────────────────────────────────────────────────────
// SoftwareCryptoProvider — Constructor
// ─────────────────────────────────────────────────────────────────────────────

SoftwareCryptoProvider::SoftwareCryptoProvider(uint32_t seed) noexcept
    : lfsr_state_{(seed != 0U) ? seed : 0x1U}  // LFSR state must not be zero
{
}

// ─────────────────────────────────────────────────────────────────────────────
// LFSR — Galois-LFSR (32-bit, polynomial 0xB400'0000)
// ─────────────────────────────────────────────────────────────────────────────

uint32_t SoftwareCryptoProvider::LfsrNext() noexcept
{
    // Galois LFSR with primitive polynomial x^32+x^31+x^29+x^1+1.
    // Feedback mask 0xB4000000 produces a maximal-length sequence of 2^32-1.
    uint32_t lsb{lfsr_state_ & 0x1U};
    lfsr_state_ >>= 1U;
    if (lsb != 0U)
    {
        lfsr_state_ ^= 0xB4000000U;
    }
    return lfsr_state_;
}

// ─────────────────────────────────────────────────────────────────────────────
// GenerateRandomNonce
// ─────────────────────────────────────────────────────────────────────────────

CryptoStatus SoftwareCryptoProvider::GenerateRandomNonce(
    Nonce& nonce_out) noexcept
{
    static_assert(kNonceLen % 4U == 0U,
        "kNonceLen must be a multiple of 4 for word-aligned LFSR fill.");

    for (std::size_t i{0U}; i < kNonceLen; i += 4U)
    {
        const uint32_t word{LfsrNext()};
        std::memcpy(&nonce_out[i], &word, sizeof(word));
    }
    return CryptoStatus::kOk;
}

// ─────────────────────────────────────────────────────────────────────────────
// SHA-256 implementation (FIPS PUB 180-4)
// Zero dynamic allocation: message schedule W[64] is stack-local.
// ─────────────────────────────────────────────────────────────────────────────

void SoftwareCryptoProvider::Sha256Impl(
    const uint8_t* data,
    std::size_t    data_len,
    Sha256Digest&  out) noexcept
{
    // Working hash state initialised from FIPS 180-4 initial values.
    std::array<uint32_t, 8U> h{kSha256InitHash};

    // ── Pre-processing: length in bits for the padding field ─────────────────
    const uint64_t bit_len{static_cast<uint64_t>(data_len) * 8U};

    // Total padded length: original + 0x80 byte + zeros + 8-byte big-endian length.
    // Padded to the next multiple of 64 bytes (512-bit block boundary).
    const std::size_t padded_len{((data_len + 9U + 63U) / 64U) * 64U};

    // ── Block processing ─────────────────────────────────────────────────────
    std::array<uint8_t, 64U> block{};

    for (std::size_t block_start{0U}; block_start < padded_len; block_start += 64U)
    {
        // Fill block buffer with message bytes, padding, and length.
        for (std::size_t j{0U}; j < 64U; ++j)
        {
            const std::size_t idx{block_start + j};
            if (idx < data_len)
            {
                block[j] = data[idx];
            }
            else if (idx == data_len)
            {
                block[j] = 0x80U;  // Append 1-bit (FIPS §5.1.1)
            }
            else if (idx >= padded_len - 8U)
            {
                // Big-endian 64-bit message length in the last 8 bytes.
                const std::size_t shift{(7U - (idx - (padded_len - 8U))) * 8U};
                block[j] = static_cast<uint8_t>((bit_len >> shift) & 0xFFU);
            }
            else
            {
                block[j] = 0x00U;
            }
        }

        // ── Prepare message schedule W[0..63] ────────────────────────────────
        std::array<uint32_t, 64U> w{};
        for (std::size_t t{0U}; t < 16U; ++t)
        {
            w[t] = LoadBe32(&block[t * 4U]);
        }
        for (std::size_t t{16U}; t < 64U; ++t)
        {
            const uint32_t s0{Rotr32(w[t-15U], 7U) ^ Rotr32(w[t-15U], 18U) ^ (w[t-15U] >> 3U)};
            const uint32_t s1{Rotr32(w[t- 2U],17U) ^ Rotr32(w[t- 2U], 19U) ^ (w[t- 2U] >> 10U)};
            w[t] = w[t-16U] + s0 + w[t-7U] + s1;
        }

        // ── Compression function ──────────────────────────────────────────────
        uint32_t a{h[0]}, b{h[1]}, c{h[2]}, d{h[3]};
        uint32_t e{h[4]}, f{h[5]}, g{h[6]}, hh{h[7]};

        for (std::size_t t{0U}; t < 64U; ++t)
        {
            const uint32_t S1{Rotr32(e,6U) ^ Rotr32(e,11U) ^ Rotr32(e,25U)};
            const uint32_t ch{(e & f) ^ ((~e) & g)};
            const uint32_t temp1{hh + S1 + ch + kSha256K[t] + w[t]};
            const uint32_t S0{Rotr32(a,2U) ^ Rotr32(a,13U) ^ Rotr32(a,22U)};
            const uint32_t maj{(a & b) ^ (a & c) ^ (b & c)};
            const uint32_t temp2{S0 + maj};

            hh = g;  g = f;  f = e;  e = d + temp1;
            d  = c;  c = b;  b = a;  a = temp1 + temp2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    // ── Produce big-endian output ─────────────────────────────────────────────
    for (std::size_t i{0U}; i < 8U; ++i)
    {
        StoreBe32(&out[i * 4U], h[i]);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ComputeSha256
// ─────────────────────────────────────────────────────────────────────────────

CryptoStatus SoftwareCryptoProvider::ComputeSha256(
    const uint8_t* data,
    std::size_t    data_len,
    Sha256Digest&  digest_out) noexcept
{
    if ((data == nullptr) || (data_len == 0U))
    {
        return CryptoStatus::kInvalidParam;
    }
    Sha256Impl(data, data_len, digest_out);
    return CryptoStatus::kOk;
}

// ─────────────────────────────────────────────────────────────────────────────
// VerifyEccSignature
// Constant-time mock: accepts the signature only if it matches the expected
// test vector paired with kMockEccPublicKey. All other cases return kVerifyFailed.
// ─────────────────────────────────────────────────────────────────────────────

CryptoStatus SoftwareCryptoProvider::VerifyEccSignature(
    const Sha256Digest&    digest,
    const CryptoSignature& signature,
    const EccPublicKey&    public_key) noexcept
{
    // ── Constant-time public key comparison (AUTOSAR C++14 [A26-5-1]) ────────
    // Using volatile accumulator to prevent compiler optimisation of the loop.
    volatile uint8_t key_diff{0U};
    for (std::size_t i{0U}; i < kEccPublicKeyLen; ++i)
    {
        key_diff = static_cast<uint8_t>(key_diff | (public_key[i] ^ kMockEccPublicKey[i]));
    }
    if (key_diff != 0U)
    {
        // Unknown public key — reject unconditionally.
        return CryptoStatus::kVerifyFailed;
    }

    // ── Re-derive expected signature for the given digest ────────────────────
    // Mock derivation: sign(digest, privKey) = SHA-256(digest ∥ kMockMasterSalt)
    // concatenated with SHA-256(kMockMasterSalt ∥ digest) to fill 64 bytes.
    std::array<uint8_t, kSha256DigestLen + kSha256DigestLen> combined_input{};
    std::memcpy(&combined_input[0],               digest.data(),          kSha256DigestLen);
    std::memcpy(&combined_input[kSha256DigestLen], kMockMasterSalt.data(), kSha256DigestLen);

    Sha256Digest r_part{};
    Sha256Impl(combined_input.data(), combined_input.size(), r_part);

    // s_part = SHA-256(salt ∥ digest)
    std::memcpy(&combined_input[0],               kMockMasterSalt.data(), kSha256DigestLen);
    std::memcpy(&combined_input[kSha256DigestLen], digest.data(),          kSha256DigestLen);

    Sha256Digest s_part{};
    Sha256Impl(combined_input.data(), combined_input.size(), s_part);

    // ── Constant-time comparison of expected vs provided signature ────────────
    volatile uint8_t sig_diff{0U};
    for (std::size_t i{0U}; i < kSha256DigestLen; ++i)
    {
        sig_diff = static_cast<uint8_t>(sig_diff | (signature[i]                   ^ r_part[i]));
        sig_diff = static_cast<uint8_t>(sig_diff | (signature[i + kSha256DigestLen] ^ s_part[i]));
    }

    return (sig_diff == 0U) ? CryptoStatus::kOk : CryptoStatus::kVerifyFailed;
}

// ─────────────────────────────────────────────────────────────────────────────
// DeriveSessionKey — HKDF-SHA-256 (RFC 5869)
// ─────────────────────────────────────────────────────────────────────────────

CryptoStatus SoftwareCryptoProvider::DeriveSessionKey(
    const Nonce&    session_nonce,
    const ClientId& client_id,
    SessionKey&     key_out) noexcept
{
    // PRK survives across both HKDF stages and is the only Step 1 result needed
    // by Step 2. All other Step 1 buffers are deliberately confined to the
    // nested scope below so their stack storage is released (and reused by the
    // Step 2 buffers) before expansion begins. This keeps the per-function
    // stack frame within the Cortex-M7 budget (< 1024 B); without the scope the
    // Extract and Expand buffers coexist and overflow it.
    Sha256Digest prk{};
    {
        // ── Step 1: Extract ──────────────────────────────────────────────────
        // PRK = HMAC-SHA-256(salt, IKM)
        // IKM = nonce ∥ client_id
        // For the software mock we approximate HMAC-SHA-256 using the standard
        // HMAC construction with the master salt as the key.

        // HMAC inner block: K_ipad = salt XOR 0x36 (padded to 64 bytes)
        std::array<uint8_t, 64U> ipad_block{};
        std::array<uint8_t, 64U> opad_block{};
        std::memset(ipad_block.data(), 0x36U, 64U);
        std::memset(opad_block.data(), 0x5CU, 64U);
        for (std::size_t i{0U}; i < kSha256DigestLen; ++i)
        {
            ipad_block[i] ^= kMockMasterSalt[i];
            opad_block[i] ^= kMockMasterSalt[i];
        }

        // inner = SHA-256(K_ipad ∥ IKM)
        constexpr std::size_t ikm_len{kNonceLen + kClientIdLen};
        std::array<uint8_t, 64U + ikm_len> inner_input{};
        std::memcpy(&inner_input[0],         ipad_block.data(),   64U);
        // cppcheck-suppress containerOutOfBounds
        // Justification: false positive. inner_input is std::array<uint8_t,
        // 64U + ikm_len> (size 104), so index 64 is in-bounds. cppcheck's
        // ValueFlow evaluates a hypothetical size of 64 ("if size is 64")
        // that cannot occur because ikm_len is a non-zero constexpr.
        std::memcpy(&inner_input[64U],        session_nonce.data(), kNonceLen);
        std::memcpy(&inner_input[64U + kNonceLen], client_id.data(), kClientIdLen);

        Sha256Digest inner_hash{};
        Sha256Impl(inner_input.data(), inner_input.size(), inner_hash);

        // PRK = SHA-256(K_opad ∥ inner_hash)
        std::array<uint8_t, 64U + kSha256DigestLen> outer_input{};
        std::memcpy(&outer_input[0],  opad_block.data(), 64U);
        // cppcheck-suppress containerOutOfBounds
        // Justification: false positive — outer_input has size 64U +
        // kSha256DigestLen (96), so index 64 is in-bounds.
        std::memcpy(&outer_input[64U], inner_hash.data(), kSha256DigestLen);

        Sha256Impl(outer_input.data(), outer_input.size(), prk);
    }

    // ── Step 2: Expand ───────────────────────────────────────────────────────
    // OKM = T(1) where T(1) = HMAC-SHA-256(PRK, "" ∥ info ∥ 0x01)
    // Since kSessionKeyLen == kSha256DigestLen (both 32 bytes), one HMAC block
    // is sufficient — no loop needed.
    // HMAC with PRK as key — T(1) expand: prev(0x00) ∥ info ∥ counter(0x01)
    std::array<uint8_t, 64U> prk_ipad{};
    std::array<uint8_t, 64U> prk_opad{};
    std::memset(prk_ipad.data(), 0x36U, 64U);
    std::memset(prk_opad.data(), 0x5CU, 64U);
    for (std::size_t i{0U}; i < kSha256DigestLen; ++i)
    {
        prk_ipad[i] ^= prk[i];
        prk_opad[i] ^= prk[i];
    }

    // T(1) inner: ipad ∥ info ∥ 0x01
    std::array<uint8_t, 64U + kHkdfInfo.size() + 1U> expand_inner{};
    std::memcpy(&expand_inner[0],    prk_ipad.data(),   64U);
    std::memcpy(&expand_inner[64U],  kHkdfInfo.data(),  kHkdfInfo.size());
    expand_inner[64U + kHkdfInfo.size()] = 0x01U;

    Sha256Digest t1_inner{};
    Sha256Impl(expand_inner.data(), expand_inner.size(), t1_inner);

    // T(1) outer: opad ∥ t1_inner
    std::array<uint8_t, 64U + kSha256DigestLen> expand_outer{};
    std::memcpy(&expand_outer[0],  prk_opad.data(), 64U);
    // cppcheck-suppress containerOutOfBounds
    // Justification: false positive — expand_outer has size 64U +
    // kSha256DigestLen (96), so index 64 is in-bounds.
    std::memcpy(&expand_outer[64U], t1_inner.data(), kSha256DigestLen);

    Sha256Digest okm{};
    Sha256Impl(expand_outer.data(), expand_outer.size(), okm);

    static_assert(kSessionKeyLen == kSha256DigestLen,
        "Session key length must equal SHA-256 output for single-block HKDF expand.");

    std::memcpy(key_out.data(), okm.data(), kSessionKeyLen);
    return CryptoStatus::kOk;
}

} // namespace zzta
