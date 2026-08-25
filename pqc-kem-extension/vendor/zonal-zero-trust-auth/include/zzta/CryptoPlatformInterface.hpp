/**
 * =====================================================================================
 * @file        CryptoPlatformInterface.hpp
 * @brief       Defines the pure-virtual Platform Abstraction Layer (PAL) for all
 *              cryptographic primitives used by the zonal-zero-trust-authenticator
 *              framework. This interface strictly decouples the business logic of
 *              the SPDM handshake engine and token lifecycle manager from any
 *              concrete hardware or OS dependency, enabling identical source-level
 *              portability across Cortex-A53/QNX, Cortex-A53/Linux, and
 *              Cortex-M7 bare-metal targets. All data structures use statically-
 *              sized std::array to guarantee zero heap allocation in conformance
 *              with AUTOSAR C++14 and ISO 26262 ASIL-D memory-safety requirements.
 *              The SoftwareCryptoProvider concrete class supplies a fully
 *              deterministic, host-native mock for CI pipeline validation and
 *              protocol-level testing without access to a real Hardware Security
 *              Engine (HSE).
 * @project     zonal-zero-trust-authenticator
 * @standards   AUTOSAR C++14, ISO/SAE 21434, UN R155, ISO 26262 ASIL-D
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        This is a reference implementation showcasing norxs's SOA architecture.
 * =====================================================================================
 */

#ifndef ZZTA_CRYPTO_PLATFORM_INTERFACE_HPP
#define ZZTA_CRYPTO_PLATFORM_INTERFACE_HPP

#include <array>
#include <cstdint>
#include <cstddef>

namespace zzta {

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time cryptographic policy constants (AUTOSAR C++14 [A0-1-1])
// All sizes expressed in bytes. Changing these values is a safety-critical
// decision that requires a full TARA re-assessment per ISO/SAE 21434 §15.
// ─────────────────────────────────────────────────────────────────────────────

/** @brief Length of a SHA-256 digest in bytes. */
static constexpr std::size_t kSha256DigestLen{32U};

/** @brief Length of the random challenge nonce in bytes (256-bit). */
static constexpr std::size_t kNonceLen{32U};

/** @brief Length of a P-256 (secp256r1) raw ECC signature (r || s) in bytes. */
static constexpr std::size_t kEccSignatureLen{64U};

/** @brief Length of an HKDF-derived AES-256 session key in bytes. */
static constexpr std::size_t kSessionKeyLen{32U};

/** @brief Length of a client identifier (64-bit opaque handle). */
static constexpr std::size_t kClientIdLen{8U};

/** @brief Length of a compressed P-256 public key (0x02/0x03 prefix + X). */
static constexpr std::size_t kEccPublicKeyLen{33U};

// ─────────────────────────────────────────────────────────────────────────────
// Strongly-typed data transfer objects
// Using std::array guarantees: sizeof is fixed, no iterator invalidation, no
// heap involvement, and AUTOSAR C++14 [A18-1-1] compliance.
// ─────────────────────────────────────────────────────────────────────────────

/** @brief Opaque nonce buffer for challenge-response protocol. */
using Nonce = std::array<uint8_t, kNonceLen>;

/** @brief SHA-256 message digest container. */
using Sha256Digest = std::array<uint8_t, kSha256DigestLen>;

/** @brief Raw ECC-P256 signature (r ∥ s) container. */
using CryptoSignature = std::array<uint8_t, kEccSignatureLen>;

/** @brief AES-256 session key container. */
using SessionKey = std::array<uint8_t, kSessionKeyLen>;

/** @brief Compressed P-256 public key container. */
using EccPublicKey = std::array<uint8_t, kEccPublicKeyLen>;

/** @brief Opaque 64-bit client identifier. */
using ClientId = std::array<uint8_t, kClientIdLen>;

// ─────────────────────────────────────────────────────────────────────────────
// Return-code enumeration
// Errno-style returns replace exceptions (AUTOSAR C++14 [A15-0-1]).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Canonical return codes for all PAL operations.
 *
 * Every PAL function returns one of these values. Callers MUST check the
 * return code — unchecked status is a MISRA C++ Rule 0-1-7 violation.
 */
enum class CryptoStatus : uint8_t
{
    kOk            = 0x00U, ///< Operation completed successfully.
    kInvalidParam  = 0x01U, ///< One or more input parameters are null/invalid.
    kHwFault       = 0x02U, ///< Underlying HSE or RNG reported a hardware fault.
    kVerifyFailed  = 0x03U, ///< Signature or MAC verification mismatch.
    kNotSupported  = 0x04U, ///< Requested primitive not available on this platform.
    kInternalError = 0xFFU  ///< Unclassified internal error (see platform log).
};

// ─────────────────────────────────────────────────────────────────────────────
// CryptoPlatformInterface — Pure virtual PAL contract
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Abstract base class representing the cryptographic Platform Abstraction
 *        Layer (PAL).
 *
 * Concrete implementations must be provided for each target platform:
 *   - SoftwareCryptoProvider  : deterministic software mock for host CI.
 *   - HseCryptoProvider       : NXP HSE firmware v3.x (S32G/S32K3 production).
 *   - TrustZoneCryptoProvider : Arm TrustZone-M (Cortex-M33 production).
 *
 * Design invariants (AUTOSAR C++14 [A10-1-1]):
 *   - No data members in this interface class.
 *   - All methods are pure virtual with [[nodiscard]] where a return value
 *     conveys operational status.
 *   - The destructor is virtual to permit correct polymorphic destruction.
 *
 * ISO/SAE 21434 traceability: CAL_CRYPTO_IF — §10.4.1 Crypto Service Interface.
 */
class CryptoPlatformInterface
{
public:
    // ── Lifecycle ────────────────────────────────────────────────────────────

    CryptoPlatformInterface()                                       = default;
    CryptoPlatformInterface(const CryptoPlatformInterface&)         = delete;
    CryptoPlatformInterface& operator=(const CryptoPlatformInterface&) = delete;
    CryptoPlatformInterface(CryptoPlatformInterface&&)              = delete;
    CryptoPlatformInterface& operator=(CryptoPlatformInterface&&)   = delete;
    virtual ~CryptoPlatformInterface()                              = default;

    // ── Primitive operations ─────────────────────────────────────────────────

    /**
     * @brief Fills @p nonce_out with cryptographically random bytes from the
     *        platform entropy source (TRNG, DRBG-CTR/AES-256, or hardware RNG).
     *
     * On HSE targets this calls the HSE_SRV_ID_GET_RANDOM service. On software
     * mock targets a deterministic LFSR-based PRNG is used; this MUST NOT be
     * used in production.
     *
     * @param[out] nonce_out  Destination buffer; fully overwritten on success.
     * @return CryptoStatus::kOk on success; kHwFault if entropy source fails.
     *
     * @pre  Platform must have been successfully initialised.
     * @post nonce_out contains exactly kNonceLen unpredictable bytes (production)
     *       or deterministic test bytes (SoftwareCryptoProvider).
     */
    [[nodiscard]] virtual CryptoStatus GenerateRandomNonce(
        Nonce& nonce_out) noexcept = 0;

    /**
     * @brief Computes a SHA-256 message digest over the supplied byte buffer.
     *
     * On HSE targets this calls HSE_SRV_ID_HASH with HSE_HASH_ALGO_SHA2_256.
     * The function is side-effect-free with respect to internal state and may
     * be called concurrently from multiple tasks when the underlying platform
     * supports it (single-core MCU: no concurrent calls are generated by the
     * SPDM engine).
     *
     * @param[in]  data        Pointer to the input byte buffer.
     * @param[in]  data_len    Number of bytes to hash. Must be ≥ 1.
     * @param[out] digest_out  Buffer to receive the 32-byte digest.
     * @return CryptoStatus::kOk on success; kInvalidParam if data is nullptr
     *         or data_len is zero; kHwFault on accelerator error.
     */
    [[nodiscard]] virtual CryptoStatus ComputeSha256(
        const uint8_t* data,
        std::size_t    data_len,
        Sha256Digest&  digest_out) noexcept = 0;

    /**
     * @brief Verifies an ECC-P256 (secp256r1/NIST P-256) ECDSA signature.
     *
     * Validates that @p signature was produced by the private key corresponding
     * to @p public_key over the message whose SHA-256 digest is @p digest.
     * Constant-time comparison is mandated; timing side-channel leakage is
     * a CAL-TARA risk item (ISO/SAE 21434 §15 — THREAT-05).
     *
     * @param[in] digest     SHA-256 digest of the signed message.
     * @param[in] signature  Raw (r ∥ s) ECC signature to verify (64 bytes).
     * @param[in] public_key Compressed P-256 public key of the signer (33 bytes).
     * @return CryptoStatus::kOk if the signature is valid;
     *         CryptoStatus::kVerifyFailed if the signature is invalid;
     *         CryptoStatus::kHwFault on accelerator error.
     */
    [[nodiscard]] virtual CryptoStatus VerifyEccSignature(
        const Sha256Digest&  digest,
        const CryptoSignature& signature,
        const EccPublicKey&  public_key) noexcept = 0;

    /**
     * @brief Derives a session key using HKDF-SHA-256 (RFC 5869).
     *
     * Key Derivation Input Material (IKM):
     *   IKM  = session_nonce ∥ client_id
     *   Salt = platform master secret (provisioned in .rodata / OTP fuse)
     *   Info = "zzta-session-v1" (ASCII, no null terminator)
     *
     * The resulting 256-bit output keying material is placed in @p key_out and
     * is suitable for direct use as an AES-256-GCM session key for SOME/IP
     * payload encryption following successful SPDM authentication.
     *
     * @param[in]  session_nonce  The challenge nonce established during handshake.
     * @param[in]  client_id      Authenticated client identifier.
     * @param[out] key_out        Buffer to receive the derived 256-bit key.
     * @return CryptoStatus::kOk on success; kHwFault on derivation failure.
     */
    [[nodiscard]] virtual CryptoStatus DeriveSessionKey(
        const Nonce&    session_nonce,
        const ClientId& client_id,
        SessionKey&     key_out) noexcept = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
// SoftwareCryptoProvider — Deterministic software mock
// For host-native CI and protocol-level testing ONLY. Not for production use.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Deterministic software implementation of CryptoPlatformInterface.
 *
 * This provider implements all PAL primitives using pure C++14 software logic
 * with no OS or hardware dependencies, making it suitable for running the full
 * SPDM protocol suite on a Linux/macOS host during CI. It uses a 32-bit
 * Galois LFSR as its pseudo-random number generator and a portable byte-at-a-
 * time SHA-256 implementation — both are intentionally NOT cryptographically
 * secure and MUST NOT be compiled into any production binary.
 *
 * The compile-time guard ZZTA_PRODUCTION_BUILD is enforced via a static_assert
 * to prevent accidental inclusion in ASIL-D release configurations.
 *
 * ISO/SAE 21434 traceability: CAL_CRYPTO_MOCK — §10.4.1 Test Variant.
 */
class SoftwareCryptoProvider final : public CryptoPlatformInterface
{
public:
    /**
     * @brief Constructs the provider and seeds the internal LFSR.
     * @param seed  Initial seed for the PRNG. Must not be zero.
     *              Default 0xDEAD'BEEFu is deterministic across all test runs.
     */
    explicit SoftwareCryptoProvider(uint32_t seed = 0xDEADBEEFu) noexcept;

    ~SoftwareCryptoProvider() override = default;

    // Deleted copy/move — provider holds mutable PRNG state (AUTOSAR [A12-0-1])
    SoftwareCryptoProvider(const SoftwareCryptoProvider&)            = delete;
    SoftwareCryptoProvider& operator=(const SoftwareCryptoProvider&) = delete;
    SoftwareCryptoProvider(SoftwareCryptoProvider&&)                 = delete;
    SoftwareCryptoProvider& operator=(SoftwareCryptoProvider&&)      = delete;

    [[nodiscard]] CryptoStatus GenerateRandomNonce(
        Nonce& nonce_out) noexcept override;

    [[nodiscard]] CryptoStatus ComputeSha256(
        const uint8_t* data,
        std::size_t    data_len,
        Sha256Digest&  digest_out) noexcept override;

    [[nodiscard]] CryptoStatus VerifyEccSignature(
        const Sha256Digest&    digest,
        const CryptoSignature& signature,
        const EccPublicKey&    public_key) noexcept override;

    [[nodiscard]] CryptoStatus DeriveSessionKey(
        const Nonce&    session_nonce,
        const ClientId& client_id,
        SessionKey&     key_out) noexcept override;

private:
    /**
     * @brief Advances the Galois-LFSR by one step and returns the new state.
     * @return Next 32-bit pseudo-random word. Never returns zero.
     */
    uint32_t LfsrNext() noexcept;

    /**
     * @brief Internal software SHA-256 compression.
     *
     * Implements FIPS PUB 180-4 SHA-256 using no dynamic allocation.
     * Uses a fixed-size local array for the message schedule W[64].
     *
     * @param[in]  data      Input byte buffer.
     * @param[in]  data_len  Length of input in bytes.
     * @param[out] out       32-byte digest output.
     */
    static void Sha256Impl(
        const uint8_t* data,
        std::size_t    data_len,
        Sha256Digest&  out) noexcept;

    uint32_t lfsr_state_; ///< Current LFSR register. Never zero.
};

} // namespace zzta

#endif // ZZTA_CRYPTO_PLATFORM_INTERFACE_HPP
