/**
 * =====================================================================================
 * @file        SpdmProtocolEngine.hpp
 * @brief       Declares the SpdmProtocolEngine class, which implements the SPDM
 *              (Security Protocol and Data Model, DMTF DSP0274) Challenge-Response
 *              authentication handshake as a deterministic, zero-allocation finite
 *              state machine for Zonal ECU peer authentication over SOME/IP. The
 *              engine manages four explicit states (kUnauthenticated, kChallengeSent,
 *              kAuthenticated, kRevoked) and delegates all cryptographic operations
 *              exclusively to the injected CryptoPlatformInterface PAL, ensuring that
 *              the protocol logic remains fully portable across Cortex-A53/QNX and
 *              Cortex-M7 bare-metal targets. State transitions are enforced via a
 *              compile-time transition table, preventing any illegal state jump that
 *              would violate the SPDM protocol sequence and satisfying ISO/SAE 21434
 *              Threat ID THREAT-03 (Authentication Bypass).
 * @project     zonal-zero-trust-authenticator
 * @standards   AUTOSAR C++14, ISO/SAE 21434, UN R155, ISO 26262 ASIL-D
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        This is a reference implementation showcasing norxs's SOA architecture.
 * =====================================================================================
 */

#ifndef ZZTA_SPDM_PROTOCOL_ENGINE_HPP
#define ZZTA_SPDM_PROTOCOL_ENGINE_HPP

#include "zzta/CryptoPlatformInterface.hpp"

#include <array>
#include <cstdint>
#include <cstddef>

namespace zzta {

// ─────────────────────────────────────────────────────────────────────────────
// Protocol frame sizes (compile-time, AUTOSAR C++14 [A0-1-1])
// ─────────────────────────────────────────────────────────────────────────────

/** @brief Total byte length of an SPDM GET_CAPABILITIES / INIT request frame. */
static constexpr std::size_t kSpdmAuthRequestLen{kClientIdLen + 4U}; // client_id + version_tag

/** @brief Total byte length of an SPDM CHALLENGE_AUTH response frame. */
static constexpr std::size_t kSpdmAuthResponseLen{kClientIdLen + kEccSignatureLen};

// ─────────────────────────────────────────────────────────────────────────────
// SPDM frame DTOs
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Wire-format SPDM authentication initiation frame.
 *
 * Sent by an ECU peer requesting to authenticate with this Zonal Gateway.
 * The version_tag field carries the 4-byte SPDM version identifier
 * (MSB: major, next: minor, low 2 bytes: reserved/zero).
 */
struct SpdmAuthRequest
{
    ClientId client_id;               ///< Requesting node's unique 64-bit identifier.
    std::array<uint8_t, 4U> version;  ///< SPDM version: {0x01, 0x10, 0x00, 0x00} = v1.1.
};
static_assert(sizeof(SpdmAuthRequest) == kSpdmAuthRequestLen,
    "SpdmAuthRequest layout mismatch — check padding.");

/**
 * @brief Wire-format SPDM CHALLENGE_AUTH response frame.
 *
 * Sent by the requesting ECU in response to a challenge nonce.
 * The signature field contains ECDSA-P256(SHA-256(nonce ∥ client_id)).
 */
struct SpdmAuthResponse
{
    ClientId       client_id; ///< Must match the client_id from the prior SpdmAuthRequest.
    CryptoSignature signature; ///< ECC-P256 signature over SHA-256(nonce ∥ client_id).
};
static_assert(sizeof(SpdmAuthResponse) == kSpdmAuthResponseLen,
    "SpdmAuthResponse layout mismatch — check padding.");

// ─────────────────────────────────────────────────────────────────────────────
// Session result — returned by ProcessAuthResponse on success
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Output token produced on successful SPDM authentication.
 *
 * Passed to TokenLifecycleManager::RegisterToken() immediately following
 * a successful handshake. The session_key is an HKDF-SHA-256 derived
 * AES-256 key suitable for protecting subsequent SOME/IP payload traffic.
 */
struct SpdmSessionToken
{
    ClientId   client_id;    ///< Authenticated node identifier.
    Nonce      session_nonce; ///< The winning nonce from the handshake.
    SessionKey session_key;   ///< HKDF-derived 256-bit session key.
};

// ─────────────────────────────────────────────────────────────────────────────
// Engine status codes
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Return codes specific to SPDM protocol engine operations.
 *
 * Callers MUST handle every code — partial handling is a safety violation
 * under ISO 26262 Part 6 §7.4.2 (robustness of software elements).
 */
enum class SpdmStatus : uint8_t
{
    kOk                  = 0x00U, ///< Operation completed without error.
    kInvalidState        = 0x01U, ///< Function called in an illegal state.
    kVersionMismatch     = 0x02U, ///< Client sent an unsupported SPDM version.
    kClientIdMismatch    = 0x03U, ///< Response client_id does not match the request.
    kSignatureInvalid    = 0x04U, ///< ECC signature verification failed.
    kCryptoError         = 0x05U, ///< PAL returned a hardware or derivation fault.
    kAlreadyAuthenticated = 0x06U, ///< Duplicate AUTH request for an active session.
    kRevoked             = 0x07U, ///< Session has been explicitly revoked; re-auth required.
    kInvalidParam        = 0x08U  ///< Null pointer or zero-length buffer supplied.
};

// ─────────────────────────────────────────────────────────────────────────────
// Known peer public key table — stored in .rodata
// Indexed by a 4-bit zone_id embedded in the high nibble of client_id[0].
// Supports up to kMaxKnownPeers authenticated zone nodes per engine instance.
// ─────────────────────────────────────────────────────────────────────────────

/** @brief Maximum number of distinct peer public keys the engine knows. */
static constexpr std::size_t kMaxKnownPeers{8U};

/**
 * @brief Compile-time table of known-good peer public keys.
 *
 * In a production system this table is generated from an OEM-signed
 * certificate chain and placed in a write-protected flash region during
 * secure boot. For the reference implementation, entry [0] is the
 * SoftwareCryptoProvider test key; entries [1..7] are zero-padded.
 */
struct KnownPeerEntry
{
    ClientId     client_id;  ///< Peer node's unique 64-bit identifier.
    EccPublicKey public_key; ///< Corresponding compressed P-256 public key.
};

// ─────────────────────────────────────────────────────────────────────────────
// SpdmProtocolEngine
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Implements the SPDM DSP0274 v1.1 Challenge-Response authentication
 *        handshake as a zero-allocation four-state finite state machine.
 *
 * ## State Transition Diagram
 * @verbatim
 *
 *   ┌────────────────┐  ProcessAuthRequest()   ┌────────────────┐
 *   │kUnauthenticated│ ───────────────────────► │kChallengeSent  │
 *   └────────────────┘                          └───────┬────────┘
 *          ▲                                            │
 *          │  Revoke()                                  │ ProcessAuthResponse()
 *          │  EvaluateTokenExpiry() (via TLM)           │  [valid signature]
 *          │                                            ▼
 *   ┌──────┴─────────┐   Revoke()             ┌────────────────┐
 *   │   kRevoked     │ ◄───────────────────── │ kAuthenticated │
 *   └────────────────┘                        └────────────────┘
 *          │
 *          │ Reset()
 *          ▼
 *   ┌────────────────┐
 *   │kUnauthenticated│  (session cleared)
 *   └────────────────┘
 *
 * @endverbatim
 *
 * Design invariants:
 *   - A single SpdmProtocolEngine instance manages exactly ONE client session.
 *   - The Zonal Gateway instantiates one engine per authenticated zone node slot.
 *   - PAL operations are invoked through the CryptoPlatformInterface reference;
 *     no crypto code lives inside this class.
 *   - No virtual functions — final class, direct dispatch only.
 *
 * ISO/SAE 21434 traceability: CAL_SPDM_ENGINE — §10.4.2 Authentication Service.
 */
class SpdmProtocolEngine final
{
public:
    // ── State enumeration ─────────────────────────────────────────────────────

    /**
     * @brief Authentication state of this engine instance.
     *
     * The underlying integer values are fixed and must not be changed;
     * they map to SPDM DSP0274 v1.1 MessageType codes for interoperability.
     */
    enum class State : uint8_t
    {
        kUnauthenticated = 0x00U, ///< No challenge in flight. Idle.
        kChallengeSent   = 0x01U, ///< Challenge nonce generated; awaiting response.
        kAuthenticated   = 0x02U, ///< Handshake complete; session key active.
        kRevoked         = 0x03U  ///< Session explicitly invalidated. Re-auth required.
    };

    // ── Construction ─────────────────────────────────────────────────────────

    /**
     * @brief Constructs the engine with a PAL reference and a peer table.
     *
     * @param crypto_pal    Reference to the platform cryptographic provider.
     *                      The referenced object MUST outlive this engine instance.
     * @param peer_table    Pointer to an array of KnownPeerEntry records in .rodata.
     * @param peer_count    Number of valid entries in peer_table. Must be ≤ kMaxKnownPeers.
     */
    explicit SpdmProtocolEngine(
        CryptoPlatformInterface& crypto_pal,
        const KnownPeerEntry*    peer_table,
        std::size_t              peer_count) noexcept;

    ~SpdmProtocolEngine() = default;

    // Copy / move: deleted — engines own session state (AUTOSAR [A12-0-1]).
    SpdmProtocolEngine(const SpdmProtocolEngine&)            = delete;
    SpdmProtocolEngine& operator=(const SpdmProtocolEngine&) = delete;
    // Move constructor is intentionally not deleted — required for
    // std::array<SpdmProtocolEngine, N> aggregate initialisation in SomeIpAdaptor.
    // Move-constructing an engine produces a valid kUnauthenticated instance;
    // the source object is left in a safe (but indeterminate) state and must
    // not be used after the move. AUTOSAR [A12-8-4]: explicitly defaulted.
    SpdmProtocolEngine(SpdmProtocolEngine&&)                 = default;
    SpdmProtocolEngine& operator=(SpdmProtocolEngine&&)      = delete;

    // ── Protocol operations ───────────────────────────────────────────────────

    /**
     * @brief Processes an incoming SPDM authentication request from a peer node.
     *
     * Valid only in state kUnauthenticated. On success, a cryptographically
     * random 256-bit nonce is generated via the PAL and stored internally.
     * The caller must read the nonce via GetPendingChallenge() and transmit
     * it back to the requesting peer over the SOME/IP channel.
     *
     * State transition: kUnauthenticated → kChallengeSent.
     *
     * @param[in] request  Parsed SPDM authentication request frame.
     * @return SpdmStatus::kOk on success.
     *         SpdmStatus::kInvalidState if current state ≠ kUnauthenticated.
     *         SpdmStatus::kVersionMismatch if request.version is not supported.
     *         SpdmStatus::kCryptoError if nonce generation fails.
     */
    [[nodiscard]] SpdmStatus ProcessAuthRequest(
        const SpdmAuthRequest& request) noexcept;

    /**
     * @brief Processes the peer's CHALLENGE_AUTH response frame.
     *
     * Valid only in state kChallengeSent. Performs:
     *   1. Client ID continuity check (must match the original request).
     *   2. Lookup of peer public key from the .rodata peer table.
     *   3. SHA-256(nonce ∥ client_id) computation via PAL.
     *   4. ECC-P256 signature verification via PAL.
     *   5. HKDF-SHA-256 session key derivation via PAL.
     *   6. Population of session_token_out on success.
     *
     * State transition: kChallengeSent → kAuthenticated (success)
     *                   kChallengeSent → kRevoked        (verification failure)
     *
     * @param[in]  response          Parsed SPDM CHALLENGE_AUTH response frame.
     * @param[out] session_token_out Populated with the derived session on success.
     * @return SpdmStatus::kOk on success.
     *         SpdmStatus::kInvalidState if current state ≠ kChallengeSent.
     *         SpdmStatus::kClientIdMismatch if response.client_id ≠ request.client_id.
     *         SpdmStatus::kSignatureInvalid if ECC verification fails.
     *         SpdmStatus::kCryptoError if any PAL operation fails.
     */
    [[nodiscard]] SpdmStatus ProcessAuthResponse(
        const SpdmAuthResponse& response,
        SpdmSessionToken&       session_token_out) noexcept;

    /**
     * @brief Immediately revokes the current session, regardless of state.
     *
     * After this call the engine enters kRevoked. The caller must invoke
     * Reset() before a new handshake can begin. This is the mandatory
     * response to any anomaly detected by the TokenLifecycleManager.
     *
     * State transition: any → kRevoked.
     *
     * @post Internal nonce buffer is zeroed (key material sanitised).
     */
    void Revoke() noexcept;

    /**
     * @brief Resets the engine to kUnauthenticated, clearing all session state.
     *
     * May be called in any state. Intended for use after Revoke() to allow
     * fresh re-authentication following an anomaly event.
     *
     * @post state == kUnauthenticated; all internal buffers zeroed.
     */
    void Reset() noexcept;

    // ── Accessors ─────────────────────────────────────────────────────────────

    /**
     * @brief Returns the current authentication state of this engine.
     * @return Current State value.
     */
    [[nodiscard]] State GetState() const noexcept { return state_; }

    /**
     * @brief Returns a const reference to the pending challenge nonce.
     *
     * Valid only when GetState() == State::kChallengeSent.
     * The nonce must be transmitted to the peer over a secure SOME/IP channel.
     *
     * @return Const reference to the internal nonce buffer.
     * @warning Result is undefined if state ≠ kChallengeSent.
     */
    [[nodiscard]] const Nonce& GetPendingChallenge() const noexcept
    {
        return pending_nonce_;
    }

    /**
     * @brief Returns the currently authenticated client ID.
     *
     * Valid only when GetState() == State::kAuthenticated.
     * @return Const reference to the authenticated client identifier.
     * @warning Result is undefined if state ≠ kAuthenticated.
     */
    [[nodiscard]] const ClientId& GetAuthenticatedClientId() const noexcept
    {
        return authenticated_client_id_;
    }

private:
    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * @brief Looks up the ECC public key for a given client ID in the peer table.
     *
     * @param[in]  client_id  Client identifier to look up.
     * @param[out] key_out    Receives the matching public key on success.
     * @return true if the client_id was found; false otherwise.
     */
    [[nodiscard]] bool FindPeerPublicKey(
        const ClientId& client_id,
        EccPublicKey&   key_out) const noexcept;

    /**
     * @brief Computes the SPDM challenge message digest: SHA-256(nonce ∥ client_id).
     *
     * @param[in]  nonce      The challenge nonce.
     * @param[in]  client_id  The authenticated client identifier.
     * @param[out] digest_out Receives the 32-byte digest.
     * @return CryptoStatus::kOk on success; error code on failure.
     */
    [[nodiscard]] CryptoStatus ComputeChallengeDigest(
        const Nonce&    nonce,
        const ClientId& client_id,
        Sha256Digest&   digest_out) noexcept;

    /**
     * @brief Sanitises all secret material in the instance using a
     *        volatile byte-write loop to prevent compiler elimination.
     *
     * Called by both Revoke() and Reset() to prevent key material from
     * persisting in RAM after session termination (UN R155 §7.2.2).
     */
    void SanitiseSecretMaterial() noexcept;

    // ── Member variables ──────────────────────────────────────────────────────

    CryptoPlatformInterface& crypto_pal_;          ///< Injected PAL reference.
    const KnownPeerEntry*    peer_table_;           ///< .rodata peer table pointer.
    std::size_t              peer_count_;           ///< Number of entries in peer_table_.

    State    state_;                               ///< Current FSM state.
    Nonce    pending_nonce_;                       ///< Challenge nonce (valid in kChallengeSent).
    ClientId pending_client_id_;                   ///< Client ID from in-flight request.
    ClientId authenticated_client_id_;             ///< Client ID confirmed after auth.

    /** @brief Supported SPDM version: {major=1, minor=1, reserved=0, reserved=0}. */
    static constexpr std::array<uint8_t, 4U> kSupportedVersion{{0x01U, 0x10U, 0x00U, 0x00U}};
};

} // namespace zzta

#endif // ZZTA_SPDM_PROTOCOL_ENGINE_HPP
