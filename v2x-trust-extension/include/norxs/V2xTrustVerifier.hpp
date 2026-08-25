/**
 * =====================================================================================
 * @file        V2xTrustVerifier.hpp
 * @brief       Verifies a received V2xSignedBsm's full certificate chain (root ->
 *              intermediate -> pseudonym -> message signature) using
 *              zonal-zero-trust-auth's real CryptoPlatformInterface for every
 *              cryptographic operation. No signature primitive implemented here.
 *
 *              Deliberately separate from SafetyArbitrator's SensorFaultEvent /
 *              SensorDomain::kV2X path - see CooperativeAwarenessAdvisory.hpp for why
 *              a trusted V2X message is NOT the same kind of input as an onboard
 *              sensor's health, and must not be fed into
 *              SafetyArbitrator::IngestFault().
 *
 * @project     v2x-trust-extension
 * @standards   AUTOSAR C++14, IEEE 1609.2, ISO/SAE 21434
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * =====================================================================================
 */

#ifndef NORXS_V2X_TRUST_VERIFIER_HPP
#define NORXS_V2X_TRUST_VERIFIER_HPP

#include "norxs/V2xCertificate.hpp"

namespace norxs {
namespace v2x {

class V2xTrustVerifier final
{
public:
    /**
     * @param crypto_pal   Reference to the (real) CryptoPlatformInterface
     *                     used for every VerifyEccSignature/ComputeSha256
     *                     call this class makes. Must outlive this object.
     * @param trusted_root_key  The root CA public key this verifier trusts
     *                          a priori (provisioned out of band - not
     *                          this module's concern how).
     */
    explicit V2xTrustVerifier(CryptoPlatformInterface& crypto_pal,
                               const EccPublicKey&      trusted_root_key) noexcept;

    ~V2xTrustVerifier() noexcept = default;

    V2xTrustVerifier(const V2xTrustVerifier&)            = delete;
    V2xTrustVerifier& operator=(const V2xTrustVerifier&) = delete;
    V2xTrustVerifier(V2xTrustVerifier&&)                 = delete;
    V2xTrustVerifier& operator=(V2xTrustVerifier&&)      = delete;

    /**
     * @brief Verify a full chain: root -> intermediate_cert -> pseudonym_cert
     *        -> bsm_signature over payload. Fail-safe default: any single
     *        failed step returns immediately with that step's specific
     *        reason; nothing downstream of a failed step is evaluated (an
     *        expired intermediate cert's signature over the leaf is never
     *        even checked, for example - there is no partial-trust result).
     *
     * @param bsm       The received message and its attached chain.
     * @param nowEpochS Current time (Unix epoch seconds) for validity checks -
     *                  supplied by the caller, not read internally, so this
     *                  function stays a pure, unit-testable function of its
     *                  inputs (same rationale as sotif-gate's Evaluate()).
     */
    [[nodiscard]] V2xTrustStatus VerifyChain(
        const V2xSignedBsm& bsm,
        std::uint32_t       nowEpochS) noexcept;

private:
    [[nodiscard]] bool VerifyCertSignature(
        const V2xCertificate& cert,
        const EccPublicKey&   issuerPublicKey) noexcept;

    [[nodiscard]] static bool WithinValidity(
        const V2xCertificate& cert,
        std::uint32_t         nowEpochS) noexcept;

    CryptoPlatformInterface& crypto_pal_;
    EccPublicKey             trusted_root_key_;
};

} // namespace v2x
} // namespace norxs

#endif // NORXS_V2X_TRUST_VERIFIER_HPP
