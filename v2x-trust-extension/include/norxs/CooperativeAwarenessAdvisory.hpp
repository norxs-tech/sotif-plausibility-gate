/**
 * =====================================================================================
 * @file        CooperativeAwarenessAdvisory.hpp
 * @brief       The compact, already-trust-verified payload V2xNetworkAdapter publishes
 *              into the SOA gateway once a V2xSignedBsm has passed V2xTrustVerifier.
 *
 *              Deliberately NOT a SensorFaultEvent and NOT routed through
 *              SafetyArbitrator::IngestFault() / SensorDomain::kV2X. Two independent
 *              reasons, both load-bearing:
 *
 *              1. Domain semantics: SafetyArbitrator's SensorDomain enum models the
 *                 vehicle's OWN onboard sensors — losing a camera or lidar degrades
 *                 the vehicle's own perception, so a fault there correctly drives a
 *                 degraded-capability state. A remote vehicle's V2X beacon going
 *                 silent, or failing certificate verification, is not an onboard
 *                 sensor fault: the ego vehicle's own sensing capability is
 *                 completely unaffected either way. Feeding V2X loss into the same
 *                 fault-arbitration path SafetyArbitrator uses for camera/lidar/radar
 *                 would conflate "I can no longer see" with "a remote party stopped
 *                 talking to me" - two different hazards with different mitigations.
 *
 *              2. What authentication proves: V2xTrustVerifier::VerifyChain() proves
 *                 the message was signed by a certificate chaining to a trusted root
 *                 - i.e. WHO plausibly sent it. It proves nothing about whether the
 *                 claimed position/speed/heading is physically true. That is exactly
 *                 the SOTIF-plausibility question sotif-gate's SotifPlausibilityGate
 *                 already asks of the vehicle's OWN perception stack. A
 *                 CooperativeAwarenessAdvisory is therefore an unconfirmed, external,
 *                 cryptographically-attributed-but-not-physically-confirmed input -
 *                 consumers must apply their own plausibility/fusion logic before
 *                 acting on it, exactly as they would any other unconfirmed
 *                 environment perception. This module does not perform that fusion.
 *
 * @project     v2x-trust-extension
 * @standards   AUTOSAR C++14, SAE J2735, ISO 21448
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * =====================================================================================
 */

#ifndef NORXS_COOPERATIVE_AWARENESS_ADVISORY_HPP
#define NORXS_COOPERATIVE_AWARENESS_ADVISORY_HPP

#include "norxs/V2xCertificate.hpp"
#include <array>
#include <cstdint>

namespace norxs {
namespace v2x {

/** @brief Length of the truncated pseudonym-correlation hash (not an identity). */
static constexpr std::size_t kPseudonymCorrelationHashLen{8U};

/**
 * @brief Decoded, chain-verified content of one remote V2X Basic Safety Message.
 *
 * Field layout mirrors a deliberately minimal subset of SAE J2735's
 * BasicSafetyMessage core data frame - NOT the full ASN.1-encoded message
 * (path history, event flags, vehicle size, brake status, etc. are not
 * modelled; see v2x-trust-extension/README.md).
 */
struct CooperativeAwarenessAdvisory {
    std::int32_t  latitude_1e7;              ///< WGS84 latitude  * 1e7 (SAE J2735 units).
    std::int32_t  longitude_1e7;             ///< WGS84 longitude * 1e7 (SAE J2735 units).
    std::int16_t  speed_cm_s;                ///< Speed, centimetres/second.
    std::int16_t  heading_decidegrees;       ///< Heading, 0.1-degree units, 0 = true north.
    std::uint32_t msg_timestamp_epoch_s;     ///< Sender-claimed message time (Unix epoch seconds) - NOT verified against wall clock beyond the certificate validity window check already performed on the signing chain.

    /**
     * Truncated SHA-256(pseudonym_cert.subject_public_key), NOT a vehicle
     * identity: IEEE 1609.2 pseudonym certificates rotate specifically so a
     * receiver cannot correlate messages across rotations. This hash only
     * lets a consumer group messages that share a still-current pseudonym
     * (e.g. for short-lived track association), and must not be persisted
     * or treated as a stable vehicle identifier.
     */
    std::array<std::uint8_t, kPseudonymCorrelationHashLen> pseudonym_correlation_hash;

    V2xTrustStatus trust_status; ///< Always kTrusted for an advisory that was actually published - carried for completeness/logging.
};

} // namespace v2x
} // namespace norxs

#endif // NORXS_COOPERATIVE_AWARENESS_ADVISORY_HPP
