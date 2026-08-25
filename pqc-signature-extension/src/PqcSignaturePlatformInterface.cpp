/**
 * @copyright (c) 2026 norxs Technology LLC. All rights reserved.
 */

#include "zzta/PqcSignaturePlatformInterface.hpp"

namespace zzta {

CryptoStatus UnavailablePqcSignatureProvider::GenerateKeyPair(
    PqcSigPublicKey& /*public_key_out*/,
    PqcSigSecretKey& /*secret_key_out*/) noexcept
{
    return CryptoStatus::kNotSupported;
}

CryptoStatus UnavailablePqcSignatureProvider::Sign(
    const PqcSigSecretKey& /*secret_key*/,
    const uint8_t*         /*message*/,
    std::size_t             /*message_len*/,
    PqcSignature&           /*signature_out*/) noexcept
{
    return CryptoStatus::kNotSupported;
}

CryptoStatus UnavailablePqcSignatureProvider::Verify(
    const PqcSigPublicKey& /*public_key*/,
    const uint8_t*         /*message*/,
    std::size_t             /*message_len*/,
    const PqcSignature&     /*signature*/) noexcept
{
    return CryptoStatus::kNotSupported;
}

} // namespace zzta
