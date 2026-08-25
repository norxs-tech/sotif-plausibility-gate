/**
 * =====================================================================================
 * @file        PqcKemPlatformInterface.cpp
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * =====================================================================================
 */

#include "zzta/PqcKemPlatformInterface.hpp"

namespace zzta {

CryptoStatus UnavailablePqcKemProvider::GenerateKeyPair(
    PqcPublicKey& /*public_key_out*/,
    PqcSecretKey& /*secret_key_out*/) noexcept
{
    return CryptoStatus::kNotSupported;
}

CryptoStatus UnavailablePqcKemProvider::Encapsulate(
    const PqcPublicKey& /*peer_public_key*/,
    PqcCiphertext&      /*ciphertext_out*/,
    PqcSharedSecret&    /*shared_secret_out*/) noexcept
{
    return CryptoStatus::kNotSupported;
}

CryptoStatus UnavailablePqcKemProvider::Decapsulate(
    const PqcSecretKey&  /*secret_key*/,
    const PqcCiphertext& /*ciphertext*/,
    PqcSharedSecret&     /*shared_secret_out*/) noexcept
{
    return CryptoStatus::kNotSupported;
}

} // namespace zzta
