/**
 * =====================================================================================
 * @file        NetworkAdapter.hpp
 * @brief       Pure abstract base class (interface) for the Network Adapter layer.
 *              Concrete implementations provide SOME/IP and DDS deserialization into
 *              SoaEvent objects without dynamic memory allocation. Implementations
 *              MUST guarantee noexcept on every virtual method.
 * @project     SOA Gateway for Autonomous Safety-Supervisor
 * @standards   AUTOSAR C++14, POSIX, UN R155
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        This is a reference implementation showcasing norxs's SOA architecture.
 * =====================================================================================
 */

#ifndef NORXS_SOA_NETWORKADAPTER_HPP
#define NORXS_SOA_NETWORKADAPTER_HPP

#include "SoaServiceManager.hpp"
#include <cstdint>
#include <array>

namespace norxs {
namespace soa {

// ---------------------------------------------------------------------------
// Wire-frame constants
// ---------------------------------------------------------------------------

static constexpr std::size_t kSomeIpHeaderBytes = 16U;
static constexpr std::size_t kMaxWireFrameBytes  = 1472U;

// ---------------------------------------------------------------------------
// Raw wire frame buffer - stack-allocated
// ---------------------------------------------------------------------------

struct WireFrame {
    std::array<std::uint8_t, kMaxWireFrameBytes> data{};
    std::uint16_t                                length{ 0U };
};

// ---------------------------------------------------------------------------
// SOME/IP Header fields (big-endian on wire, host-endian after deserialise)
// ---------------------------------------------------------------------------

struct SomeIpHeader {
    std::uint16_t serviceId    { 0U };
    std::uint16_t methodId     { 0U };
    std::uint32_t length       { 0U };
    std::uint16_t clientId     { 0U };
    std::uint16_t sessionId    { 0U };
    std::uint8_t  protocolVer  { 0U };
    std::uint8_t  interfaceVer { 0U };
    std::uint8_t  messageType  { 0U };
    std::uint8_t  returnCode   { 0U };
};

static constexpr std::uint8_t kSomeIpMsgRequest         = 0x00U;
static constexpr std::uint8_t kSomeIpMsgRequestNoReturn  = 0x01U;
static constexpr std::uint8_t kSomeIpMsgNotification     = 0x02U;
static constexpr std::uint8_t kSomeIpMsgResponse         = 0x80U;
static constexpr std::uint8_t kSomeIpMsgError            = 0x81U;

// ---------------------------------------------------------------------------
// Abstract NetworkAdapter interface
// ---------------------------------------------------------------------------

class NetworkAdapter {
public:
    virtual ~NetworkAdapter() noexcept = default;

    virtual VoidResult Init() noexcept = 0;
    virtual VoidResult Receive(WireFrame& frame) noexcept = 0;
    virtual VoidResult Deserialise(WireFrame const& frame,
                                   SoaEvent&        event) noexcept = 0;
    virtual VoidResult Serialise(SoaEvent const& event,
                                  WireFrame&      frame) noexcept = 0;
    virtual VoidResult Transmit(WireFrame const& frame) noexcept = 0;
    virtual char const* ProtocolName() const noexcept = 0;

protected:
    static std::uint32_t Be32ToHost(std::uint32_t be) noexcept {
        return ((be & 0xFF000000U) >> 24U) |
               ((be & 0x00FF0000U) >>  8U) |
               ((be & 0x0000FF00U) <<  8U) |
               ((be & 0x000000FFU) << 24U);
    }

    static std::uint16_t Be16ToHost(std::uint16_t be) noexcept {
        return static_cast<std::uint16_t>(((be & 0xFF00U) >> 8U) |
                                          ((be & 0x00FFU) << 8U));
    }

    static std::uint32_t HostToBe32(std::uint32_t host) noexcept {
        return Be32ToHost(host);
    }

    static std::uint16_t HostToBe16(std::uint16_t host) noexcept {
        return Be16ToHost(host);
    }
};

} // namespace soa
} // namespace norxs

#endif // NORXS_SOA_NETWORKADAPTER_HPP
