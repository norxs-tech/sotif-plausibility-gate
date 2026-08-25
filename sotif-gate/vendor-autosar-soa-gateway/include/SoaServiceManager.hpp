/**
 * =====================================================================================
 * @file        SoaServiceManager.hpp
 * @brief       Service lifecycle manager for SOME/IP SD, Pub/Sub, and RPC orchestration.
 *              Maintains a static service registry and dispatches inbound/outbound events
 *              to registered handlers without dynamic allocation.
 * @project     SOA Gateway for Autonomous Safety-Supervisor
 * @standards   AUTOSAR C++14, POSIX, UN R155
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        This is a reference implementation showcasing norxs's SOA architecture.
 * =====================================================================================
 */

#ifndef NORXS_SOA_SOASERVICEMANAGER_HPP
#define NORXS_SOA_SOASERVICEMANAGER_HPP

#include <cstdint>
#include <array>
#include <atomic>
#include <functional>

namespace norxs {
namespace soa {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

static constexpr std::uint8_t  kMaxServices        = 32U;
static constexpr std::uint8_t  kMaxSubscribers      = 16U;
static constexpr std::uint8_t  kMaxPendingEvents    = 64U;
static constexpr std::uint16_t kInvalidServiceId    = 0xFFFFU;

// ---------------------------------------------------------------------------
// Error codes shared across the SOA Gateway
// ---------------------------------------------------------------------------

enum class ErrorCode : std::uint8_t {
    kOk                  = 0U,
    kNullPointer         = 1U,
    kRegistryFull        = 2U,
    kServiceNotFound     = 3U,
    kSubscriberFull      = 4U,
    kQueueFull           = 5U,
    kUnauthorized        = 6U,
    kInvalidArgument     = 7U,
    kE2eViolation        = 8U,
    kIpcBufferFull       = 9U,
    kAlreadyRegistered   = 10U,
    kNotInitialized      = 11U,
    kChecksumMismatch    = 12U,
    kSequenceError       = 13U,
    kTimeout             = 14U,
    kUnknown             = 0xFFU
};

// ---------------------------------------------------------------------------
// Result<T, E> - zero-exception error propagation (AUTOSAR AP compliant)
// ---------------------------------------------------------------------------

template <typename T>
struct Result {
    T         value{};
    ErrorCode error{ ErrorCode::kUnknown };
    bool      ok{ false };

    static Result<T> Ok(T const& v) noexcept {
        Result<T> r;
        r.value = v;
        r.error = ErrorCode::kOk;
        r.ok    = true;
        return r;
    }

    static Result<T> Err(ErrorCode e) noexcept {
        Result<T> r;
        r.error = e;
        r.ok    = false;
        return r;
    }
};

template <>
struct Result<void*> {
    ErrorCode error{ ErrorCode::kUnknown };
    bool      ok{ false };

    static Result<void*> Ok() noexcept {
        Result<void*> r;
        r.error = ErrorCode::kOk;
        r.ok    = true;
        return r;
    }
    static Result<void*> Err(ErrorCode e) noexcept {
        Result<void*> r;
        r.error = e;
        r.ok    = false;
        return r;
    }
};

using VoidResult = Result<void*>;

// ---------------------------------------------------------------------------
// Service state machine
// ---------------------------------------------------------------------------

enum class ServiceState : std::uint8_t {
    kDown        = 0U,
    kRequested   = 1U,
    kAvailable   = 2U,
    kStopping    = 3U
};

// ---------------------------------------------------------------------------
// Service Descriptor - fully stack-allocated
// ---------------------------------------------------------------------------

struct ServiceDescriptor {
    std::uint16_t serviceId    { kInvalidServiceId };
    std::uint16_t instanceId   { 0U };
    std::uint8_t  majorVersion { 0U };
    std::uint8_t  minorVersion { 0U };
    ServiceState  state        { ServiceState::kDown };
    char          name[32]     {};
};

// ---------------------------------------------------------------------------
// Event payload - fixed-size wire frame
// ---------------------------------------------------------------------------

static constexpr std::size_t kMaxPayloadBytes = 256U;

struct SoaEvent {
    std::uint16_t serviceId  { kInvalidServiceId };
    std::uint16_t eventId    { 0U };
    std::uint32_t sessionId  { 0U };
    std::uint8_t  payloadLen { 0U };
    std::uint8_t  payload[kMaxPayloadBytes] {};
};

// ---------------------------------------------------------------------------
// Subscriber callback type (no std::function heap - use plain fn-ptr)
// ---------------------------------------------------------------------------

using EventHandler = void (*)(SoaEvent const&);

struct SubscriberEntry {
    std::uint16_t serviceId { kInvalidServiceId };
    std::uint16_t eventId   { 0U };
    EventHandler  handler   { nullptr };
};

// ---------------------------------------------------------------------------
// SoaServiceManager
// ---------------------------------------------------------------------------

class SoaServiceManager final {
public:
    SoaServiceManager() noexcept;
    ~SoaServiceManager() noexcept = default;

    SoaServiceManager(SoaServiceManager const&)            = delete;
    SoaServiceManager& operator=(SoaServiceManager const&) = delete;
    SoaServiceManager(SoaServiceManager&&)                 = delete;
    SoaServiceManager& operator=(SoaServiceManager&&)      = delete;

    VoidResult Init() noexcept;
    VoidResult RegisterService(ServiceDescriptor const& desc) noexcept;
    VoidResult OfferService(std::uint16_t serviceId, std::uint16_t instanceId) noexcept;
    VoidResult StopService(std::uint16_t serviceId, std::uint16_t instanceId) noexcept;
    VoidResult Subscribe(std::uint16_t serviceId,
                         std::uint16_t eventId,
                         EventHandler  handler) noexcept;
    VoidResult PublishEvent(SoaEvent const& event) noexcept;
    void ProcessEvents() noexcept;
    Result<ServiceDescriptor const*> FindService(std::uint16_t serviceId,
                                                  std::uint16_t instanceId) const noexcept;

private:
    bool FindServiceIndex(std::uint16_t serviceId,
                          std::uint16_t instanceId,
                          std::uint8_t& outIdx) const noexcept;
    bool IsInitialised() const noexcept;

    std::array<ServiceDescriptor, kMaxServices>   registry_{};
    std::atomic<std::uint8_t>                     registryCount_{ 0U };
    std::array<SubscriberEntry, kMaxSubscribers>  subscribers_{};
    std::atomic<std::uint8_t>                     subscriberCount_{ 0U };
    std::array<SoaEvent, kMaxPendingEvents>       eventQueue_{};
    std::atomic<std::uint8_t>                     queueHead_{ 0U };
    std::atomic<std::uint8_t>                     queueTail_{ 0U };
    std::atomic<bool>                             initialised_{ false };
};

} // namespace soa
} // namespace norxs

#endif // NORXS_SOA_SOASERVICEMANAGER_HPP
