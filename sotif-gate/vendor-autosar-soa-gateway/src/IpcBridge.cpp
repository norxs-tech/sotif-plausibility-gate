/**
 * =====================================================================================
 * @file        IpcBridge.cpp
 * @brief       IPC Bridge implementation: SoaEvent -> IpcSlot translation,
 *              AUTOSAR E2E Profile 5 CRC injection, and lock-free SPSC ring-buffer
 *              write into cross-core shared SRAM with explicit ARM memory barriers.
 * @project     SOA Gateway for Autonomous Safety-Supervisor
 * @standards   AUTOSAR C++14, POSIX, UN R155, AUTOSAR E2E Profile 5
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        This is a reference implementation showcasing norxs's SOA architecture.
 * =====================================================================================
 */

#include "IpcBridge.hpp"
#include <cstring>
#include <utility>

namespace norxs {
namespace soa {

// ---------------------------------------------------------------------------
// CRC-16/ARC lookup table (polynomial 0x8005, reflected in/out)
// Generated entirely at compile time via constexpr – resides in .rodata
// ---------------------------------------------------------------------------

namespace {

constexpr std::uint16_t GenerateCrcEntry(std::uint8_t idx) noexcept {
    std::uint16_t crc = static_cast<std::uint16_t>(idx);
    for (std::uint8_t bit = 0U; bit < 8U; ++bit) {
        if ((crc & 0x0001U) != 0U) {
            crc = static_cast<std::uint16_t>((crc >> 1U) ^ 0x8005U);
        } else {
            crc = static_cast<std::uint16_t>(crc >> 1U);
        }
    }
    return crc;
}

template <std::size_t... I>
constexpr std::array<std::uint16_t, 256U>
MakeCrcTable(std::index_sequence<I...>) noexcept {
    return {{ GenerateCrcEntry(static_cast<std::uint8_t>(I))... }};
}

} // anonymous namespace

// Static member definition
std::array<std::uint16_t, 256U> const IpcBridge::kCrcTable_ =
    MakeCrcTable(std::make_index_sequence<256U>{});

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

IpcBridge::IpcBridge(IpcRingBuffer* sramBase) noexcept
    : ring_(sramBase) {}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

VoidResult IpcBridge::Init() noexcept {
    if (ring_ == nullptr) {
        return VoidResult::Err(ErrorCode::kNullPointer);
    }
    if (initialised_) {
        return VoidResult::Err(ErrorCode::kAlreadyRegistered);
    }

    // Zero the entire ring buffer in shared SRAM before advertising it.
    static_assert(sizeof(IpcRingBuffer) <= 8192U,
                  "IpcRingBuffer exceeds expected SRAM budget");

    std::memset(ring_, 0, sizeof(IpcRingBuffer));

    ring_->head = 0U;
    ring_->tail = 0U;
    ring_->pad  = 0U;

    // Full seq_cst fence: all prior writes must be visible to M7 before magic.
    std::atomic_thread_fence(std::memory_order_seq_cst);

    ring_->magic = kIpcMagic;

    // Second barrier: M7 cannot observe slots before seeing the magic marker.
    std::atomic_thread_fence(std::memory_order_seq_cst);

    seqCounter_ = 0U;
    initialised_ = true;
    return VoidResult::Ok();
}

// ---------------------------------------------------------------------------
// ComputeE2eCrc  (CRC-16/ARC, table-driven, O(n))
// ---------------------------------------------------------------------------

std::uint16_t IpcBridge::ComputeE2eCrc(std::uint8_t const* data,
                                         std::uint16_t       length) noexcept {
    if (data == nullptr) {
        return 0U;
    }

    std::uint16_t crc = 0x0000U; // Initial value for CRC-16/ARC

    for (std::uint16_t i = 0U; i < length; ++i) {
        std::uint8_t const tableIdx =
            static_cast<std::uint8_t>(crc ^ static_cast<std::uint16_t>(data[i]));
        crc = static_cast<std::uint16_t>((crc >> 8U) ^ kCrcTable_[tableIdx]);
    }

    return crc; // No final XOR for CRC-16/ARC
}

// ---------------------------------------------------------------------------
// VerifyE2e  (used by M7 consumer or unit tests)
// ---------------------------------------------------------------------------

VoidResult IpcBridge::VerifyE2e(IpcSlot const& slot,
                                  std::uint8_t   expectedCounter) noexcept {
    // Re-compute CRC over everything after the crc field itself.
    // Protected region: bytes [2 .. sizeof(IpcSlot)-1]  (crc field excluded)
    std::uint8_t const* const base =
        reinterpret_cast<std::uint8_t const*>(&slot);

    static constexpr std::uint16_t kCrcOffset = 2U; // sizeof(crc field)
    static constexpr std::uint16_t kProtectedLen =
        static_cast<std::uint16_t>(sizeof(IpcSlot) - kCrcOffset);

    std::uint16_t const computed = ComputeE2eCrc(base + kCrcOffset, kProtectedLen);

    if (computed != slot.e2eHeader.crc) {
        return VoidResult::Err(ErrorCode::kChecksumMismatch);
    }

    if (slot.e2eHeader.counter != expectedCounter) {
        return VoidResult::Err(ErrorCode::kSequenceError);
    }

    return VoidResult::Ok();
}

// ---------------------------------------------------------------------------
// ApplyE2eHeader  (private – stamps header fields and CRC into slot)
// ---------------------------------------------------------------------------

void IpcBridge::ApplyE2eHeader(IpcSlot& slot) noexcept {
    slot.e2eHeader.counter  = seqCounter_;
    slot.e2eHeader.dataId   = 0x01U;  // Application-defined; configure per slot type
    slot.e2eHeader.length   = static_cast<std::uint16_t>(sizeof(IpcSlot));
    slot.e2eHeader.reserved = 0x0000U;
    slot.e2eHeader.crc      = 0x0000U; // Zero CRC field before computing

    // Protect: counter field onward (skip crc field at offset 0)
    std::uint8_t const* const base =
        reinterpret_cast<std::uint8_t const*>(&slot);

    static constexpr std::uint16_t kCrcOffset    = 2U;
    static constexpr std::uint16_t kProtectedLen =
        static_cast<std::uint16_t>(sizeof(IpcSlot) - kCrcOffset);

    slot.e2eHeader.crc = ComputeE2eCrc(base + kCrcOffset, kProtectedLen);

    // Advance and wrap sequence counter
    seqCounter_ = static_cast<std::uint8_t>(seqCounter_ + 1U);
}

// ---------------------------------------------------------------------------
// Send  (lock-free SPSC enqueue with E2E injection)
// ---------------------------------------------------------------------------

VoidResult IpcBridge::Send(SoaEvent const& event) noexcept {
    if (!initialised_) {
        return VoidResult::Err(ErrorCode::kNotInitialized);
    }
    if (ring_ == nullptr) {
        return VoidResult::Err(ErrorCode::kNullPointer);
    }
    if (event.payloadLen > static_cast<std::uint8_t>(kIpcPayloadBytes)) {
        return VoidResult::Err(ErrorCode::kInvalidArgument);
    }

    // Load head (producer-local) and tail (consumer-updated).
    // Design note: ring_->head and ring_->tail are plain uint32_t fields in a
    // struct that lives in cache-inhibited shared SRAM (mapped by the linker
    // script). std::atomic<> cannot be used here because (a) the struct layout
    // must be ABI-compatible with the M7 C consumer and (b) placement-new into
    // a hardware-mapped region is not portable. The volatile cast + explicit
    // std::atomic_thread_fence() pair provides the necessary ordering guarantee
    // on Cortex-A53: the acquire fence maps to DMB ISHLD, preventing the
    // compiler and CPU from reordering the tail read before stale cached data.
    std::uint32_t const head =
        *reinterpret_cast<volatile std::uint32_t const*>(&ring_->head);  // NOLINT

    // Acquire fence: ensure M7's tail update is visible before we check fullness.
    std::atomic_thread_fence(std::memory_order_acquire);

    std::uint32_t const tail =
        *reinterpret_cast<volatile std::uint32_t const*>(&ring_->tail);  // NOLINT

    std::uint32_t const nextHead = (head + 1U) & kIpcRingSlotMask;

    if (nextHead == tail) {
        return VoidResult::Err(ErrorCode::kIpcBufferFull);
    }

    // Populate the IPC slot from the SoaEvent
    IpcSlot& slot     = ring_->slots[head];
    slot.serviceId    = event.serviceId;
    slot.eventId      = event.eventId;
    slot.sessionId    = event.sessionId;
    slot.payloadLen   = event.payloadLen;
    slot.reserved[0]  = 0U;
    slot.reserved[1]  = 0U;
    slot.reserved[2]  = 0U;

    std::memset(slot.payload, 0, kIpcPayloadBytes);
    if (event.payloadLen > 0U) {
        std::memcpy(slot.payload, event.payload, event.payloadLen);
    }

    // Stamp E2E header (includes CRC computation over the completed slot)
    ApplyE2eHeader(slot);

    // seq_cst fence: all slot writes must complete and be visible to M7
    // before the head pointer advances. Equivalent to DMB SY on Cortex-A53.
    std::atomic_thread_fence(std::memory_order_seq_cst);

    // Advance producer head - M7 consumer will observe the new slot.
    *reinterpret_cast<volatile std::uint32_t*>(&ring_->head) = nextHead;

    // Final release fence so the head store is not reordered past future writes.
    std::atomic_thread_fence(std::memory_order_release);

    return VoidResult::Ok();
}

} // namespace soa
} // namespace norxs
