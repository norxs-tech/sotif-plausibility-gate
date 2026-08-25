/**
 * =====================================================================================
 * @file        IpcBridge.hpp
 * @brief       Cross-core IPC bridge between the Cortex-A53 SOA Gateway and the
 *              Cortex-M7 AUTOSAR Safety Supervisor. Translates C++ SoaEvent objects
 *              into C-compatible fixed-size structs, injects AUTOSAR E2E Profile 5
 *              protection (CRC-16 + sequence counter), and writes the result into a
 *              lock-free SPSC ring buffer residing in shared SRAM.
 *
 *              Memory model:
 *                - Ring buffer headers use volatile uint32_t with explicit
 *                  acquire/release fences to guarantee visibility across cores.
 *                - std::atomic_thread_fence(seq_cst) is inserted before each
 *                  head-pointer advance (equivalent to DMB SY on ARM Cortex-A53).
 * @project     SOA Gateway for Autonomous Safety-Supervisor
 * @standards   AUTOSAR C++14, POSIX, UN R155, AUTOSAR E2E Profile 5
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        This is a reference implementation showcasing norxs's SOA architecture.
 * =====================================================================================
 */

#ifndef NORXS_SOA_IPCBRIDGE_HPP
#define NORXS_SOA_IPCBRIDGE_HPP

#include "SoaServiceManager.hpp"
#include <cstdint>
#include <array>
#include <atomic>

namespace norxs {
namespace soa {

// ---------------------------------------------------------------------------
// Shared SRAM ring-buffer geometry
// ---------------------------------------------------------------------------

static constexpr std::uint32_t kIpcRingSlots    = 32U;   ///< Must be power of 2
static constexpr std::uint32_t kIpcPayloadBytes  = 128U;  ///< Fixed C-struct payload
static constexpr std::uint32_t kIpcRingSlotMask  = kIpcRingSlots - 1U;

// ---------------------------------------------------------------------------
// E2E Profile 5 header (AUTOSAR SWS_E2ELibrary §7.6)
// ---------------------------------------------------------------------------

struct E2eProfile5Header {
    std::uint16_t crc;       ///< CRC-16 over header + payload
    std::uint8_t  counter;   ///< Sequence counter [0..255], wraps
    std::uint8_t  dataId;    ///< Unique data element identifier
    std::uint16_t length;    ///< Total length of protected data in bytes
    std::uint16_t reserved;  ///< Shall be 0x0000
};

static_assert(sizeof(E2eProfile5Header) == 8U,
              "E2E Profile 5 header must be exactly 8 bytes");

// ---------------------------------------------------------------------------
// IPC C-struct slot written to shared SRAM
// ---------------------------------------------------------------------------

struct IpcSlot {
    E2eProfile5Header e2eHeader;
    std::uint16_t     serviceId;
    std::uint16_t     eventId;
    std::uint32_t     sessionId;
    std::uint8_t      payloadLen;
    std::uint8_t      reserved[3];
    std::uint8_t      payload[kIpcPayloadBytes];
};

static_assert(sizeof(IpcSlot) == (8U + 4U + 4U + 4U + kIpcPayloadBytes),
              "IpcSlot layout mismatch");

// ---------------------------------------------------------------------------
// Shared SRAM ring buffer control block
// Placed at a fixed linker-script address; both cores map this region.
// ---------------------------------------------------------------------------

struct IpcRingBuffer {
    volatile std::uint32_t head;              ///< Written by A53 (producer)
    volatile std::uint32_t tail;              ///< Written by M7 (consumer)
    std::uint32_t          magic;             ///< 0xA53CA53C - presence marker
    std::uint32_t          pad;               ///< Align slots to 8-byte boundary
    IpcSlot                slots[kIpcRingSlots];
};

static constexpr std::uint32_t kIpcMagic = 0xA53CA53CU;

// ---------------------------------------------------------------------------
// IpcBridge
// ---------------------------------------------------------------------------

class IpcBridge final {
public:
    explicit IpcBridge(IpcRingBuffer* sramBase) noexcept;
    ~IpcBridge() noexcept = default;

    IpcBridge(IpcBridge const&)            = delete;
    IpcBridge& operator=(IpcBridge const&) = delete;
    IpcBridge(IpcBridge&&)                 = delete;
    IpcBridge& operator=(IpcBridge&&)      = delete;

    /**
     * @brief  Initialise the ring buffer control block (A53 side only).
     *         Sets magic, zeroes head/tail. Must be called before Send().
     */
    VoidResult Init() noexcept;

    /**
     * @brief  Translate a SoaEvent into an IpcSlot, apply E2E Profile 5,
     *         and write the slot into the shared SRAM ring buffer.
     *         Lock-free: uses only atomic ops with full memory barriers.
     * @return VoidResult::Ok() on success,
     *         Err(kIpcBufferFull) if the ring is full,
     *         Err(kInvalidArgument) if payload exceeds kIpcPayloadBytes.
     */
    VoidResult Send(SoaEvent const& event) noexcept;

    /**
     * @brief  Compute AUTOSAR E2E Profile 5 CRC-16 (CRC-16/ARC variant).
     *         Exposed for unit-testing.
     */
    static std::uint16_t ComputeE2eCrc(std::uint8_t const* data,
                                        std::uint16_t       length) noexcept;

    /**
     * @brief  Verify the E2E header of an IpcSlot (used by M7 side or tests).
     */
    static VoidResult VerifyE2e(IpcSlot const& slot,
                                 std::uint8_t   expectedCounter) noexcept;

private:
    void ApplyE2eHeader(IpcSlot& slot) noexcept;

    IpcRingBuffer* const ring_;
    std::uint8_t         seqCounter_  { 0U };
    bool                 initialised_ { false };

    static std::array<std::uint16_t, 256U> const kCrcTable_;
};

} // namespace soa
} // namespace norxs

#endif // NORXS_SOA_IPCBRIDGE_HPP
