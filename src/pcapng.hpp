#pragma once
#include <cstddef>
#include <cstdint>

// decimal
// e_ = expected
constexpr std::uint32_t e_shb_block_type = 168627466;
constexpr std::uint32_t e_byte_order_magic = 439041101; // little endian
constexpr std::uint8_t e_idb_block_type = 1;
constexpr std::uint8_t e_epb_block_type = 6;

/* https://pcapng.com/#SHB */
struct SectionHeaderBlock {
  std::uint32_t block_type; // 0x0a0d0d0a
  // ! PALINDROME
  std::uint32_t block_total_length;
  std::uint32_t byte_order_magic; // 0x1a2b3c4d
  std::uint16_t major_version;    // 0x0001
  std::uint16_t minor_version;    // 0x0000
  std::int64_t section_length;    // -1 when not specified
};

/* https://pcapng.com/#IDB */
struct InterfaceDescriptionBlock {
  std::uint32_t block_type; // 0x00000001
  std::uint32_t block_total_length;
  std::uint16_t link_type;
  std::uint16_t reserved;    // 0x0000
  std::uint32_t snap_length; // 0 = no limit
  // options, variable len
  // block total len again
};

/* https://pcapng.com/#EPB */
struct EnhancedPacketBlock {
  std::uint32_t block_type; // 0x00000006
  std::uint32_t block_total_length;
  std::uint32_t interface_id;
  std::uint32_t timestamp_upper;
  std::uint32_t timestamp_lower;
  std::uint32_t captured_packet_length;
  std::uint32_t original_packet_length;
  // packet data, variable len
  // options, variable len
  // block total len again
};

static_assert(offsetof(SectionHeaderBlock, section_length) == 16);
static_assert(offsetof(InterfaceDescriptionBlock, snap_length) == 12);
