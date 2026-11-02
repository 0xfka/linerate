#include "pcapng.hpp"
#include <span>

constexpr std::uint8_t batch_pkt = 64;
// p_ = parser

/* Enhanced packet block
   The main structure that holds the packet data.

   If returns 1, send batch via TX */
[[gnu::always_inline]] inline std::uint8_t
p_epb(std::uint8_t *p, std::array<std::span<const uint8_t>, batch_pkt> &pkts,
      std::uint32_t &truncated_pkt_cnt, std::uint8_t &idx_pkt) {
  EnhancedPacketBlock *epb = (EnhancedPacketBlock *)p;
  epb->original_packet_length > epb->captured_packet_length
      ? ++truncated_pkt_cnt
      : 0;
  pkts[idx_pkt] = std::span<const uint8_t>(p + sizeof(EnhancedPacketBlock),
                                           epb->captured_packet_length);
  ++idx_pkt;
  return idx_pkt == 64;
}
