#pragma once

#include "netstack/types.hpp"

namespace netstack {

// Internet checksum (RFC 1071): one's complement sum of 16-bit words.
// `finish` returns the value to store in the checksum field.
inline std::uint64_t checksum_add(std::uint64_t sum, std::span<const std::uint8_t> data) {
  std::size_t i = 0;
  for (; i + 1 < data.size(); i += 2) {
    sum += (std::uint32_t(data[i]) << 8) | data[i + 1];
  }
  if (i < data.size()) sum += std::uint32_t(data[i]) << 8;
  return sum;
}

inline std::uint16_t checksum_fold(std::uint64_t sum) {
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return static_cast<std::uint16_t>(~static_cast<std::uint16_t>(sum));
}

inline std::uint16_t internet_checksum(std::span<const std::uint8_t> data,
                                       std::uint64_t seed = 0) {
  return checksum_fold(checksum_add(seed, data));
}

// A packet that already contains its checksum field folds to 0xffff
// (or 0x0000, the one's-complement negative zero).
inline bool checksum_valid(std::span<const std::uint8_t> data, std::uint64_t seed = 0) {
  std::uint64_t sum = checksum_add(seed, data);
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return sum == 0xffff || sum == 0;
}

// TCP/UDP pseudo-header checksum (RFC 9293 / RFC 768). `segment` includes
// the transport header with the checksum field set to zero.
inline std::uint16_t transport_checksum(Ipv4 src, Ipv4 dst, IpProto proto,
                                        std::span<const std::uint8_t> segment) {
  std::uint8_t ph[12];
  wr32(ph, src.host);
  wr32(ph + 4, dst.host);
  ph[8] = 0;
  ph[9] = static_cast<std::uint8_t>(proto);
  wr16(ph + 10, static_cast<std::uint16_t>(segment.size()));
  std::uint64_t sum = checksum_add(0, ph);
  sum = checksum_add(sum, segment);
  std::uint16_t csum = checksum_fold(sum);
  // UDP: a computed checksum of zero is transmitted as 0xffff, because
  // zero in the field means "no checksum" (RFC 768). TCP has no such
  // sentinel; 0xffff is a legal TCP checksum and needs no rewrite.
  if (proto == IpProto::Udp && csum == 0) csum = 0xffff;
  return csum;
}

inline bool transport_checksum_ok(Ipv4 src, Ipv4 dst, IpProto proto,
                                  std::span<const std::uint8_t> segment) {
  std::uint8_t ph[12];
  wr32(ph, src.host);
  wr32(ph + 4, dst.host);
  ph[8] = 0;
  ph[9] = static_cast<std::uint8_t>(proto);
  wr16(ph + 10, static_cast<std::uint16_t>(segment.size()));
  return checksum_valid(segment, checksum_add(0, ph));
}

}  // namespace netstack
