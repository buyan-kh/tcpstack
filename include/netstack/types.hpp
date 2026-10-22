#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace netstack {

// Monotonic clock for RTO, TIME_WAIT, and trace timestamps. Tests inject a
// manual clock so retransmission can be exercised without sleeping.
using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;
using Duration = Clock::duration;

class ClockSource {
 public:
  virtual ~ClockSource() = default;
  virtual TimePoint now() const = 0;
};

class SteadyClockSource final : public ClockSource {
 public:
  TimePoint now() const override { return Clock::now(); }
};

class ManualClock final : public ClockSource {
 public:
  explicit ManualClock(TimePoint start = TimePoint{}) : now_(start) {}
  TimePoint now() const override { return now_; }
  void advance(Duration d) { now_ += d; }

 private:
  TimePoint now_;
};

struct Mac {
  std::array<std::uint8_t, 6> b{};

  static constexpr Mac broadcast() {
    return Mac{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
  }
  bool is_broadcast() const { return *this == broadcast(); }
  bool operator==(const Mac&) const = default;

  std::string to_string() const {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1],
                  b[2], b[3], b[4], b[5]);
    return buf;
  }
};

// IPv4 address stored in host byte order so shifts and masks read naturally.
struct Ipv4 {
  std::uint32_t host = 0;

  static constexpr Ipv4 from_octets(std::uint8_t a, std::uint8_t b, std::uint8_t c,
                                    std::uint8_t d) {
    return Ipv4{(std::uint32_t(a) << 24) | (std::uint32_t(b) << 16) |
                (std::uint32_t(c) << 8) | d};
  }

  static std::optional<Ipv4> parse(std::string_view s) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    char tail = 0;
    if (std::sscanf(std::string(s).c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) !=
        4) {
      return std::nullopt;
    }
    if (a > 255 || b > 255 || c > 255 || d > 255) return std::nullopt;
    return from_octets(static_cast<std::uint8_t>(a), static_cast<std::uint8_t>(b),
                       static_cast<std::uint8_t>(c), static_cast<std::uint8_t>(d));
  }

  constexpr bool operator==(const Ipv4&) const = default;
  constexpr bool operator!=(const Ipv4&) const = default;

  std::string to_string() const {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (host >> 24) & 0xff,
                  (host >> 16) & 0xff, (host >> 8) & 0xff, host & 0xff);
    return buf;
  }
};

enum class EtherType : std::uint16_t { Ipv4 = 0x0800, Arp = 0x0806 };
enum class IpProto : std::uint8_t { Icmp = 1, Tcp = 6, Udp = 17 };

inline std::uint16_t rd16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>((std::uint16_t(p[0]) << 8) | p[1]);
}
inline std::uint32_t rd32(const std::uint8_t* p) {
  return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) |
         (std::uint32_t(p[2]) << 8) | p[3];
}
inline void wr16(std::uint8_t* p, std::uint16_t v) {
  p[0] = static_cast<std::uint8_t>(v >> 8);
  p[1] = static_cast<std::uint8_t>(v);
}
inline void wr32(std::uint8_t* p, std::uint32_t v) {
  p[0] = static_cast<std::uint8_t>(v >> 24);
  p[1] = static_cast<std::uint8_t>(v >> 16);
  p[2] = static_cast<std::uint8_t>(v >> 8);
  p[3] = static_cast<std::uint8_t>(v);
}

// Sequence numbers are a 32-bit ring (RFC 9293). Casting the unsigned
// difference to int32 is the comparison, valid while the true distance
// stays below 2^31. Windows in this stack are far smaller than that.
inline bool seq_lt(std::uint32_t a, std::uint32_t b) {
  return static_cast<std::int32_t>(a - b) < 0;
}
inline bool seq_le(std::uint32_t a, std::uint32_t b) {
  return static_cast<std::int32_t>(a - b) <= 0;
}
inline bool seq_gt(std::uint32_t a, std::uint32_t b) {
  return static_cast<std::int32_t>(a - b) > 0;
}
inline bool seq_ge(std::uint32_t a, std::uint32_t b) {
  return static_cast<std::int32_t>(a - b) >= 0;
}

// Byte queue with a read cursor. Used for TCP send/receive buffers so
// consuming the front does not memmove the whole buffer every ACK.
class ByteQueue {
 public:
  std::size_t size() const { return buf_.size() - r_; }
  bool empty() const { return size() == 0; }

  void append(std::span<const std::uint8_t> s) {
    buf_.insert(buf_.end(), s.begin(), s.end());
  }
  void append_byte(std::uint8_t b) { buf_.push_back(b); }

  std::span<const std::uint8_t> peek() const {
    return {buf_.data() + r_, size()};
  }

  std::vector<std::uint8_t> take(std::size_t n) {
    n = std::min(n, size());
    std::vector<std::uint8_t> out(buf_.begin() + static_cast<std::ptrdiff_t>(r_),
                                  buf_.begin() + static_cast<std::ptrdiff_t>(r_ + n));
    consume(n);
    return out;
  }

  void consume(std::size_t n) {
    r_ += n;
    if (r_ > (1u << 16) && r_ * 2 > buf_.size()) {
      buf_.erase(buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(r_));
      r_ = 0;
    }
  }

  void clear() {
    buf_.clear();
    r_ = 0;
  }

 private:
  std::vector<std::uint8_t> buf_;
  std::size_t r_ = 0;
};

struct Counters {
  std::uint64_t rx_frames = 0;
  std::uint64_t tx_frames = 0;
  std::uint64_t rx_arp = 0;
  std::uint64_t tx_arp = 0;
  std::uint64_t rx_ip = 0;
  std::uint64_t tx_ip = 0;
  std::uint64_t rx_icmp = 0;
  std::uint64_t tx_icmp = 0;
  std::uint64_t rx_udp = 0;
  std::uint64_t tx_udp = 0;
  std::uint64_t rx_tcp = 0;
  std::uint64_t tx_tcp = 0;
  std::uint64_t checksum_drops = 0;
  std::uint64_t frag_reassembled = 0;
  std::uint64_t frag_timeouts = 0;
  std::uint64_t tcp_retx = 0;
  std::uint64_t tcp_fast_retx = 0;
  std::uint64_t tcp_timeouts = 0;
  std::uint64_t tcp_debug_drops = 0;
  std::uint64_t bytes_acked = 0;
};

}  // namespace netstack
