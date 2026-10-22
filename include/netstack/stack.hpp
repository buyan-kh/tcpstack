#pragma once

#include "netstack/congestion.hpp"
#include "netstack/device.hpp"
#include "netstack/types.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace netstack {

struct IoResult {
  enum class Code { Ok, WouldBlock, Closed, Reset, Error };
  Code code = Code::WouldBlock;
  std::size_t n = 0;
  static IoResult ok(std::size_t n) { return {Code::Ok, n}; }
  static IoResult block() { return {Code::WouldBlock, 0}; }
  static IoResult closed() { return {Code::Closed, 0}; }
  static IoResult reset() { return {Code::Reset, 0}; }
};

struct TcpInfo {
  std::string state;
  std::string algo;
  std::uint32_t cwnd = 0;
  std::uint32_t ssthresh = 0;
  std::uint32_t snd_una = 0;
  std::uint32_t snd_nxt = 0;
  std::uint32_t snd_wnd = 0;
  std::uint32_t rcv_nxt = 0;
  std::uint32_t mss = 0;
  std::uint32_t flight = 0;
  double rto_sec = 1;
  double srtt_sec = 0;
  std::uint64_t retx = 0;
  std::uint64_t fast_retx = 0;
  std::uint64_t timeouts = 0;
  bool established = false;
  bool reset = false;
  bool peer_closed = false;
  bool fin_sent = false;
};

struct LossSample {
  std::uint64_t t_us = 0;
  std::uint32_t cwnd_before = 0;
  std::uint64_t rexmit_ack_us = 0;
  std::uint64_t restored_us = 0;
  bool fast = false;
  bool got_rexmit_ack = false;
  bool restored = false;
};

class Stack;

// BSD-shaped TCP endpoint. All calls are non-blocking and single-threaded:
// the owner thread is the only thread that may call poll() and socket
// methods. Blocking would deadlock a test that runs both peers in one thread.
class TcpSocket {
 public:
  ~TcpSocket();
  TcpSocket(TcpSocket&&) noexcept;
  TcpSocket& operator=(TcpSocket&&) noexcept;
  TcpSocket(const TcpSocket&) = delete;
  TcpSocket& operator=(const TcpSocket&) = delete;

  IoResult send(std::span<const std::uint8_t> data);
  IoResult recv(std::span<std::uint8_t> buf);
  void close();
  bool established() const;
  bool failed() const;
  TcpInfo info() const;

 private:
  friend class Stack;
  friend class TcpListener;
  struct Rep;
  explicit TcpSocket(std::unique_ptr<Rep> rep);
  std::unique_ptr<Rep> rep_;
};

class TcpListener {
 public:
  ~TcpListener();
  TcpListener(TcpListener&&) noexcept;
  TcpListener& operator=(TcpListener&&) noexcept;
  TcpListener(const TcpListener&) = delete;
  TcpListener& operator=(const TcpListener&) = delete;

  std::unique_ptr<TcpSocket> accept_nb();
  std::uint16_t port() const;

 private:
  friend class Stack;
  struct Rep;
  explicit TcpListener(std::unique_ptr<Rep> rep);
  std::unique_ptr<Rep> rep_;
};

class UdpSocket {
 public:
  ~UdpSocket();
  UdpSocket(UdpSocket&&) noexcept;
  UdpSocket& operator=(UdpSocket&&) noexcept;
  UdpSocket(const UdpSocket&) = delete;
  UdpSocket& operator=(const UdpSocket&) = delete;

  IoResult send_to(Ipv4 dst, std::uint16_t port, std::span<const std::uint8_t> data);
  struct Datagram {
    Ipv4 src{};
    std::uint16_t port = 0;
    std::vector<std::uint8_t> data;
  };
  std::optional<Datagram> recv_from();
  std::uint16_t port() const;

 private:
  friend class Stack;
  struct Rep;
  explicit UdpSocket(std::unique_ptr<Rep> rep);
  std::unique_ptr<Rep> rep_;
};

class Stack {
 public:
  struct Config {
    Ipv4 ip{};
    Ipv4 mask = Ipv4::from_octets(255, 255, 255, 0);
    Ipv4 gateway{};
    CongestionKind congestion = CongestionKind::Reno;
    std::uint32_t rx_buf = 256 * 1024;
    std::uint32_t tx_buf = 256 * 1024;
    std::uint32_t initial_cwnd_segs = 10;
    int max_retries = 6;
    Duration time_wait = std::chrono::seconds(60);
    Duration delayed_ack = std::chrono::milliseconds(40);
    Duration rto_min = std::chrono::milliseconds(200);
    // Drop the Nth data segment (0-based) once, on first transmission.
    // -1 disables. The retransmission is sent. Used to measure recovery
    // against a real peer without depending on a statistical loss draw.
    int drop_data_seg = -1;
    bool window_scale = true;
    std::uint32_t isn = 0;  // 0 = random
  };

  Stack(Device& device, Config config, ClockSource& clock);
  ~Stack();
  Stack(const Stack&) = delete;
  Stack& operator=(const Stack&) = delete;

  void poll();
  void poll_for(std::chrono::milliseconds timeout);

  std::unique_ptr<TcpListener> listen(std::uint16_t port, int backlog = 16);
  std::unique_ptr<TcpSocket> connect(Ipv4 dst, std::uint16_t port);
  std::unique_ptr<UdpSocket> udp_bind(std::uint16_t port);

  struct PingReply {
    std::uint16_t seq = 0;
    std::chrono::microseconds rtt{};
  };
  // Non-blocking ping. `ping_take` returns the matching echo reply once it
  // has been processed by poll(). `ping` loops on poll_for and is the right
  // call when the peer is the kernel on the other side of a TAP device.
  bool ping_send(Ipv4 dst, std::uint16_t seq = 1, std::vector<std::uint8_t> payload = {});
  std::optional<PingReply> ping_take(std::uint16_t seq);
  std::optional<PingReply> ping(Ipv4 dst, std::chrono::milliseconds timeout, std::uint16_t seq = 1,
                                std::vector<std::uint8_t> payload = {});

  void set_verbose(bool on);
  void open_pcap(const std::string& path);
  void open_trace(const std::string& path, std::string title, std::string description,
                  std::string source);

  const Counters& counters() const;
  std::vector<LossSample> loss_samples() const;
  // Machine-readable snapshot. Bytes and times are measured, not estimated.
  std::string summary_json() const;
  std::string debug_dump() const;

 private:
  struct Impl;
  friend class TcpSocket;
  friend class TcpListener;
  friend class UdpSocket;
  Impl& internals();
  const Impl& internals() const;
  std::unique_ptr<Impl> impl_;
};

}  // namespace netstack
