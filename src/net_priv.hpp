#pragma once

#include "netstack/checksum.hpp"
#include "netstack/stack.hpp"

#include <deque>
#include <fstream>
#include <memory>
#include <random>
#include <unordered_map>
#include <utility>
#include <vector>

namespace netstack {

enum class TcpState {
  Closed,
  SynSent,
  SynReceived,
  Established,
  FinWait1,
  FinWait2,
  CloseWait,
  Closing,
  LastAck,
  TimeWait
};

const char* tcp_state_name(TcpState s);

constexpr std::uint8_t kFin = 0x01;
constexpr std::uint8_t kSyn = 0x02;
constexpr std::uint8_t kRst = 0x04;
constexpr std::uint8_t kPsh = 0x08;
constexpr std::uint8_t kAck = 0x10;

struct TxSeg {
  std::uint32_t seq = 0;
  std::vector<std::uint8_t> data;
  bool syn = false;
  bool fin = false;
  bool psh = false;
  bool ack = true;
  int tx_count = 0;
  bool drop_once = false;
  std::uint32_t sequence_length() const {
    return static_cast<std::uint32_t>(data.size()) + (syn ? 1u : 0u) + (fin ? 1u : 0u);
  }
};

struct OooSeg {
  std::uint32_t seq = 0;
  std::vector<std::uint8_t> data;
  bool fin = false;
};

struct Tcb;

struct LossTrack {
  LossSample pub;
  std::uint32_t retx_end = 0;
  std::uint16_t local_port = 0;
  std::uint32_t remote_ip = 0;
  std::uint16_t remote_port = 0;
};

struct Tcb {
  TcpState state = TcpState::Closed;
  bool passive = false;
  std::uint16_t listener_port = 0;
  Ipv4 local_ip{};
  Ipv4 remote_ip{};
  std::uint16_t local_port = 0;
  std::uint16_t remote_port = 0;

  std::uint32_t iss = 0;
  std::uint32_t irs = 0;
  std::uint32_t snd_una = 0;
  std::uint32_t snd_nxt = 0;
  std::uint32_t snd_wnd = 0;
  std::uint32_t snd_wl1 = 0;
  std::uint32_t snd_wl2 = 0;
  std::uint8_t snd_scale = 0;
  std::uint8_t rcv_scale = 0;
  bool scale_ok = false;
  std::uint16_t snd_mss = 1460;

  std::uint32_t rcv_nxt = 0;
  std::uint32_t last_adv = 0;

  ByteQueue unsent;
  ByteQueue app_rx;
  std::deque<TxSeg> inflight;
  std::vector<OooSeg> ooo;

  bool fin_pending = false;
  bool fin_sent = false;
  std::uint32_t fin_seq = 0;
  bool peer_fin = false;
  bool reset_flag = false;
  bool close_called = false;
  bool handshake_done = false;

  std::unique_ptr<CongestionControl> cc;
  RttEstimator rtt;
  bool rto_armed = false;
  TimePoint rto_at{};
  int timeout_strikes = 0;
  bool persist_armed = false;
  TimePoint persist_at{};

  bool timing = false;
  std::uint32_t timed_seq = 0;
  TimePoint timed_at{};
  double min_rtt = 0;
  bool have_min_rtt = false;

  std::uint32_t dup_acks = 0;
  bool in_recovery = false;
  std::uint32_t recover = 0;
  std::uint32_t limited_extra = 0;
  std::uint32_t data_segs_sent = 0;

  bool ack_now = false;
  int ack_delay_count = 0;
  bool ack_timer = false;
  TimePoint ack_deadline{};

  TimePoint timewait_deadline{};
  TimePoint finwait2_deadline{};
  bool finwait2_armed = false;

  std::uint64_t retx = 0;
  std::uint64_t fast_retx = 0;
  std::uint64_t timeouts = 0;
  bool ever_progress = false;
};

struct TcpSegView {
  std::uint16_t src = 0;
  std::uint16_t dst = 0;
  std::uint32_t seq = 0;
  std::uint32_t ack = 0;
  std::uint8_t flags = 0;
  std::uint16_t window = 0;
  bool has_mss = false;
  std::uint16_t mss = 0;
  bool has_wscale = false;
  std::uint8_t wscale = 0;
  std::span<const std::uint8_t> payload{};
  bool ok = false;
};

struct Stack::Impl {
  struct Listener {
    Impl* stack = nullptr;
    std::uint16_t port = 0;
    int backlog = 16;
    std::deque<std::shared_ptr<Tcb>> ready;
    bool dead = false;
  };
  struct UdpState {
    Impl* stack = nullptr;
    std::uint16_t port = 0;
    std::deque<UdpSocket::Datagram> q;
    bool dead = false;
  };
  struct ConnKey {
    std::uint16_t lp = 0;
    std::uint32_t rip = 0;
    std::uint16_t rp = 0;
    bool operator==(const ConnKey& o) const { return lp == o.lp && rip == o.rip && rp == o.rp; }
  };
  struct ConnHash {
    std::size_t operator()(const ConnKey& k) const {
      std::uint64_t x = (std::uint64_t(k.rip) << 32) ^ (std::uint64_t(k.lp) << 16) ^ k.rp;
      x *= 0x9E3779B97F4A7C15ull;
      return static_cast<std::size_t>(x ^ (x >> 32));
    }
  };
  struct FragKey {
    std::uint32_t src = 0;
    std::uint32_t dst = 0;
    std::uint16_t id = 0;
    std::uint8_t proto = 0;
    bool operator==(const FragKey& o) const {
      return src == o.src && dst == o.dst && id == o.id && proto == o.proto;
    }
  };
  struct FragHash {
    std::size_t operator()(const FragKey& k) const {
      return (static_cast<std::size_t>(k.src) * 131u) ^ (static_cast<std::size_t>(k.dst) << 1) ^
             (static_cast<std::size_t>(k.id) << 16) ^ k.proto;
    }
  };
  struct Frag {
    std::vector<std::uint8_t> data;
    std::vector<std::uint8_t> have;
    std::size_t n_got = 0;
    std::size_t total = 0;
    TimePoint deadline{};
  };
  struct ArpEnt {
    Mac mac{};
    TimePoint exp{};
  };
  struct ArpPend {
    std::vector<std::vector<std::uint8_t>> pkts;
    TimePoint next{};
    int tries = 0;
  };
  struct PingWait {
    std::uint16_t seq = 0;
    std::vector<std::uint8_t> payload;
    TimePoint sent{};
    bool done = false;
    Duration rtt{};
  };

  Impl(Device& device, Stack::Config config, ClockSource& clock_in);

  Device& dev;
  Stack::Config cfg;
  ClockSource& clock;
  TimePoint start;
  bool verbose = false;
  Counters ctr{};
  Mac mac{};
  std::uint16_t mtu = 1500;
  std::uint16_t ip_id = 1;
  std::uint16_t eph = 49152;
  std::uint16_t ping_id = 1;
  std::uint32_t isn_cursor = 0;
  std::mt19937 rng;

  std::unordered_map<std::uint32_t, ArpEnt> arp;
  std::unordered_map<std::uint32_t, ArpPend> arp_wait;
  std::unordered_map<FragKey, Frag, FragHash> frags;
  std::vector<PingWait> pings;
  std::unordered_map<std::uint16_t, std::shared_ptr<UdpState>> udp;
  std::unordered_map<std::uint16_t, std::shared_ptr<Listener>> listeners;
  std::unordered_map<ConnKey, std::shared_ptr<Tcb>, ConnHash> conns;
  std::vector<LossTrack> losses;

  bool have_goodput_start = false;
  TimePoint goodput_start{};
  TimePoint goodput_end{};
  std::uint64_t payload_acked = 0;
  // A burst is a period with outstanding send data. Idle gaps between HTTP
  // requests must not dilute the goodput of the transfer itself.
  bool burst_active = false;
  TimePoint burst_start{};
  TimePoint burst_end{};
  std::uint64_t burst_bytes = 0;
  std::uint64_t best_burst_bytes = 0;
  double best_burst_sec = 0;

  std::ofstream pcap;
  bool pcap_on = false;
  std::ofstream trace;
  bool trace_on = false;
  bool trace_comma = false;
  std::string trace_title;
  std::string trace_desc;
  std::string trace_source;

  ~Impl();

  void poll();
  void poll_for(std::chrono::milliseconds timeout);
  void input(std::span<const std::uint8_t> frame);
  void run_timers();
  std::optional<TimePoint> next_deadline() const;
  std::uint64_t now_us() const;
  double now_sec() const;
  void log(std::string_view msg) const;

  bool on_link(Ipv4 dst) const;
  Ipv4 next_hop_for(Ipv4 dst) const;
  void arp_learn(Ipv4 ip, Mac mac_addr);
  void arp_rx(std::span<const std::uint8_t> body);
  void arp_request(Ipv4 target);
  void flush_arp(Ipv4 ip);
  void send_frame(Mac dst, std::uint16_t ethertype, std::span<const std::uint8_t> payload);
  void send_ip(Ipv4 dst, IpProto proto, std::span<const std::uint8_t> payload);
  void transmit_ip(Ipv4 hop, std::vector<std::uint8_t> datagram);
  std::vector<std::uint8_t> build_ip(Ipv4 dst, IpProto proto, std::uint16_t id, std::uint16_t frag_off,
                                     bool more, std::span<const std::uint8_t> payload) const;
  void ipv4_rx(std::span<const std::uint8_t> packet);
  void deliver_l4(Ipv4 src, Ipv4 dst, std::uint8_t proto, std::span<const std::uint8_t> payload);
  std::optional<std::vector<std::uint8_t>> reassemble(Ipv4 src, Ipv4 dst, std::uint16_t id,
                                                      std::uint8_t proto, std::uint16_t offset, bool more,
                                                      std::span<const std::uint8_t> data);
  void icmp_rx(Ipv4 src, Ipv4 dst, std::span<const std::uint8_t> msg);
  void udp_rx(Ipv4 src, Ipv4 dst, std::span<const std::uint8_t> seg);
  void send_icmp(Ipv4 dst, std::span<const std::uint8_t> msg);
  void send_icmp_unreach(Ipv4 dst, std::span<const std::uint8_t> quoted);

  void tcp_rx(Ipv4 src, Ipv4 dst, std::span<const std::uint8_t> seg);
  void tcp_input(const std::shared_ptr<Tcb>& t, const TcpSegView& seg);
  void tcp_output(const std::shared_ptr<Tcb>& t);
  void tcp_transmit(Tcb& t, TxSeg& seg);
  void tcp_retransmit(Tcb& t);
  void tcp_send_control(Tcb& t, bool syn, bool ack_flag);
  void tcp_send_pure_ack(Tcb& t);
  void tcp_send_rst_closed(Ipv4 local, Ipv4 remote, const TcpSegView& seg);
  void tcp_reset(Tcb& t);
  void tcp_arm_rto(Tcb& t, bool restart);
  void tcp_on_rto(const std::shared_ptr<Tcb>& t);
  void tcp_schedule_ack(Tcb& t, bool immediate);
  void tcp_ingest(Tcb& t, std::uint32_t seq, std::vector<std::uint8_t> data, bool fin);
  void tcp_drain(Tcb& t);
  void tcp_accept_fin(Tcb& t);
  void tcp_apply_ack(Tcb& t, const TcpSegView& seg);
  void tcp_note_loss(Tcb& t, bool fast, std::uint32_t retx_end);
  void tcp_trace_loss(Tcb& t, bool fast);
  void burst_finalize();
  void burst_on_tx(TimePoint now);
  void tcp_check_loss(const Tcb& t);
  std::uint16_t adv_window(const Tcb& t, bool syn) const;
  std::uint32_t free_rx(const Tcb& t) const;
  std::uint32_t tx_queued(const Tcb& t) const;
  std::uint32_t alloc_isn();
  std::uint16_t alloc_port();
  bool port_busy(std::uint16_t port) const;
  std::uint16_t our_mss() const;
  void apply_options(Tcb& t, const TcpSegView& seg);
  void trace_ev(const Tcb* t, const char* dir, const char* kind, std::uint8_t flags, std::uint32_t seq,
                std::uint32_t ack, std::uint32_t len, std::uint16_t win);
  void pcap_write(std::span<const std::uint8_t> frame, bool inbound);
  void close_trace();

  bool ping_send(Ipv4 dst, std::uint16_t seq, std::vector<std::uint8_t> payload);
  std::optional<Stack::PingReply> ping_take(std::uint16_t seq);

  std::unique_ptr<TcpListener> listen(std::uint16_t port, int backlog);
  std::unique_ptr<TcpSocket> connect(Ipv4 dst, std::uint16_t port);
  std::unique_ptr<UdpSocket> udp_bind(std::uint16_t port);
  std::unique_ptr<TcpSocket> adopt(const std::shared_ptr<Tcb>& tcb);
  IoResult tcp_send(const std::shared_ptr<Tcb>& t, std::span<const std::uint8_t> data);
  IoResult tcp_recv(const std::shared_ptr<Tcb>& t, std::span<std::uint8_t> buf);
  void tcp_close(const std::shared_ptr<Tcb>& t);
  TcpInfo tcp_info(const std::shared_ptr<Tcb>& t) const;
  std::string summary_json() const;
  std::string debug_dump() const;
};

struct TcpSocket::Rep {
  Stack* stack = nullptr;
  std::shared_ptr<Tcb> tcb;
};
struct TcpListener::Rep {
  Stack* stack = nullptr;
  std::shared_ptr<Stack::Impl::Listener> listener;
};
struct UdpSocket::Rep {
  Stack* stack = nullptr;
  std::shared_ptr<Stack::Impl::UdpState> udp;
};

std::string flags_string(std::uint8_t flags);

}  // namespace netstack
