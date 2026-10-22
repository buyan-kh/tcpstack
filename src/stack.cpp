#include "net_priv.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <utility>

namespace netstack {
namespace {

void wr_le32(std::ostream& out, std::uint32_t v) {
  char b[4] = {static_cast<char>(v), static_cast<char>(v >> 8), static_cast<char>(v >> 16),
               static_cast<char>(v >> 24)};
  out.write(b, 4);
}
void wr_le16(std::ostream& out, std::uint16_t v) {
  char b[2] = {static_cast<char>(v), static_cast<char>(v >> 8)};
  out.write(b, 2);
}

std::string json_escape(std::string_view s) {
  std::string o;
  for (char c : s) {
    switch (c) {
      case '\\': o += "\\\\"; break;
      case '"': o += "\\\""; break;
      case '\n': o += "\\n"; break;
      default: o += c; break;
    }
  }
  return o;
}

}  // namespace

Stack::Impl::Impl(Device& device, Stack::Config config, ClockSource& clock_in)
    : dev(device),
      cfg(std::move(config)),
      clock(clock_in),
      start(clock.now()),
      mac(device.mac()),
      mtu(device.mtu()),
      rng(std::random_device{}()) {
  std::uniform_int_distribution<std::uint16_t> dist(1, 65535);
  ping_id = dist(rng);
  ip_id = dist(rng);
}

Stack::Impl::~Impl() { close_trace(); }

Stack::Stack(Device& device, Config config, ClockSource& clock) : impl_(std::make_unique<Impl>(device, std::move(config), clock)) {}
Stack::~Stack() = default;
Stack::Impl& Stack::internals() { return *impl_; }
const Stack::Impl& Stack::internals() const { return *impl_; }

std::uint64_t Stack::Impl::now_us() const {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(clock.now() - start).count());
}
double Stack::Impl::now_sec() const {
  return std::chrono::duration<double>(clock.now().time_since_epoch()).count();
}

void Stack::Impl::poll() {
  std::vector<std::uint8_t> frame;
  for (int i = 0; i < 64 && dev.poll_frame(frame); ++i) input(frame);
  run_timers();
}

void Stack::Impl::poll_for(std::chrono::milliseconds timeout) {
  const TimePoint end = clock.now() + timeout;
  while (clock.now() < end) {
    poll();
    const TimePoint now = clock.now();
    if (now >= end) break;
    auto slice = std::chrono::duration_cast<std::chrono::milliseconds>(end - now);
    if (auto nd = next_deadline()) {
      if (*nd <= now) continue;
      const auto until = std::chrono::duration_cast<std::chrono::milliseconds>(*nd - now);
      if (until < slice) slice = until;
    }
    if (slice.count() <= 0) continue;
    const TimePoint before = clock.now();
    dev.wait_ms(static_cast<int>(slice.count()));
    if (clock.now() == before) break;
  }
}

std::optional<TimePoint> Stack::Impl::next_deadline() const {
  std::optional<TimePoint> best;
  auto consider = [&](bool on, TimePoint tp) {
    if (!on) return;
    if (!best || tp < *best) best = tp;
  };
  for (const auto& [k, t] : conns) {
    (void)k;
    consider(t->rto_armed, t->rto_at);
    consider(t->ack_timer, t->ack_deadline);
    consider(t->persist_armed, t->persist_at);
    consider(t->state == TcpState::TimeWait, t->timewait_deadline);
    consider(t->finwait2_armed && t->state == TcpState::FinWait2, t->finwait2_deadline);
  }
  for (const auto& [k, f] : frags) {
    (void)k;
    consider(true, f.deadline);
  }
  for (const auto& [ip, p] : arp_wait) {
    (void)ip;
    if (!p.pkts.empty()) consider(true, p.next);
  }
  return best;
}

void Stack::Impl::run_timers() {
  const TimePoint now = clock.now();
  std::vector<ConnKey> dead;
  // Copy keys first: reset/close mutates the map only after the loop, but
  // output can re-enter timers? It does not. Keys are stable.
  std::vector<ConnKey> keys;
  keys.reserve(conns.size());
  for (const auto& [k, t] : conns) {
    (void)t;
    keys.push_back(k);
  }
  for (const auto& k : keys) {
    auto it = conns.find(k);
    if (it == conns.end()) continue;
    auto t = it->second;
    if (t->rto_armed && now >= t->rto_at) tcp_on_rto(t);
    if (t->state == TcpState::Closed) {
      dead.push_back(k);
      continue;
    }
    if (t->ack_timer && now >= t->ack_deadline) {
      t->ack_timer = false;
      t->ack_now = true;
      tcp_output(t);
    }
    if (t->persist_armed && now >= t->persist_at && t->inflight.empty() && !t->unsent.empty() && t->snd_wnd == 0 &&
        (t->state == TcpState::Established || t->state == TcpState::CloseWait)) {
      t->persist_armed = false;
      TxSeg seg;
      seg.seq = t->snd_nxt;
      seg.data = t->unsent.take(1);
      seg.ack = true;
      seg.psh = true;
      t->snd_nxt += 1;
      t->inflight.push_back(std::move(seg));
      tcp_transmit(*t, t->inflight.back());
    }
    if (t->state == TcpState::TimeWait && now >= t->timewait_deadline) {
      t->state = TcpState::Closed;
      dead.push_back(k);
    } else if (t->finwait2_armed && t->state == TcpState::FinWait2 && now >= t->finwait2_deadline) {
      t->state = TcpState::Closed;
      dead.push_back(k);
    }
  }
  for (const auto& k : dead) conns.erase(k);

  for (auto it = frags.begin(); it != frags.end();) {
    if (now >= it->second.deadline) {
      ctr.frag_timeouts++;
      it = frags.erase(it);
    } else {
      ++it;
    }
  }
  std::vector<std::uint32_t> drop;
  for (auto& [ip, pend] : arp_wait) {
    if (pend.pkts.empty() || (pend.tries >= 5 && now >= pend.next)) {
      drop.push_back(ip);
      continue;
    }
    if (now >= pend.next) {
      arp_request(Ipv4{ip});
      pend.tries++;
      pend.next = now + std::chrono::seconds(1);
    }
  }
  for (auto ip : drop) arp_wait.erase(ip);
}

void Stack::Impl::pcap_write(std::span<const std::uint8_t> frame, bool) {
  if (!pcap_on) return;
  const auto us = now_us();
  wr_le32(pcap, static_cast<std::uint32_t>(us / 1000000));
  wr_le32(pcap, static_cast<std::uint32_t>(us % 1000000));
  wr_le32(pcap, static_cast<std::uint32_t>(frame.size()));
  wr_le32(pcap, static_cast<std::uint32_t>(frame.size()));
  pcap.write(reinterpret_cast<const char*>(frame.data()), static_cast<std::streamsize>(frame.size()));
}

void Stack::Impl::trace_ev(const Tcb* t, const char* dir, const char* kind, std::uint8_t flags, std::uint32_t seq,
                           std::uint32_t ack, std::uint32_t len, std::uint16_t win) {
  if (!trace_on || !t) return;
  if (trace_comma) trace << ",\n";
  trace_comma = true;
  trace << "{\"t_us\":" << now_us() << ",\"dir\":\"" << dir << "\",\"kind\":\"" << kind << "\",\"flags\":\""
        << flags_string(flags) << "\",\"seq\":" << seq << ",\"ack\":" << ack << ",\"len\":" << len << ",\"win\":" << win
        << ",\"state\":\"" << tcp_state_name(t->state) << "\",\"cwnd\":" << (t->cc ? t->cc->cwnd() : 0)
        << ",\"ssthresh\":" << (t->cc ? t->cc->ssthresh() : 0) << ",\"flight\":" << (t->snd_nxt - t->snd_una)
        << ",\"algo\":\"" << (t->cc ? t->cc->name() : "") << "\""
        << ",\"local\":\"" << t->local_ip.to_string() << ":" << t->local_port << "\""
        << ",\"peer\":\"" << t->remote_ip.to_string() << ":" << t->remote_port << "\"}";
}

void Stack::Impl::close_trace() {
  if (!trace_on) return;
  trace << "\n]}\n";
  trace.flush();
  trace_on = false;
}

void Stack::set_verbose(bool on) { impl_->verbose = on; }

void Stack::open_pcap(const std::string& path) {
  impl_->pcap.open(path, std::ios::binary | std::ios::trunc);
  if (!impl_->pcap) return;
  wr_le32(impl_->pcap, 0xa1b2c3d4);
  wr_le16(impl_->pcap, 2);
  wr_le16(impl_->pcap, 4);
  wr_le32(impl_->pcap, 0);
  wr_le32(impl_->pcap, 0);
  wr_le32(impl_->pcap, 65535);
  wr_le32(impl_->pcap, 1);  // Ethernet
  impl_->pcap_on = true;
}

void Stack::open_trace(const std::string& path, std::string title, std::string description, std::string source) {
  impl_->close_trace();
  impl_->trace.open(path, std::ios::trunc);
  if (!impl_->trace) return;
  impl_->trace_title = std::move(title);
  impl_->trace_desc = std::move(description);
  impl_->trace_source = std::move(source);
  impl_->trace_comma = false;
  impl_->trace_on = true;
  impl_->trace << "{\"v\":1,\"title\":\"" << json_escape(impl_->trace_title) << "\",\"description\":\""
               << json_escape(impl_->trace_desc) << "\",\"source\":\"" << json_escape(impl_->trace_source)
               << "\",\"algo\":\"" << (impl_->cfg.congestion == CongestionKind::Cubic ? "cubic" : "reno")
               << "\",\"events\":[\n";
}

const Counters& Stack::counters() const { return impl_->ctr; }

std::vector<LossSample> Stack::loss_samples() const {
  std::vector<LossSample> out;
  out.reserve(impl_->losses.size());
  for (const auto& tr : impl_->losses) out.push_back(tr.pub);
  return out;
}

std::string Stack::Impl::summary_json() const {
  double sec = best_burst_sec;
  std::uint64_t burst_bytes_report = best_burst_bytes;
  if (burst_active && burst_end > burst_start) {
    const double open = std::chrono::duration<double>(burst_end - burst_start).count();
    if (burst_bytes >= burst_bytes_report) {
      sec = open;
      burst_bytes_report = burst_bytes;
    }
  }
  const double mbps = sec > 0 ? (static_cast<double>(burst_bytes_report) * 8.0) / sec / 1e6 : 0;
  std::ostringstream o;
  o << std::setprecision(10);
  o << "{\"cc\":\"" << (cfg.congestion == CongestionKind::Cubic ? "cubic" : "reno") << "\""
    << ",\"payload_acked\":" << payload_acked << ",\"best_burst_bytes\":" << burst_bytes_report
    << ",\"transfer_s\":" << sec << ",\"goodput_mbps\":" << mbps
    << ",\"tx_tcp\":" << ctr.tx_tcp << ",\"rx_tcp\":" << ctr.rx_tcp << ",\"retx\":" << ctr.tcp_retx
    << ",\"fast_retx\":" << ctr.tcp_fast_retx << ",\"timeouts\":" << ctr.tcp_timeouts
    << ",\"debug_drops\":" << ctr.tcp_debug_drops << ",\"checksum_drops\":" << ctr.checksum_drops
    << ",\"frag_reassembled\":" << ctr.frag_reassembled << ",\"losses\":[";
  bool first = true;
  for (const auto& tr : losses) {
    if (!first) o << ',';
    first = false;
    o << "{\"t_us\":" << tr.pub.t_us << ",\"cwnd_before\":" << tr.pub.cwnd_before
      << ",\"rexmit_ack_us\":" << tr.pub.rexmit_ack_us << ",\"restored_us\":" << tr.pub.restored_us
      << ",\"fast\":" << (tr.pub.fast ? "true" : "false")
      << ",\"got_rexmit_ack\":" << (tr.pub.got_rexmit_ack ? "true" : "false")
      << ",\"restored\":" << (tr.pub.restored ? "true" : "false") << "}";
  }
  o << "]}";
  return o.str();
}

std::string Stack::summary_json() const { return impl_->summary_json(); }

std::string Stack::Impl::debug_dump() const {
  std::ostringstream o;
  o << "frames rx " << ctr.rx_frames << " tx " << ctr.tx_frames << " csum_drop " << ctr.checksum_drops
    << " tcp rx " << ctr.rx_tcp << " tx " << ctr.tx_tcp << " retx " << ctr.tcp_retx << " fast " << ctr.tcp_fast_retx
    << " rto " << ctr.tcp_timeouts << "\n";
  for (const auto& [k, t] : conns) {
    (void)k;
    o << tcp_state_name(t->state) << " " << t->local_ip.to_string() << ":" << t->local_port << " -> "
      << t->remote_ip.to_string() << ":" << t->remote_port << " una " << t->snd_una << " nxt " << t->snd_nxt
      << " rcv " << t->rcv_nxt << " cwnd " << (t->cc ? t->cc->cwnd() : 0) << " wnd " << t->snd_wnd << " flight "
      << (t->snd_nxt - t->snd_una) << " unsent " << t->unsent.size() << " rxbuf " << t->app_rx.size() << " inflight "
      << t->inflight.size() << "\n";
  }
  return o.str();
}

std::string Stack::debug_dump() const { return impl_->debug_dump(); }

void Stack::poll() { impl_->poll(); }
void Stack::poll_for(std::chrono::milliseconds timeout) { impl_->poll_for(timeout); }

bool Stack::ping_send(Ipv4 dst, std::uint16_t seq, std::vector<std::uint8_t> payload) {
  return impl_->ping_send(dst, seq, std::move(payload));
}
std::optional<Stack::PingReply> Stack::ping_take(std::uint16_t seq) { return impl_->ping_take(seq); }

std::optional<Stack::PingReply> Stack::ping(Ipv4 dst, std::chrono::milliseconds timeout, std::uint16_t seq,
                                            std::vector<std::uint8_t> payload) {
  if (!ping_send(dst, seq, std::move(payload))) return std::nullopt;
  const TimePoint end = impl_->clock.now() + timeout;
  while (impl_->clock.now() < end) {
    if (auto r = ping_take(seq)) return r;
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(end - impl_->clock.now());
    const TimePoint before = impl_->clock.now();
    poll_for(std::min(std::chrono::milliseconds(50), std::max(left, std::chrono::milliseconds(0))));
    if (impl_->clock.now() == before) break;
  }
  return ping_take(seq);
}

std::unique_ptr<TcpListener> Stack::listen(std::uint16_t port, int backlog) {
  if (port == 0 || impl_->listeners.count(port) || impl_->udp.count(port)) return nullptr;
  auto listener = std::make_shared<Impl::Listener>();
  listener->stack = impl_.get();
  listener->port = port;
  listener->backlog = std::max(1, backlog);
  impl_->listeners[port] = listener;
  auto rep = std::make_unique<TcpListener::Rep>();
  rep->stack = this;
  rep->listener = listener;
  return std::unique_ptr<TcpListener>(new TcpListener(std::move(rep)));
}

std::unique_ptr<TcpSocket> Stack::connect(Ipv4 dst, std::uint16_t port) {
  const std::uint16_t lp = impl_->alloc_port();
  if (lp == 0) return nullptr;
  auto t = std::make_shared<Tcb>();
  t->state = TcpState::SynSent;
  t->local_ip = impl_->cfg.ip;
  t->remote_ip = dst;
  t->local_port = lp;
  t->remote_port = port;
  t->iss = impl_->alloc_isn();
  t->snd_una = t->iss;
  t->snd_nxt = t->iss;
  t->rtt.rto_min = std::chrono::duration<double>(impl_->cfg.rto_min).count();
  t->snd_mss = impl_->our_mss();
  CongestionConfig cc;
  cc.mss = t->snd_mss;
  cc.initial_cwnd_segs = std::max<std::uint32_t>(1, impl_->cfg.initial_cwnd_segs);
  t->cc = make_congestion(impl_->cfg.congestion, cc);
  TxSeg syn;
  syn.seq = t->iss;
  syn.syn = true;
  syn.ack = false;
  t->snd_nxt = t->iss + 1;
  t->inflight.push_back(std::move(syn));
  impl_->conns[Impl::ConnKey{lp, dst.host, port}] = t;
  impl_->tcp_transmit(*t, t->inflight.back());
  auto rep = std::make_unique<TcpSocket::Rep>();
  rep->stack = this;
  rep->tcb = t;
  return std::unique_ptr<TcpSocket>(new TcpSocket(std::move(rep)));
}

std::unique_ptr<UdpSocket> Stack::udp_bind(std::uint16_t port) {
  if (port == 0) port = impl_->alloc_port();
  if (port == 0 || impl_->udp.count(port) || impl_->listeners.count(port)) return nullptr;
  auto st = std::make_shared<Impl::UdpState>();
  st->stack = impl_.get();
  st->port = port;
  impl_->udp[port] = st;
  auto rep = std::make_unique<UdpSocket::Rep>();
  rep->stack = this;
  rep->udp = st;
  return std::unique_ptr<UdpSocket>(new UdpSocket(std::move(rep)));
}

IoResult Stack::Impl::tcp_send(const std::shared_ptr<Tcb>& t, std::span<const std::uint8_t> data) {
  if (!t || t->reset_flag) return IoResult::reset();
  if (t->fin_pending || t->fin_sent) return IoResult::closed();
  if (t->state == TcpState::Closed) return IoResult::closed();
  if (data.empty()) return IoResult::ok(0);
  const auto queued = tx_queued(*t);
  if (queued >= cfg.tx_buf) return IoResult::block();
  const std::size_t room = cfg.tx_buf - queued;
  const std::size_t n = std::min(room, data.size());
  t->unsent.append(data.first(n));
  tcp_output(t);
  return IoResult::ok(n);
}

IoResult Stack::Impl::tcp_recv(const std::shared_ptr<Tcb>& t, std::span<std::uint8_t> buf) {
  if (!t) return IoResult::reset();
  if (t->reset_flag && t->app_rx.empty()) return IoResult::reset();
  const std::size_t n = std::min(buf.size(), t->app_rx.size());
  if (n > 0) {
    auto bytes = t->app_rx.take(n);
    std::memcpy(buf.data(), bytes.data(), n);
    const auto free_now = free_rx(*t);
    if (t->last_adv == 0 || free_now > t->last_adv + t->snd_mss) {
      t->ack_now = true;
      tcp_output(t);
    }
    return IoResult::ok(n);
  }
  if (t->peer_fin || t->state == TcpState::Closed || t->state == TcpState::TimeWait) {
    return t->reset_flag ? IoResult::reset() : IoResult::closed();
  }
  return IoResult::block();
}

void Stack::Impl::tcp_close(const std::shared_ptr<Tcb>& t) {
  if (!t || t->close_called) return;
  t->close_called = true;
  if (t->state == TcpState::SynSent || t->state == TcpState::Closed) {
    if (t->state == TcpState::SynSent) tcp_reset(*t);
    t->state = TcpState::Closed;
    return;
  }
  t->fin_pending = true;
  tcp_output(t);
}

TcpInfo Stack::Impl::tcp_info(const std::shared_ptr<Tcb>& t) const {
  TcpInfo info;
  if (!t) return info;
  info.state = tcp_state_name(t->state);
  info.algo = t->cc ? std::string(t->cc->name()) : "";
  info.cwnd = t->cc ? t->cc->cwnd() : 0;
  info.ssthresh = t->cc ? t->cc->ssthresh() : 0;
  info.snd_una = t->snd_una;
  info.snd_nxt = t->snd_nxt;
  info.snd_wnd = t->snd_wnd;
  info.rcv_nxt = t->rcv_nxt;
  info.mss = t->snd_mss;
  info.flight = t->snd_nxt - t->snd_una;
  info.rto_sec = t->rtt.rto();
  info.srtt_sec = t->rtt.have() ? t->rtt.srtt() : 0;
  info.retx = t->retx;
  info.fast_retx = t->fast_retx;
  info.timeouts = t->timeouts;
  info.established = t->handshake_done && !t->reset_flag && t->state != TcpState::Closed &&
                     t->state != TcpState::SynSent && t->state != TcpState::SynReceived;
  info.reset = t->reset_flag;
  info.peer_closed = t->peer_fin;
  info.fin_sent = t->fin_sent;
  return info;
}

TcpSocket::TcpSocket(std::unique_ptr<Rep> rep) : rep_(std::move(rep)) {}
TcpSocket::~TcpSocket() {
  if (rep_ && rep_->tcb && rep_->stack) rep_->stack->internals().tcp_close(rep_->tcb);
}
TcpSocket::TcpSocket(TcpSocket&& o) noexcept : rep_(std::move(o.rep_)) {}
TcpSocket& TcpSocket::operator=(TcpSocket&& o) noexcept {
  if (this != &o) {
    if (rep_ && rep_->tcb && rep_->stack) rep_->stack->internals().tcp_close(rep_->tcb);
    rep_ = std::move(o.rep_);
  }
  return *this;
}
IoResult TcpSocket::send(std::span<const std::uint8_t> data) {
  if (!rep_ || !rep_->stack) return IoResult::reset();
  return rep_->stack->internals().tcp_send(rep_->tcb, data);
}
IoResult TcpSocket::recv(std::span<std::uint8_t> buf) {
  if (!rep_ || !rep_->stack) return IoResult::reset();
  return rep_->stack->internals().tcp_recv(rep_->tcb, buf);
}
void TcpSocket::close() {
  if (!rep_ || !rep_->stack) return;
  rep_->stack->internals().tcp_close(rep_->tcb);
}
bool TcpSocket::established() const {
  if (!rep_ || !rep_->tcb) return false;
  return rep_->tcb->handshake_done && !rep_->tcb->reset_flag && rep_->tcb->state != TcpState::Closed &&
         rep_->tcb->state != TcpState::SynSent && rep_->tcb->state != TcpState::SynReceived;
}
bool TcpSocket::failed() const {
  if (!rep_ || !rep_->tcb) return true;
  return rep_->tcb->reset_flag || (rep_->tcb->state == TcpState::Closed && !rep_->tcb->handshake_done);
}
TcpInfo TcpSocket::info() const {
  if (!rep_ || !rep_->stack) return {};
  return rep_->stack->internals().tcp_info(rep_->tcb);
}

TcpListener::TcpListener(std::unique_ptr<Rep> rep) : rep_(std::move(rep)) {}
TcpListener::~TcpListener() {
  if (!rep_ || !rep_->listener || !rep_->stack) return;
  auto& impl = rep_->stack->internals();
  auto& listener = *rep_->listener;
  listener.dead = true;
  for (auto& t : listener.ready) {
    impl.tcp_reset(*t);
    impl.conns.erase(Stack::Impl::ConnKey{t->local_port, t->remote_ip.host, t->remote_port});
  }
  listener.ready.clear();
  impl.listeners.erase(listener.port);
}
TcpListener::TcpListener(TcpListener&& o) noexcept : rep_(std::move(o.rep_)) {}
TcpListener& TcpListener::operator=(TcpListener&& o) noexcept {
  if (this != &o) {
    if (rep_ && rep_->listener && rep_->stack) {
      auto& impl = rep_->stack->internals();
      auto& listener = *rep_->listener;
      listener.dead = true;
      for (auto& t : listener.ready) {
        impl.tcp_reset(*t);
        impl.conns.erase(Stack::Impl::ConnKey{t->local_port, t->remote_ip.host, t->remote_port});
      }
      listener.ready.clear();
      impl.listeners.erase(listener.port);
    }
    rep_ = std::move(o.rep_);
  }
  return *this;
}
std::uint16_t TcpListener::port() const { return rep_ && rep_->listener ? rep_->listener->port : 0; }
std::unique_ptr<TcpSocket> TcpListener::accept_nb() {
  if (!rep_ || !rep_->listener || rep_->listener->ready.empty()) return nullptr;
  auto t = rep_->listener->ready.front();
  rep_->listener->ready.pop_front();
  auto r = std::make_unique<TcpSocket::Rep>();
  r->stack = rep_->stack;
  r->tcb = std::move(t);
  return std::unique_ptr<TcpSocket>(new TcpSocket(std::move(r)));
}

UdpSocket::UdpSocket(std::unique_ptr<Rep> rep) : rep_(std::move(rep)) {}
UdpSocket::~UdpSocket() {
  if (!rep_ || !rep_->udp || !rep_->stack) return;
  rep_->udp->dead = true;
  rep_->stack->internals().udp.erase(rep_->udp->port);
}
UdpSocket::UdpSocket(UdpSocket&& o) noexcept : rep_(std::move(o.rep_)) {}
UdpSocket& UdpSocket::operator=(UdpSocket&& o) noexcept {
  if (this != &o) {
    if (rep_ && rep_->udp && rep_->stack) {
      rep_->udp->dead = true;
      rep_->stack->internals().udp.erase(rep_->udp->port);
    }
    rep_ = std::move(o.rep_);
  }
  return *this;
}
std::uint16_t UdpSocket::port() const { return rep_ && rep_->udp ? rep_->udp->port : 0; }
IoResult UdpSocket::send_to(Ipv4 dst, std::uint16_t port, std::span<const std::uint8_t> data) {
  if (!rep_ || !rep_->udp || !rep_->stack || rep_->udp->dead) return IoResult::reset();
  if (8 + data.size() > 65535) return IoResult::reset();
  std::vector<std::uint8_t> seg(8 + data.size());
  wr16(seg.data(), rep_->udp->port);
  wr16(seg.data() + 2, port);
  wr16(seg.data() + 4, static_cast<std::uint16_t>(seg.size()));
  wr16(seg.data() + 6, 0);
  if (!data.empty()) std::memcpy(seg.data() + 8, data.data(), data.size());
  wr16(seg.data() + 6, transport_checksum(rep_->stack->internals().cfg.ip, dst, IpProto::Udp, seg));
  rep_->stack->internals().ctr.tx_udp++;
  rep_->stack->internals().send_ip(dst, IpProto::Udp, seg);
  return IoResult::ok(data.size());
}
std::optional<UdpSocket::Datagram> UdpSocket::recv_from() {
  if (!rep_ || !rep_->udp || rep_->udp->q.empty()) return std::nullopt;
  auto d = std::move(rep_->udp->q.front());
  rep_->udp->q.pop_front();
  return d;
}

}  // namespace netstack
