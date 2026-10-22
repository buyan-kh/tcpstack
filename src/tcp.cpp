#include "net_priv.hpp"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <sstream>

namespace netstack {
namespace {

TcpSegView parse_tcp(std::span<const std::uint8_t> seg) {
  TcpSegView v;
  if (seg.size() < 20) return v;
  v.src = rd16(seg.data());
  v.dst = rd16(seg.data() + 2);
  v.seq = rd32(seg.data() + 4);
  v.ack = rd32(seg.data() + 8);
  const std::uint8_t off = static_cast<std::uint8_t>((seg[12] >> 4) * 4);
  if (off < 20 || seg.size() < off) return v;
  v.flags = seg[13];
  v.window = rd16(seg.data() + 14);
  std::size_t i = 20;
  while (i < off) {
    const std::uint8_t kind = seg[i];
    if (kind == 0) break;
    if (kind == 1) {
      ++i;
      continue;
    }
    if (i + 1 >= off) break;
    const std::uint8_t len = seg[i + 1];
    if (len < 2 || i + len > off) break;
    if (kind == 2 && len == 4) {
      v.has_mss = true;
      v.mss = rd16(seg.data() + i + 2);
    } else if (kind == 3 && len == 3) {
      v.has_wscale = true;
      v.wscale = seg[i + 2];
    }
    i += len;
  }
  v.payload = seg.subspan(off);
  v.ok = true;
  return v;
}

std::vector<std::uint8_t> build_tcp(Ipv4 src, Ipv4 dst, std::uint16_t sp, std::uint16_t dp, std::uint32_t seq,
                                    std::uint32_t ack, std::uint8_t flags, std::uint16_t window,
                                    std::span<const std::uint8_t> payload, std::span<const std::uint8_t> opts) {
  const std::size_t hdr = 20 + opts.size();
  std::vector<std::uint8_t> seg(hdr + payload.size());
  wr16(seg.data(), sp);
  wr16(seg.data() + 2, dp);
  wr32(seg.data() + 4, seq);
  wr32(seg.data() + 8, ack);
  seg[12] = static_cast<std::uint8_t>((hdr / 4) << 4);
  seg[13] = flags;
  wr16(seg.data() + 14, window);
  wr16(seg.data() + 16, 0);
  if (!opts.empty()) std::memcpy(seg.data() + 20, opts.data(), opts.size());
  if (!payload.empty()) std::memcpy(seg.data() + hdr, payload.data(), payload.size());
  wr16(seg.data() + 16, transport_checksum(src, dst, IpProto::Tcp, seg));
  return seg;
}

std::uint32_t payload_between(const Tcb& t, std::uint32_t from, std::uint32_t to) {
  std::uint32_t n = 0;
  for (const auto& seg : t.inflight) {
    const std::uint32_t data_seq = seg.seq + (seg.syn ? 1u : 0u);
    const std::uint32_t data_end = data_seq + static_cast<std::uint32_t>(seg.data.size());
    std::uint32_t a = seq_lt(data_seq, from) ? from : data_seq;
    std::uint32_t b = seq_lt(to, data_end) ? to : data_end;
    if (seq_lt(a, b)) n += b - a;
  }
  return n;
}

bool acceptable_seq(const Tcb& t, const TcpSegView& seg, std::uint32_t wnd) {
  const std::uint32_t seglen =
      static_cast<std::uint32_t>(seg.payload.size()) + ((seg.flags & kSyn) ? 1u : 0u) + ((seg.flags & kFin) ? 1u : 0u);
  if (seglen == 0) {
    if (wnd == 0) return seg.seq == t.rcv_nxt;
    return seq_le(t.rcv_nxt, seg.seq) && seq_lt(seg.seq, t.rcv_nxt + wnd);
  }
  if (wnd == 0) return false;
  const std::uint32_t last = seg.seq + seglen - 1;
  const bool start_ok = seq_le(t.rcv_nxt, seg.seq) && seq_lt(seg.seq, t.rcv_nxt + wnd);
  const bool last_ok = seq_le(t.rcv_nxt, last) && seq_lt(last, t.rcv_nxt + wnd);
  return start_ok || last_ok;
}

}  // namespace

const char* tcp_state_name(TcpState s) {
  switch (s) {
    case TcpState::Closed: return "CLOSED";
    case TcpState::SynSent: return "SYN_SENT";
    case TcpState::SynReceived: return "SYN_RECEIVED";
    case TcpState::Established: return "ESTABLISHED";
    case TcpState::FinWait1: return "FIN_WAIT_1";
    case TcpState::FinWait2: return "FIN_WAIT_2";
    case TcpState::CloseWait: return "CLOSE_WAIT";
    case TcpState::Closing: return "CLOSING";
    case TcpState::LastAck: return "LAST_ACK";
    case TcpState::TimeWait: return "TIME_WAIT";
  }
  return "?";
}

std::string flags_string(std::uint8_t flags) {
  std::string s;
  auto add = [&](std::uint8_t bit, const char* name) {
    if (!(flags & bit)) return;
    if (!s.empty()) s += ',';
    s += name;
  };
  add(kSyn, "SYN");
  add(kAck, "ACK");
  add(kFin, "FIN");
  add(kRst, "RST");
  add(kPsh, "PSH");
  if (s.empty()) s = "NONE";
  return s;
}

std::uint16_t Stack::Impl::our_mss() const {
  if (mtu <= 40) return 1;
  return static_cast<std::uint16_t>(mtu - 40);
}

std::uint32_t Stack::Impl::free_rx(const Tcb& t) const {
  const auto used = t.app_rx.size();
  if (used >= cfg.rx_buf) return 0;
  return static_cast<std::uint32_t>(cfg.rx_buf - used);
}

std::uint32_t Stack::Impl::tx_queued(const Tcb& t) const {
  std::uint32_t n = static_cast<std::uint32_t>(t.unsent.size());
  for (const auto& seg : t.inflight) n += static_cast<std::uint32_t>(seg.data.size());
  return n;
}

std::uint16_t Stack::Impl::adv_window(const Tcb& t, bool syn) const {
  std::uint32_t wnd = free_rx(t);
  if (syn || t.rcv_scale == 0) return static_cast<std::uint16_t>(std::min<std::uint32_t>(wnd, 65535));
  wnd >>= t.rcv_scale;
  return static_cast<std::uint16_t>(std::min<std::uint32_t>(wnd, 65535));
}

std::uint32_t Stack::Impl::alloc_isn() {
  if (cfg.isn != 0) return cfg.isn + isn_cursor++;
  std::uniform_int_distribution<std::uint32_t> dist;
  return dist(rng);
}

bool Stack::Impl::port_busy(std::uint16_t port) const {
  if (listeners.count(port) || udp.count(port)) return true;
  for (const auto& [k, t] : conns) {
    (void)k;
    if (t->local_port == port) return true;
  }
  return false;
}

std::uint16_t Stack::Impl::alloc_port() {
  for (int i = 0; i < 20000; ++i) {
    const std::uint16_t p = eph++;
    if (eph < 49152) eph = 49152;
    if (!port_busy(p)) return p;
  }
  return 0;
}

void Stack::Impl::apply_options(Tcb& t, const TcpSegView& seg) {
  const std::uint16_t ours = our_mss();
  const std::uint16_t peer = seg.has_mss && seg.mss > 0 ? seg.mss : 536;
  t.snd_mss = std::min(ours, peer);
  if (cfg.window_scale && seg.has_wscale) {
    t.snd_scale = std::min<std::uint8_t>(seg.wscale, 14);
    t.rcv_scale = 7;
    t.scale_ok = true;
  } else {
    t.snd_scale = 0;
    t.rcv_scale = 0;
    t.scale_ok = false;
  }
  if (t.cc) t.cc->set_mss(t.snd_mss);
}

void Stack::Impl::tcp_schedule_ack(Tcb& t, bool immediate) {
  if (immediate) {
    t.ack_now = true;
    t.ack_delay_count = 0;
    t.ack_timer = false;
    return;
  }
  t.ack_delay_count++;
  if (t.ack_delay_count >= 2) {
    t.ack_now = true;
    t.ack_delay_count = 0;
    t.ack_timer = false;
    return;
  }
  if (!t.ack_timer) {
    t.ack_timer = true;
    t.ack_deadline = clock.now() + cfg.delayed_ack;
  }
}

void Stack::Impl::tcp_note_loss(Tcb& t, bool fast, std::uint32_t retx_end) {
  LossTrack tr;
  tr.pub.t_us = now_us();
  tr.pub.cwnd_before = t.cc ? t.cc->cwnd() : 0;
  tr.pub.fast = fast;
  tr.retx_end = retx_end;
  tr.local_port = t.local_port;
  tr.remote_ip = t.remote_ip.host;
  tr.remote_port = t.remote_port;
  losses.push_back(tr);
}

void Stack::Impl::tcp_trace_loss(Tcb& t, bool fast) {
  // Logged after the congestion controller has applied the reduction, so the
  // trace's cwnd and ssthresh are the post-loss values.
  trace_ev(&t, "tx", fast ? "fast_retransmit" : "rto", 0, t.snd_una, t.rcv_nxt, 0, adv_window(t, false));
}

void Stack::Impl::burst_finalize() {
  if (!burst_active) return;
  if (burst_bytes > 0 && burst_end > burst_start) {
    const double sec = std::chrono::duration<double>(burst_end - burst_start).count();
    if (sec > 0 && burst_bytes >= best_burst_bytes) {
      best_burst_bytes = burst_bytes;
      best_burst_sec = sec;
    }
  }
  burst_active = false;
  burst_bytes = 0;
}

void Stack::Impl::burst_on_tx(TimePoint now) {
  // A quiet gap splits /health from the download. A momentary drain of the
  // send buffer between poll turns is not a gap: the same response continues.
  if (burst_active && burst_bytes > 0 && burst_end > burst_start &&
      now - burst_end > std::chrono::milliseconds(100)) {
    burst_finalize();
  }
  if (!burst_active) {
    burst_active = true;
    burst_start = now;
    burst_bytes = 0;
    burst_end = now;
  }
}

void Stack::Impl::tcp_check_loss(const Tcb& t) {
  for (auto& tr : losses) {
    if (tr.local_port != t.local_port || tr.remote_ip != t.remote_ip.host || tr.remote_port != t.remote_port) continue;
    if (!tr.pub.got_rexmit_ack && tr.retx_end != 0 && seq_ge(t.snd_una, tr.retx_end)) {
      tr.pub.got_rexmit_ack = true;
      tr.pub.rexmit_ack_us = now_us() - tr.pub.t_us;
    }
    // Ignore the artificial inflation inside fast recovery. Recovery is
    // "cwnd back to the pre-loss value" once NewReno has deflated it.
    if (!tr.pub.restored && !t.in_recovery && t.cc && t.cc->cwnd() >= tr.pub.cwnd_before) {
      tr.pub.restored = true;
      tr.pub.restored_us = now_us() - tr.pub.t_us;
    }
  }
}

void Stack::Impl::tcp_arm_rto(Tcb& t, bool restart) {
  if (t.inflight.empty()) {
    t.rto_armed = false;
    return;
  }
  if (!t.rto_armed || restart) {
    t.rto_armed = true;
    const auto sec = std::chrono::duration<double>(t.rtt.rto());
    t.rto_at = clock.now() + std::chrono::duration_cast<Duration>(sec);
  }
}

void Stack::Impl::tcp_transmit(Tcb& t, TxSeg& seg) {
  if (seg.tx_count == 0 && !seg.data.empty() && cfg.drop_data_seg >= 0) {
    if (static_cast<int>(t.data_segs_sent) == cfg.drop_data_seg) seg.drop_once = true;
    t.data_segs_sent++;
  }
  const bool first = seg.tx_count == 0;
  const bool drop = seg.drop_once && first;
  if (!first) {
    t.timing = false;  // Karn: a retransmitted segment must not update the RTT sample.
    t.retx++;
    ctr.tcp_retx++;
  }
  std::uint8_t flags = 0;
  if (seg.syn) flags |= kSyn;
  if (seg.ack) flags |= kAck;
  if (seg.fin) flags |= kFin;
  if (seg.psh && !seg.data.empty()) flags |= kPsh;
  std::uint8_t optbuf[8];
  std::span<const std::uint8_t> opts;
  if (seg.syn) {
    wr16(optbuf, 0x0204);
    wr16(optbuf + 2, our_mss());
    optbuf[4] = 1;
    optbuf[5] = 3;
    optbuf[6] = 3;
    optbuf[7] = cfg.window_scale ? 7 : 0;
    if (!cfg.window_scale) {
      opts = {optbuf, 4};
    } else {
      opts = {optbuf, 8};
    }
  }
  const bool syn_seg = seg.syn;
  const std::uint16_t win = adv_window(t, syn_seg);
  t.last_adv = free_rx(t);
  auto bytes = build_tcp(t.local_ip, t.remote_ip, t.local_port, t.remote_port, seg.seq, t.rcv_nxt, flags, win,
                         seg.data, opts);
  if (drop) {
    ctr.tcp_debug_drops++;
    log("debug-drop data seg " + std::to_string(t.data_segs_sent - 1));
  } else {
    if (static_cast<std::uint8_t>(IpProto::Tcp)) ctr.tx_tcp++;
    send_ip(t.remote_ip, IpProto::Tcp, bytes);
  }
  if (first && !t.timing) {
    t.timing = true;
    t.timed_seq = seg.seq + seg.sequence_length();
    t.timed_at = clock.now();
  }
  if (first && !seg.data.empty()) {
    if (!have_goodput_start) {
      have_goodput_start = true;
      goodput_start = clock.now();
    }
    burst_on_tx(clock.now());
  }
  seg.tx_count++;
  trace_ev(&t, "tx", drop ? "drop" : "segment", flags, seg.seq, t.rcv_nxt,
           static_cast<std::uint32_t>(seg.data.size()), win);
  tcp_arm_rto(t, !first);
}

void Stack::Impl::tcp_retransmit(Tcb& t) {
  if (t.inflight.empty()) return;
  tcp_transmit(t, t.inflight.front());
}

void Stack::Impl::tcp_send_pure_ack(Tcb& t) {
  const std::uint16_t win = adv_window(t, false);
  t.last_adv = free_rx(t);
  auto bytes = build_tcp(t.local_ip, t.remote_ip, t.local_port, t.remote_port, t.snd_nxt, t.rcv_nxt, kAck, win, {}, {});
  ctr.tx_tcp++;
  send_ip(t.remote_ip, IpProto::Tcp, bytes);
  trace_ev(&t, "tx", "segment", kAck, t.snd_nxt, t.rcv_nxt, 0, win);
  t.ack_now = false;
  t.ack_timer = false;
  t.ack_delay_count = 0;
}

void Stack::Impl::tcp_send_rst_closed(Ipv4 local, Ipv4 remote, const TcpSegView& seg) {
  std::uint32_t seq = 0;
  std::uint32_t ack = 0;
  std::uint8_t flags = kRst;
  if (seg.flags & kAck) {
    seq = seg.ack;
  } else {
    flags = static_cast<std::uint8_t>(kRst | kAck);
    const std::uint32_t seglen = static_cast<std::uint32_t>(seg.payload.size()) + ((seg.flags & kSyn) ? 1u : 0u) +
                                 ((seg.flags & kFin) ? 1u : 0u);
    ack = seg.seq + std::max<std::uint32_t>(seglen, 1);
  }
  auto bytes = build_tcp(local, remote, seg.dst, seg.src, seq, ack, flags, 0, {}, {});
  ctr.tx_tcp++;
  send_ip(remote, IpProto::Tcp, bytes);
}

void Stack::Impl::tcp_reset(Tcb& t) {
  if (t.state != TcpState::Closed && t.state != TcpState::SynSent) {
    auto bytes = build_tcp(t.local_ip, t.remote_ip, t.local_port, t.remote_port, t.snd_nxt, t.rcv_nxt, kRst | kAck, 0,
                           {}, {});
    ctr.tx_tcp++;
    send_ip(t.remote_ip, IpProto::Tcp, bytes);
  }
  t.reset_flag = true;
  t.state = TcpState::Closed;
  t.rto_armed = false;
  t.inflight.clear();
}

void Stack::Impl::tcp_accept_fin(Tcb& t) {
  if (t.peer_fin) return;
  t.peer_fin = true;
  t.rcv_nxt += 1;
  tcp_schedule_ack(t, true);
  switch (t.state) {
    case TcpState::Established:
      t.state = TcpState::CloseWait;
      break;
    case TcpState::FinWait1:
      t.state = TcpState::Closing;
      break;
    case TcpState::FinWait2:
      t.state = TcpState::TimeWait;
      t.timewait_deadline = clock.now() + cfg.time_wait;
      break;
    default:
      break;
  }
}

void Stack::Impl::tcp_drain(Tcb& t) {
  bool progress = true;
  while (progress) {
    progress = false;
    for (std::size_t i = 0; i < t.ooo.size();) {
      auto& o = t.ooo[i];
      const std::uint32_t end = o.seq + static_cast<std::uint32_t>(o.data.size());
      if (o.fin && end == t.rcv_nxt && seq_le(o.seq, t.rcv_nxt)) {
        t.ooo.erase(t.ooo.begin() + static_cast<std::ptrdiff_t>(i));
        tcp_accept_fin(t);
        progress = true;
        break;
      }
      if (seq_le(end, t.rcv_nxt) && !(o.fin && end == t.rcv_nxt)) {
        t.ooo.erase(t.ooo.begin() + static_cast<std::ptrdiff_t>(i));
        progress = true;
        continue;
      }
      if (o.data.empty() && o.fin && o.seq == t.rcv_nxt) {
        t.ooo.erase(t.ooo.begin() + static_cast<std::ptrdiff_t>(i));
        tcp_accept_fin(t);
        progress = true;
        break;
      }
      if (seq_le(o.seq, t.rcv_nxt) && seq_lt(t.rcv_nxt, end)) {
        const std::uint32_t skip = t.rcv_nxt - o.seq;
        const auto chunk = std::span<const std::uint8_t>(o.data).subspan(skip);
        if (t.app_rx.size() + chunk.size() > cfg.rx_buf) return;
        t.app_rx.append(chunk);
        t.rcv_nxt = end;
        const bool fin = o.fin;
        t.ooo.erase(t.ooo.begin() + static_cast<std::ptrdiff_t>(i));
        if (fin) tcp_accept_fin(t);
        progress = true;
        break;
      }
      ++i;
    }
  }
}

void Stack::Impl::tcp_ingest(Tcb& t, std::uint32_t seq, std::vector<std::uint8_t> data, bool fin) {
  if (t.state != TcpState::Established && t.state != TcpState::FinWait1 && t.state != TcpState::FinWait2 &&
      t.state != TcpState::CloseWait) {
    // Still accept data that was in the window for the synchronized states above.
  }
  if (t.peer_fin && seq_ge(seq, t.rcv_nxt)) {
    tcp_schedule_ack(t, true);
    return;
  }
  std::uint32_t end = seq + static_cast<std::uint32_t>(data.size());
  if (seq_lt(seq, t.rcv_nxt)) {
    const std::uint32_t skip = t.rcv_nxt - seq;
    if (skip >= data.size()) {
      if (fin && t.rcv_nxt == end) tcp_accept_fin(t);
      tcp_schedule_ack(t, true);
      return;
    }
    data.erase(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(skip));
    seq = t.rcv_nxt;
    end = seq + static_cast<std::uint32_t>(data.size());
  }
  const std::uint32_t win_end = t.rcv_nxt + free_rx(t);
  if (!data.empty() && seq_ge(seq, win_end)) {
    tcp_schedule_ack(t, true);
    return;
  }
  if (seq_gt(end, win_end)) {
    data.resize(win_end - seq);
    end = seq + static_cast<std::uint32_t>(data.size());
    fin = false;
  }
  const bool in_order = (seq == t.rcv_nxt) || data.empty();
  if (seq == t.rcv_nxt) {
    if (!data.empty()) {
      t.app_rx.append(data);
      t.rcv_nxt += static_cast<std::uint32_t>(data.size());
    }
    if (fin && t.rcv_nxt == end) tcp_accept_fin(t);
    tcp_drain(t);
    tcp_schedule_ack(t, fin);
  } else if (!data.empty() || fin) {
    if (t.ooo.size() < 128) t.ooo.push_back(OooSeg{seq, std::move(data), fin});
    tcp_schedule_ack(t, true);  // duplicate ACK, immediate: fast retransmit depends on it
  }
  (void)in_order;
}

void Stack::Impl::tcp_apply_ack(Tcb& t, const TcpSegView& seg) {
  if (!(seg.flags & kAck)) return;
  if (seq_gt(seg.ack, t.snd_nxt)) {
    tcp_schedule_ack(t, true);
    return;
  }
  const bool syn_seg = (seg.flags & kSyn) != 0;
  const std::uint32_t wnd = syn_seg ? seg.window : (std::uint32_t(seg.window) << t.snd_scale);
  const bool win_changed = wnd != t.snd_wnd;
  const std::uint32_t old_una = t.snd_una;
  const std::uint32_t flight = t.snd_nxt - t.snd_una;

  if (seq_gt(seg.ack, t.snd_una)) {
    const std::uint32_t acked_payload = payload_between(t, old_una, seg.ack);
    const bool was_recovery = t.in_recovery;
    const std::uint32_t recover = t.recover;
    while (!t.inflight.empty()) {
      auto& front = t.inflight.front();
      const std::uint32_t end = front.seq + front.sequence_length();
      if (seq_le(end, seg.ack)) {
        t.inflight.pop_front();
        continue;
      }
      if (seq_lt(front.seq, seg.ack)) {
        std::uint32_t trim = seg.ack - front.seq;
        if (front.syn && trim > 0) {
          front.syn = false;
          front.seq += 1;
          trim -= 1;
        }
        if (trim > 0 && trim <= front.data.size()) {
          front.data.erase(front.data.begin(), front.data.begin() + static_cast<std::ptrdiff_t>(trim));
          front.seq += trim;
        }
      }
      break;
    }
    t.snd_una = seg.ack;
    if (t.timing && seq_ge(seg.ack, t.timed_seq)) {
      const double r = std::chrono::duration<double>(clock.now() - t.timed_at).count();
      t.rtt.sample(r);
      t.timing = false;
      if (!t.have_min_rtt || r < t.min_rtt) {
        t.min_rtt = r;
        t.have_min_rtt = true;
      }
    }
    if (acked_payload > 0) {
      payload_acked += acked_payload;
      ctr.bytes_acked += acked_payload;
      goodput_end = clock.now();
      if (!burst_active) {
        burst_active = true;
        burst_start = clock.now();
      }
      burst_bytes += acked_payload;
      burst_end = clock.now();
      if (!have_goodput_start) {
        have_goodput_start = true;
        goodput_start = clock.now();
      }
    }
    t.dup_acks = 0;
    t.limited_extra = 0;
    t.timeout_strikes = 0;
    if (was_recovery) {
      if (seq_ge(seg.ack, recover)) {
        t.in_recovery = false;
        if (t.cc) t.cc->on_exit_fast_recovery();
        trace_ev(&t, "rx", "recovery_exit", seg.flags, seg.seq, seg.ack, 0, seg.window);
      } else if (t.cc) {
        t.cc->on_partial_ack(acked_payload);
        tcp_retransmit(t);
      }
    } else if (t.cc && acked_payload > 0) {
      t.cc->on_ack(acked_payload, t.rtt.have() ? t.rtt.srtt() : 0.0, now_sec());
    }
    if (t.fin_sent && seq_ge(t.snd_una, t.fin_seq + 1)) {
      if (t.state == TcpState::FinWait1) {
        t.state = TcpState::FinWait2;
        t.finwait2_armed = true;
        t.finwait2_deadline = clock.now() + cfg.time_wait;
      } else if (t.state == TcpState::Closing) {
        t.state = TcpState::TimeWait;
        t.timewait_deadline = clock.now() + cfg.time_wait;
      } else if (t.state == TcpState::LastAck) {
        t.state = TcpState::Closed;
      }
    }
    tcp_arm_rto(t, true);
    tcp_check_loss(t);
    (void)flight;
  } else if (seg.ack == t.snd_una) {
    const bool pure = seg.payload.empty() && !(seg.flags & (kFin | kSyn)) && !win_changed && flight > 0 &&
                      !t.inflight.empty();
    const bool head_is_syn = !t.inflight.empty() && t.inflight.front().syn && t.inflight.front().data.empty() &&
                             !t.inflight.front().fin;
    if (pure && !head_is_syn) {
      if (!t.in_recovery) {
        t.dup_acks++;
        if (t.dup_acks < 3) {
          t.limited_extra += t.snd_mss;  // RFC 3042 limited transmit
        } else if (t.dup_acks == 3) {
          const std::uint32_t end =
              t.inflight.empty() ? t.snd_una : t.inflight.front().seq + t.inflight.front().sequence_length();
          tcp_note_loss(t, true, end);
          t.in_recovery = true;
          t.limited_extra = 0;
          t.recover = t.snd_nxt;
          if (t.cc) t.cc->on_enter_fast_recovery(flight, now_sec());
          tcp_trace_loss(t, true);
          t.fast_retx++;
          ctr.tcp_fast_retx++;
          tcp_retransmit(t);
          tcp_arm_rto(t, true);
        }
      } else {
        t.dup_acks++;
        if (t.cc) t.cc->on_dup_ack();
      }
    }
  }

  if (seq_lt(t.snd_wl1, seg.seq) || (seg.seq == t.snd_wl1 && seq_le(t.snd_wl2, seg.ack))) {
    t.snd_wnd = wnd;
    t.snd_wl1 = seg.seq;
    t.snd_wl2 = seg.ack;
  }
}

void Stack::Impl::tcp_output(const std::shared_ptr<Tcb>& tp) {
  if (!tp) return;
  Tcb& t = *tp;
  if (t.state == TcpState::Closed) return;
  bool sent_data = false;
  const bool can_data = t.state == TcpState::Established || t.state == TcpState::CloseWait ||
                        (t.state == TcpState::FinWait1 && !t.fin_sent);
  while (can_data && !t.unsent.empty()) {
    const std::uint32_t flight = t.snd_nxt - t.snd_una;
    const std::uint32_t cwnd = t.cc ? t.cc->cwnd() : t.snd_mss;
    const std::uint32_t budget_wnd = std::min(cwnd, t.snd_wnd) + t.limited_extra;
    if (flight >= budget_wnd) break;
    std::uint32_t room = budget_wnd - flight;
    if (room == 0) break;
    const std::size_t n = std::min({static_cast<std::size_t>(room), static_cast<std::size_t>(t.snd_mss), t.unsent.size()});
    if (n == 0) break;
    TxSeg seg;
    seg.seq = t.snd_nxt;
    seg.data = t.unsent.take(n);
    seg.psh = t.unsent.empty();
    seg.ack = true;
    t.snd_nxt += static_cast<std::uint32_t>(n);
    if (t.limited_extra >= n) t.limited_extra -= static_cast<std::uint32_t>(n);
    else t.limited_extra = 0;
    t.inflight.push_back(std::move(seg));
    tcp_transmit(t, t.inflight.back());
    sent_data = true;
  }
  if (t.fin_pending && !t.fin_sent && t.unsent.empty() &&
      (t.state == TcpState::Established || t.state == TcpState::CloseWait || t.state == TcpState::SynReceived)) {
    const std::uint32_t flight = t.snd_nxt - t.snd_una;
    const std::uint32_t cwnd = t.cc ? t.cc->cwnd() : t.snd_mss;
    const std::uint32_t limit = std::min(cwnd, t.snd_wnd);
    if (t.snd_wnd > flight && flight < limit) {
      TxSeg seg;
      seg.seq = t.snd_nxt;
      seg.fin = true;
      seg.ack = true;
      t.fin_seq = seg.seq;
      t.fin_sent = true;
      t.snd_nxt += 1;
      if (t.state == TcpState::Established) t.state = TcpState::FinWait1;
      else if (t.state == TcpState::CloseWait) t.state = TcpState::LastAck;
      t.inflight.push_back(std::move(seg));
      tcp_transmit(t, t.inflight.back());
      sent_data = true;
    }
  }
  if (t.snd_wnd == 0 && !t.unsent.empty() && t.inflight.empty() && can_data && !t.persist_armed) {
    t.persist_armed = true;
    const auto sec = std::chrono::duration<double>(t.rtt.rto());
    t.persist_at = clock.now() + std::chrono::duration_cast<Duration>(sec);
  }
  if (sent_data) {
    t.ack_now = false;
    t.ack_timer = false;
    t.ack_delay_count = 0;
  } else if (t.ack_now && t.state != TcpState::SynSent) {
    tcp_send_pure_ack(t);
  }
}

void Stack::Impl::tcp_on_rto(const std::shared_ptr<Tcb>& tp) {
  Tcb& t = *tp;
  t.rto_armed = false;
  if (t.inflight.empty()) return;
  t.timeouts++;
  ctr.tcp_timeouts++;
  t.timeout_strikes++;
  t.in_recovery = false;
  t.dup_acks = 0;
  t.limited_extra = 0;
  const std::uint32_t flight = t.snd_nxt - t.snd_una;
  const std::uint32_t end = t.inflight.front().seq + t.inflight.front().sequence_length();
  tcp_note_loss(t, false, end);
  if (t.cc) t.cc->on_timeout(flight, now_sec());
  tcp_trace_loss(t, false);
  t.timing = false;
  t.rtt.backoff();
  if (t.timeout_strikes >= cfg.max_retries) {
    log("connection aborted after retries");
    tcp_reset(t);
    return;
  }
  tcp_retransmit(t);
  tcp_arm_rto(t, true);
}

void Stack::Impl::tcp_input(const std::shared_ptr<Tcb>& tp, const TcpSegView& seg) {
  Tcb& t = *tp;
  trace_ev(&t, "rx", "segment", seg.flags, seg.seq, seg.ack, static_cast<std::uint32_t>(seg.payload.size()), seg.window);

  if (t.state == TcpState::SynSent) {
    if (seg.flags & kAck) {
      if (seq_le(seg.ack, t.iss) || seq_gt(seg.ack, t.snd_nxt)) {
        if (!(seg.flags & kRst)) tcp_send_rst_closed(t.local_ip, t.remote_ip, seg);
        return;
      }
    }
    if (seg.flags & kRst) {
      if (seg.flags & kAck) tcp_reset(t);
      return;
    }
    if (!(seg.flags & kSyn)) return;
    t.irs = seg.seq;
    t.rcv_nxt = seg.seq + 1;
    apply_options(t, seg);
    {
      // IW is N segments of the negotiated MSS. Nothing has been sent yet
      // except our SYN, so rebuilding the controller is safe.
      CongestionConfig cc;
      cc.mss = t.snd_mss;
      cc.initial_cwnd_segs = std::max<std::uint32_t>(1, cfg.initial_cwnd_segs);
      t.cc = make_congestion(cfg.congestion, cc);
    }
    t.snd_wnd = seg.window;  // SYN window is not scaled (RFC 7323)
    t.snd_wl1 = seg.seq;
    t.snd_wl2 = seg.ack;
    if (seg.flags & kAck) {
      t.snd_una = seg.ack;
      while (!t.inflight.empty()) {
        const auto end = t.inflight.front().seq + t.inflight.front().sequence_length();
        if (seq_le(end, t.snd_una)) t.inflight.pop_front();
        else break;
      }
      t.state = TcpState::Established;
      t.handshake_done = true;
      t.ack_now = true;
    } else {
      t.state = TcpState::SynReceived;  // simultaneous open
      TxSeg synack;
      synack.seq = t.iss;
      synack.syn = true;
      synack.ack = true;
      if (t.inflight.empty()) {
        t.inflight.push_back(std::move(synack));
        tcp_transmit(t, t.inflight.back());
      }
    }
    if (!seg.payload.empty() && t.state == TcpState::Established) {
      tcp_ingest(t, seg.seq + 1, std::vector<std::uint8_t>(seg.payload.begin(), seg.payload.end()),
                 (seg.flags & kFin) != 0);
    }
    tcp_output(tp);
    return;
  }

  if (t.state == TcpState::TimeWait) {
    if (seg.flags & kFin) {
      t.ack_now = true;
      t.timewait_deadline = clock.now() + cfg.time_wait;
      tcp_output(tp);
    }
    return;
  }

  const std::uint32_t wnd = free_rx(t);
  if (!acceptable_seq(t, seg, wnd) && !(t.state == TcpState::SynReceived && (seg.flags & kAck))) {
    if (!(seg.flags & kRst)) {
      t.ack_now = true;
      tcp_output(tp);
    }
    return;
  }

  if (seg.flags & kRst) {
    tcp_reset(t);
    return;
  }
  if ((seg.flags & kSyn) && t.state != TcpState::SynReceived) {
    tcp_reset(t);
    return;
  }
  if (t.state == TcpState::SynReceived && (seg.flags & kSyn) && !(seg.flags & kAck)) {
    // Retransmitted SYN: resend SYN-ACK.
    tcp_retransmit(t);
    return;
  }
  if (!(seg.flags & kAck)) return;

  if (t.state == TcpState::SynReceived) {
    if (!(seq_gt(seg.ack, t.snd_una) && seq_le(seg.ack, t.snd_nxt))) {
      tcp_send_rst_closed(t.local_ip, t.remote_ip, seg);
      return;
    }
    t.state = TcpState::Established;
    t.handshake_done = true;
    if (t.passive) {
      auto lit = listeners.find(t.listener_port);
      if (lit == listeners.end() || lit->second->dead ||
          static_cast<int>(lit->second->ready.size()) >= lit->second->backlog) {
        tcp_reset(t);
        return;
      }
      lit->second->ready.push_back(tp);
    }
  }

  tcp_apply_ack(t, seg);

  if (t.state == TcpState::Closed) return;

  const bool take_data = t.state == TcpState::Established || t.state == TcpState::FinWait1 ||
                         t.state == TcpState::FinWait2;
  if (take_data && (!seg.payload.empty() || (seg.flags & kFin))) {
    // Payload sequence starts after a SYN, which we never carry on established data.
    tcp_ingest(t, seg.seq, std::vector<std::uint8_t>(seg.payload.begin(), seg.payload.end()), (seg.flags & kFin) != 0);
  } else if ((seg.flags & kFin) && (t.state == TcpState::Closing || t.state == TcpState::LastAck)) {
    tcp_schedule_ack(t, true);
  }

  tcp_output(tp);
}

void Stack::Impl::tcp_rx(Ipv4 src, Ipv4 dst, std::span<const std::uint8_t> bytes) {
  auto seg = parse_tcp(bytes);
  if (!seg.ok) return;
  if (!transport_checksum_ok(src, dst, IpProto::Tcp, bytes)) {
    ctr.checksum_drops++;
    return;
  }
  ctr.rx_tcp++;
  const ConnKey key{seg.dst, src.host, seg.src};
  auto it = conns.find(key);
  if (it != conns.end()) {
    tcp_input(it->second, seg);
    if (it->second->state == TcpState::Closed) conns.erase(it);
    return;
  }
  if ((seg.flags & kSyn) && !(seg.flags & kAck)) {
    auto lit = listeners.find(seg.dst);
    if (lit != listeners.end() && !lit->second->dead) {
      if (static_cast<int>(lit->second->ready.size()) >= lit->second->backlog) {
        tcp_send_rst_closed(dst, src, seg);
        return;
      }
      auto t = std::make_shared<Tcb>();
      t->state = TcpState::SynReceived;
      t->passive = true;
      t->listener_port = seg.dst;
      t->local_ip = cfg.ip;
      t->remote_ip = src;
      t->local_port = seg.dst;
      t->remote_port = seg.src;
      t->iss = alloc_isn();
      t->irs = seg.seq;
      t->snd_una = t->iss;
      t->snd_nxt = t->iss;
      t->rcv_nxt = seg.seq + 1;
      t->rtt.rto_min = std::chrono::duration<double>(cfg.rto_min).count();
      apply_options(*t, seg);
      CongestionConfig cc;
      cc.mss = t->snd_mss;
      cc.initial_cwnd_segs = std::max<std::uint32_t>(1, cfg.initial_cwnd_segs);
      t->cc = make_congestion(cfg.congestion, cc);
      t->snd_wnd = seg.window;
      t->snd_wl1 = seg.seq;
      t->snd_wl2 = 0;
      TxSeg synack;
      synack.seq = t->iss;
      synack.syn = true;
      synack.ack = true;
      t->snd_nxt = t->iss + 1;
      t->inflight.push_back(std::move(synack));
      conns[key] = t;
      tcp_transmit(*t, t->inflight.back());
      tcp_arm_rto(*t, true);
      return;
    }
  }
  if (!(seg.flags & kRst)) tcp_send_rst_closed(dst, src, seg);
}

}  // namespace netstack
