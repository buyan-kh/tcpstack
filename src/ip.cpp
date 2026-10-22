#include "net_priv.hpp"

#include <algorithm>
#include <cstring>
#include <iostream>

namespace netstack {
namespace {

constexpr std::uint16_t kArpRequest = 1;
constexpr std::uint16_t kArpReply = 2;

}  // namespace

void Stack::Impl::log(std::string_view msg) const {
  if (verbose) std::cerr << "netstack: " << msg << '\n';
}

bool Stack::Impl::on_link(Ipv4 dst) const {
  return (dst.host & cfg.mask.host) == (cfg.ip.host & cfg.mask.host);
}

Ipv4 Stack::Impl::next_hop_for(Ipv4 dst) const {
  if (cfg.gateway.host != 0 && !on_link(dst)) return cfg.gateway;
  return dst;
}

void Stack::Impl::arp_learn(Ipv4 ip, Mac mac_addr) {
  if (ip.host == 0) return;
  arp[ip.host] = ArpEnt{mac_addr, clock.now() + std::chrono::seconds(60)};
}

void Stack::Impl::send_frame(Mac dst, std::uint16_t ethertype, std::span<const std::uint8_t> payload) {
  std::vector<std::uint8_t> frame(std::max<std::size_t>(60, 14 + payload.size()));
  std::memcpy(frame.data(), dst.b.data(), 6);
  std::memcpy(frame.data() + 6, mac.b.data(), 6);
  wr16(frame.data() + 12, ethertype);
  if (!payload.empty()) {
    std::memcpy(frame.data() + 14, payload.data(), payload.size());
  }
  pcap_write(frame, false);
  ctr.tx_frames++;
  dev.send(frame);
}

void Stack::Impl::arp_request(Ipv4 target) {
  std::uint8_t body[28] = {};
  wr16(body, 1);
  wr16(body + 2, 0x0800);
  body[4] = 6;
  body[5] = 4;
  wr16(body + 6, kArpRequest);
  std::memcpy(body + 8, mac.b.data(), 6);
  wr32(body + 14, cfg.ip.host);
  wr32(body + 24, target.host);
  ctr.tx_arp++;
  send_frame(Mac::broadcast(), static_cast<std::uint16_t>(EtherType::Arp), body);
}

void Stack::Impl::flush_arp(Ipv4 ip) {
  auto it = arp_wait.find(ip.host);
  if (it == arp_wait.end()) return;
  auto pending = std::move(it->second);
  arp_wait.erase(it);
  auto mac_it = arp.find(ip.host);
  if (mac_it == arp.end()) return;
  for (auto& pkt : pending.pkts) send_frame(mac_it->second.mac, static_cast<std::uint16_t>(EtherType::Ipv4), pkt);
}

void Stack::Impl::arp_rx(std::span<const std::uint8_t> body) {
  if (body.size() < 28) return;
  if (rd16(body.data()) != 1 || rd16(body.data() + 2) != 0x0800) return;
  if (body[4] != 6 || body[5] != 4) return;
  const std::uint16_t op = rd16(body.data() + 6);
  Mac sha{};
  std::memcpy(sha.b.data(), body.data() + 8, 6);
  const Ipv4 spa{rd32(body.data() + 14)};
  const Ipv4 tpa{rd32(body.data() + 24)};
  arp_learn(spa, sha);
  flush_arp(spa);
  if (op == kArpRequest && tpa.host == cfg.ip.host) {
    std::uint8_t rep[28] = {};
    wr16(rep, 1);
    wr16(rep + 2, 0x0800);
    rep[4] = 6;
    rep[5] = 4;
    wr16(rep + 6, kArpReply);
    std::memcpy(rep + 8, mac.b.data(), 6);
    wr32(rep + 14, cfg.ip.host);
    std::memcpy(rep + 18, sha.b.data(), 6);
    wr32(rep + 24, spa.host);
    ctr.tx_arp++;
    send_frame(sha, static_cast<std::uint16_t>(EtherType::Arp), rep);
  }
}

std::vector<std::uint8_t> Stack::Impl::build_ip(Ipv4 dst, IpProto proto, std::uint16_t id,
                                                std::uint16_t frag_off, bool more,
                                                std::span<const std::uint8_t> payload) const {
  std::vector<std::uint8_t> d(20 + payload.size());
  d[0] = 0x45;
  d[1] = 0;
  wr16(d.data() + 2, static_cast<std::uint16_t>(d.size()));
  wr16(d.data() + 4, id);
  std::uint16_t flags = frag_off & 0x1fff;
  if (more) flags |= 0x2000;
  wr16(d.data() + 6, flags);
  d[8] = 64;
  d[9] = static_cast<std::uint8_t>(proto);
  wr16(d.data() + 10, 0);
  wr32(d.data() + 12, cfg.ip.host);
  wr32(d.data() + 16, dst.host);
  if (!payload.empty()) std::memcpy(d.data() + 20, payload.data(), payload.size());
  wr16(d.data() + 10, internet_checksum({d.data(), 20}));
  return d;
}

void Stack::Impl::transmit_ip(Ipv4 hop, std::vector<std::uint8_t> datagram) {
  ctr.tx_ip++;
  auto it = arp.find(hop.host);
  if (it != arp.end() && it->second.exp > clock.now()) {
    send_frame(it->second.mac, static_cast<std::uint16_t>(EtherType::Ipv4), datagram);
    return;
  }
  auto& pend = arp_wait[hop.host];
  if (pend.pkts.size() < 16) pend.pkts.push_back(std::move(datagram));
  if (pend.tries == 0 || clock.now() >= pend.next) {
    arp_request(hop);
    pend.tries++;
    pend.next = clock.now() + std::chrono::seconds(1);
  }
}

void Stack::Impl::send_ip(Ipv4 dst, IpProto proto, std::span<const std::uint8_t> payload) {
  const std::size_t max_payload = mtu > 20 ? static_cast<std::size_t>(mtu - 20) : 0;
  if (max_payload == 0) return;
  const std::uint16_t id = ip_id++;
  if (payload.size() <= max_payload) {
    transmit_ip(next_hop_for(dst), build_ip(dst, proto, id, 0, false, payload));
    return;
  }
  const std::size_t frag_max = (max_payload / 8) * 8;
  if (frag_max == 0) return;
  std::size_t off = 0;
  while (off < payload.size()) {
    std::size_t n = std::min(frag_max, payload.size() - off);
    const bool last = off + n >= payload.size();
    if (!last) n -= n % 8;
    transmit_ip(next_hop_for(dst),
                build_ip(dst, proto, id, static_cast<std::uint16_t>(off / 8), !last, payload.subspan(off, n)));
    off += n;
  }
}

std::optional<std::vector<std::uint8_t>> Stack::Impl::reassemble(Ipv4 src, Ipv4 dst, std::uint16_t id,
                                                                 std::uint8_t proto, std::uint16_t offset,
                                                                 bool more, std::span<const std::uint8_t> data) {
  const std::size_t end = static_cast<std::size_t>(offset) + data.size();
  if (end > 65535) return std::nullopt;
  if (frags.size() > 64) frags.clear();
  FragKey key{src.host, dst.host, id, proto};
  auto& buf = frags[key];
  if (buf.data.empty()) buf.deadline = clock.now() + std::chrono::seconds(15);
  if (buf.data.size() < end) {
    buf.data.resize(end);
    buf.have.resize(end);
  }
  for (std::size_t i = 0; i < data.size(); ++i) {
    if (!buf.have[offset + i]) {
      buf.have[offset + i] = 1;
      buf.data[offset + i] = data[i];
      buf.n_got++;
    }
  }
  if (!more) buf.total = end;
  if (buf.total == 0 || buf.n_got < buf.total) return std::nullopt;
  std::vector<std::uint8_t> out(buf.data.begin(), buf.data.begin() + static_cast<std::ptrdiff_t>(buf.total));
  frags.erase(key);
  ctr.frag_reassembled++;
  return out;
}

void Stack::Impl::deliver_l4(Ipv4 src, Ipv4 dst, std::uint8_t proto, std::span<const std::uint8_t> payload) {
  switch (proto) {
    case static_cast<std::uint8_t>(IpProto::Icmp):
      icmp_rx(src, dst, payload);
      break;
    case static_cast<std::uint8_t>(IpProto::Udp):
      udp_rx(src, dst, payload);
      break;
    case static_cast<std::uint8_t>(IpProto::Tcp):
      tcp_rx(src, dst, payload);
      break;
    default:
      break;
  }
}

void Stack::Impl::ipv4_rx(std::span<const std::uint8_t> packet) {
  if (packet.size() < 20) return;
  const std::uint8_t vihl = packet[0];
  if ((vihl >> 4) != 4) return;
  const std::uint8_t ihl = static_cast<std::uint8_t>((vihl & 0x0f) * 4);
  if (ihl < 20 || packet.size() < ihl) return;
  const std::uint16_t total = rd16(packet.data() + 2);
  if (total < ihl || packet.size() < total) return;
  if (!checksum_valid(packet.first(ihl))) {
    ctr.checksum_drops++;
    return;
  }
  const Ipv4 src{rd32(packet.data() + 12)};
  const Ipv4 dst{rd32(packet.data() + 16)};
  if (dst.host != cfg.ip.host) return;
  if (packet[8] == 0) return;
  const std::uint16_t frag = rd16(packet.data() + 6);
  const std::uint16_t off = static_cast<std::uint16_t>((frag & 0x1fff) * 8);
  const bool more = (frag & 0x2000) != 0;
  const std::uint8_t proto = packet[9];
  const auto l4 = packet.subspan(ihl, static_cast<std::size_t>(total - ihl));
  ctr.rx_ip++;
  if (off != 0 || more) {
    auto full = reassemble(src, dst, rd16(packet.data() + 4), proto, off, more, l4);
    if (!full) return;
    deliver_l4(src, dst, proto, *full);
    return;
  }
  deliver_l4(src, dst, proto, l4);
}

void Stack::Impl::send_icmp(Ipv4 dst, std::span<const std::uint8_t> msg) {
  std::vector<std::uint8_t> m(msg.begin(), msg.end());
  if (m.size() < 4) return;
  wr16(m.data() + 2, 0);
  wr16(m.data() + 2, internet_checksum(m));
  ctr.tx_icmp++;
  send_ip(dst, IpProto::Icmp, m);
}

void Stack::Impl::send_icmp_unreach(Ipv4 dst, std::span<const std::uint8_t> quoted) {
  std::vector<std::uint8_t> m(8 + std::min<std::size_t>(quoted.size(), 28));
  m[0] = 3;
  m[1] = 3;
  std::memcpy(m.data() + 8, quoted.data(), m.size() - 8);
  send_icmp(dst, m);
}

void Stack::Impl::icmp_rx(Ipv4 src, Ipv4, std::span<const std::uint8_t> msg) {
  if (msg.size() < 8) return;
  if (!checksum_valid(msg)) {
    ctr.checksum_drops++;
    return;
  }
  ctr.rx_icmp++;
  const std::uint8_t type = msg[0];
  const std::uint8_t code = msg[1];
  if (type == 8 && code == 0) {
    std::vector<std::uint8_t> rep(msg.begin(), msg.end());
    rep[0] = 0;
    send_icmp(src, rep);
    return;
  }
  if (type == 0 && code == 0) {
    const std::uint16_t id = rd16(msg.data() + 4);
    const std::uint16_t seq = rd16(msg.data() + 6);
    if (id != ping_id) return;
    auto payload = msg.subspan(8);
    for (auto& w : pings) {
      if (w.done || w.seq != seq) continue;
      if (payload.size() != w.payload.size() ||
          std::memcmp(payload.data(), w.payload.data(), payload.size()) != 0) {
        continue;
      }
      w.done = true;
      w.rtt = std::chrono::duration_cast<Duration>(clock.now() - w.sent);
    }
  }
}

void Stack::Impl::udp_rx(Ipv4 src, Ipv4 dst, std::span<const std::uint8_t> seg) {
  if (seg.size() < 8) return;
  const std::uint16_t sp = rd16(seg.data());
  const std::uint16_t dp = rd16(seg.data() + 2);
  const std::uint16_t len = rd16(seg.data() + 4);
  const std::uint16_t csum = rd16(seg.data() + 6);
  if (len < 8 || seg.size() < len) return;
  auto exact = seg.first(len);
  if (csum != 0 && !transport_checksum_ok(src, dst, IpProto::Udp, exact)) {
    ctr.checksum_drops++;
    return;
  }
  ctr.rx_udp++;
  auto it = udp.find(dp);
  if (it == udp.end() || it->second->dead) {
    // ICMP dest unreachable quotes the original IP header + 8 bytes (RFC 792).
    std::vector<std::uint8_t> orig = build_ip(dst, IpProto::Udp, 0, 0, false, exact);
    wr32(orig.data() + 12, src.host);
    wr32(orig.data() + 16, cfg.ip.host);
    wr16(orig.data() + 10, 0);
    wr16(orig.data() + 10, internet_checksum({orig.data(), 20}));
    send_icmp_unreach(src, {orig.data(), std::min<std::size_t>(orig.size(), 28)});
    return;
  }
  if (it->second->q.size() >= 64) return;
  UdpSocket::Datagram d;
  d.src = src;
  d.port = sp;
  d.data.assign(exact.begin() + 8, exact.end());
  it->second->q.push_back(std::move(d));
}

bool Stack::Impl::ping_send(Ipv4 dst, std::uint16_t seq, std::vector<std::uint8_t> payload) {
  std::vector<std::uint8_t> msg(8 + payload.size());
  msg[0] = 8;
  wr16(msg.data() + 4, ping_id);
  wr16(msg.data() + 6, seq);
  if (!payload.empty()) std::memcpy(msg.data() + 8, payload.data(), payload.size());
  PingWait w;
  w.seq = seq;
  w.payload = std::move(payload);
  w.sent = clock.now();
  pings.push_back(std::move(w));
  send_icmp(dst, msg);
  return true;
}

std::optional<Stack::PingReply> Stack::Impl::ping_take(std::uint16_t seq) {
  for (auto it = pings.begin(); it != pings.end(); ++it) {
    if (it->seq == seq && it->done) {
      Stack::PingReply r;
      r.seq = seq;
      r.rtt = std::chrono::duration_cast<std::chrono::microseconds>(it->rtt);
      pings.erase(it);
      return r;
    }
  }
  return std::nullopt;
}

void Stack::Impl::input(std::span<const std::uint8_t> frame) {
  ctr.rx_frames++;
  pcap_write(frame, true);
  if (frame.size() < 14) return;
  Mac dst{};
  Mac srcm{};
  std::memcpy(dst.b.data(), frame.data(), 6);
  std::memcpy(srcm.b.data(), frame.data() + 6, 6);
  if (!(dst == mac || dst.is_broadcast())) return;
  (void)srcm;
  const std::uint16_t et = rd16(frame.data() + 12);
  const auto body = frame.subspan(14);
  if (et == static_cast<std::uint16_t>(EtherType::Arp)) {
    ctr.rx_arp++;
    arp_rx(body);
    return;
  }
  if (et == static_cast<std::uint16_t>(EtherType::Ipv4)) ipv4_rx(body);
}

}  // namespace netstack
