#pragma once

#include "netstack/stack.hpp"

#include <iostream>

namespace test {

inline netstack::Stack::Config host_config(std::uint8_t last, netstack::CongestionKind cc = netstack::CongestionKind::Reno) {
  netstack::Stack::Config c;
  c.ip = netstack::Ipv4::from_octets(10, 0, 0, last);
  c.mask = netstack::Ipv4::from_octets(255, 255, 255, 0);
  c.congestion = cc;
  c.isn = 1000u * last;
  c.time_wait = std::chrono::milliseconds(200);
  c.delayed_ack = std::chrono::milliseconds(10);
  c.rto_min = std::chrono::milliseconds(200);
  c.max_retries = 8;
  return c;
}

struct Pair {
  netstack::ManualClock clock;
  netstack::SimLink link;
  netstack::Stack a;
  netstack::Stack b;

  explicit Pair(netstack::SimConfig sim = {}, netstack::Stack::Config ca = host_config(1),
                netstack::Stack::Config cb = host_config(2))
      : link(clock, std::move(sim)), a(link.side(0), std::move(ca), clock), b(link.side(1), std::move(cb), clock) {}

  void step() {
    link.deliver();
    a.poll();
    b.poll();
    clock.advance(std::chrono::milliseconds(1));
  }

  template <typename Pred>
  bool until(Pred pred, int max_ms) {
    for (int i = 0; i < max_ms; ++i) {
      if (pred()) return true;
      step();
    }
    return pred();
  }

  void dump() const { std::cerr << a.debug_dump() << b.debug_dump(); }
};

}  // namespace test
