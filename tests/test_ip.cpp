#include "fixture.hpp"
#include "test_harness.hpp"

#include <string>

TEST(arp_and_icmp_echo) {
  test::Pair p;
  const std::vector<std::uint8_t> payload{'p', 'i', 'n', 'g'};
  p.a.ping_send(netstack::Ipv4::from_octets(10, 0, 0, 2), 7, payload);
  const bool got = p.until([&] { return p.a.ping_take(7).has_value(); }, 500);
  if (!got) p.dump();
  EXPECT(got);
  p.a.ping_send(netstack::Ipv4::from_octets(10, 0, 0, 2), 7, payload);
  EXPECT(p.until([&] { return p.a.ping_take(7).has_value(); }, 500));
  EXPECT(p.a.counters().rx_icmp >= 1);
  EXPECT(p.b.counters().tx_icmp >= 1);
}

TEST(udp_echo_and_port_unreachable) {
  test::Pair p;
  auto server = p.b.udp_bind(9000);
  auto client = p.a.udp_bind(9001);
  EXPECT(server && client);
  const std::uint8_t msg[] = {'h', 'e', 'l', 'l', 'o'};
  EXPECT(client->send_to(netstack::Ipv4::from_octets(10, 0, 0, 2), 9000, msg).code == netstack::IoResult::Code::Ok);
  EXPECT(p.until([&] { return server->recv_from().has_value(); }, 500));
  // Drain the one we just observed by receiving again after a fresh send.
  client->send_to(netstack::Ipv4::from_octets(10, 0, 0, 2), 9000, msg);
  auto dg = std::optional<netstack::UdpSocket::Datagram>{};
  EXPECT(p.until(
      [&] {
        dg = server->recv_from();
        return dg.has_value();
      },
      500));
  EXPECT(dg);
  EXPECT_EQ(dg->data.size(), 5u);
  EXPECT_EQ(dg->port, 9001);
  EXPECT(dg->data[0] == 'h');

  auto stray = p.a.udp_bind(9002);
  stray->send_to(netstack::Ipv4::from_octets(10, 0, 0, 2), 9, msg);
  EXPECT(p.until([&] { return p.a.counters().rx_icmp >= 1; }, 500));
}

TEST(ipv4_fragmentation_round_trip) {
  netstack::SimConfig sim;
  sim.mtu = 200;
  test::Pair p(sim);
  auto server = p.b.udp_bind(5000);
  auto client = p.a.udp_bind(5001);
  std::vector<std::uint8_t> payload(1000);
  for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::uint8_t>(i);
  client->send_to(netstack::Ipv4::from_octets(10, 0, 0, 2), 5000, payload);
  std::optional<netstack::UdpSocket::Datagram> dg;
  const bool got = p.until(
      [&] {
        dg = server->recv_from();
        return dg.has_value();
      },
      1000);
  if (!got) p.dump();
  EXPECT(got);
  EXPECT_EQ(dg->data.size(), payload.size());
  EXPECT(dg->data == payload);
  EXPECT(p.b.counters().frag_reassembled >= 1);
}
