#include "fixture.hpp"
#include "test_harness.hpp"

#include <string>

namespace {

std::string recv_some(test::Pair& p, netstack::TcpSocket& sock, std::size_t need, int max_ms) {
  std::string out;
  p.until(
      [&] {
        std::uint8_t buf[4096];
        auto r = sock.recv(buf);
        if (r.code == netstack::IoResult::Code::Ok) out.append(reinterpret_cast<char*>(buf), r.n);
        return out.size() >= need || r.code == netstack::IoResult::Code::Closed ||
               r.code == netstack::IoResult::Code::Reset;
      },
      max_ms);
  return out;
}

}  // namespace

TEST(tcp_reliable_stream) {
  test::Pair p;
  auto listener = p.b.listen(4242);
  auto client = p.a.connect(netstack::Ipv4::from_octets(10, 0, 0, 2), 4242);
  std::unique_ptr<netstack::TcpSocket> server;
  const bool up = p.until(
      [&] {
        if (!server) server = listener->accept_nb();
        return client->established() && server != nullptr;
      },
      2000);
  if (!up) {
    p.dump();
    std::cerr << client->info().state << " failed=" << client->failed() << "\n";
  }
  EXPECT(up);

  std::string payload(100000, '\0');
  for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<char>(i & 0xff);
  std::size_t off = 0;
  std::string got;
  const bool done = p.until(
      [&] {
        if (off < payload.size()) {
          auto r = client->send(std::span<const std::uint8_t>(
              reinterpret_cast<const std::uint8_t*>(payload.data() + off), payload.size() - off));
          if (r.code == netstack::IoResult::Code::Ok) off += r.n;
        }
        if (server) {
          std::uint8_t buf[8192];
          auto r = server->recv(buf);
          if (r.code == netstack::IoResult::Code::Ok) got.append(reinterpret_cast<char*>(buf), r.n);
        }
        return got.size() == payload.size();
      },
      8000);
  if (!done) {
    p.dump();
    std::cerr << "off " << off << " got " << got.size() << " state " << client->info().state << " cwnd "
              << client->info().cwnd << "\n";
  }
  EXPECT(done);
  EXPECT(got == payload);

  const std::string reply = "ok-reply";
  server->send(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(reply.data()), reply.size()));
  auto echoed = recv_some(p, *client, reply.size(), 2000);
  EXPECT_EQ(echoed, reply);

  client->close();
  server->close();
  EXPECT(p.until([&] { return client->info().fin_sent && server->info().fin_sent; }, 2000));
  EXPECT(p.until(
      [&] {
        return client->info().state == "TIME_WAIT" || client->info().state == "CLOSED" ||
               client->info().state == "FIN_WAIT_2" || server->info().peer_closed;
      },
      2000));
}

TEST(tcp_retransmit_on_timeout) {
  netstack::SimConfig sim;
  sim.drop_if = [](int dir, std::uint64_t n, std::span<const std::uint8_t> frame) {
    (void)frame;
    // Drop a single early data-bearing frame from A after the handshake.
    // Handshake is ARP + SYN, so the first sizable frame is later. We drop
    // by direction count in the test below using a mutable counter instead.
    (void)dir;
    (void)n;
    return false;
  };
  auto ca = test::host_config(1);
  ca.drop_data_seg = 0;
  test::Pair p(sim, ca, test::host_config(2));
  auto listener = p.b.listen(7);
  auto client = p.a.connect(netstack::Ipv4::from_octets(10, 0, 0, 2), 7);
  std::unique_ptr<netstack::TcpSocket> server;
  EXPECT(p.until(
      [&] {
        if (!server) server = listener->accept_nb();
        return client->established() && server;
      },
      2000));
  const std::string msg(100, 'R');
  auto sent = client->send(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size()));
  EXPECT(sent.code == netstack::IoResult::Code::Ok);
  std::string got;
  const bool done = p.until(
      [&] {
        std::uint8_t buf[256];
        auto r = server->recv(buf);
        if (r.code == netstack::IoResult::Code::Ok) got.append(reinterpret_cast<char*>(buf), r.n);
        return got.size() == msg.size();
      },
      5000);
  if (!done) {
    p.dump();
    std::cerr << p.a.summary_json() << "\n";
  }
  EXPECT(done);
  EXPECT(got == msg);
  EXPECT(p.a.counters().tcp_timeouts >= 1);
  EXPECT(client->info().timeouts >= 1);
}

TEST(tcp_fast_retransmit) {
  auto ca = test::host_config(1);
  ca.drop_data_seg = 0;
  ca.initial_cwnd_segs = 10;
  test::Pair p({}, ca, test::host_config(2));
  auto listener = p.b.listen(9);
  auto client = p.a.connect(netstack::Ipv4::from_octets(10, 0, 0, 2), 9);
  std::unique_ptr<netstack::TcpSocket> server;
  EXPECT(p.until(
      [&] {
        if (!server) server = listener->accept_nb();
        return client->established() && server;
      },
      2000));
  // More than one window of MSS so several segments are in flight and three
  // duplicate ACKs can form after the first one is dropped.
  std::string msg(20 * 1460, 'F');
  std::size_t off = 0;
  std::string got;
  const bool done = p.until(
      [&] {
        if (off < msg.size()) {
          auto r = client->send(std::span<const std::uint8_t>(
              reinterpret_cast<const std::uint8_t*>(msg.data() + off), msg.size() - off));
          if (r.code == netstack::IoResult::Code::Ok) off += r.n;
        }
        std::uint8_t buf[8192];
        auto r = server->recv(buf);
        if (r.code == netstack::IoResult::Code::Ok) got.append(reinterpret_cast<char*>(buf), r.n);
        return got.size() == msg.size();
      },
      8000);
  if (!done) {
    p.dump();
    std::cerr << p.a.summary_json() << "\n";
  }
  EXPECT(done);
  EXPECT(p.a.counters().tcp_fast_retx >= 1);
  EXPECT(p.a.counters().tcp_debug_drops == 1);
  auto losses = p.a.loss_samples();
  EXPECT(!losses.empty());
  EXPECT(losses[0].fast);
  EXPECT(losses[0].got_rexmit_ack);
}

TEST(tcp_recovers_under_random_loss) {
  netstack::SimConfig sim;
  sim.loss_prob = 0.03;
  sim.delay = std::chrono::milliseconds(2);
  sim.seed = 7;
  test::Pair p(sim);
  auto listener = p.b.listen(15);
  auto client = p.a.connect(netstack::Ipv4::from_octets(10, 0, 0, 2), 15);
  std::unique_ptr<netstack::TcpSocket> server;
  EXPECT(p.until(
      [&] {
        if (!server) server = listener->accept_nb();
        return (client->established() && server) || client->failed();
      },
      8000));
  EXPECT(client->established());
  std::string msg(40000, 'L');
  for (std::size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<char>(i * 17);
  std::size_t off = 0;
  std::string got;
  const bool done = p.until(
      [&] {
        if (client->failed()) return true;
        if (off < msg.size()) {
          auto r = client->send(std::span<const std::uint8_t>(
              reinterpret_cast<const std::uint8_t*>(msg.data() + off), msg.size() - off));
          if (r.code == netstack::IoResult::Code::Ok) off += r.n;
        }
        std::uint8_t buf[8192];
        auto r = server->recv(buf);
        if (r.code == netstack::IoResult::Code::Ok) got.append(reinterpret_cast<char*>(buf), r.n);
        return got.size() == msg.size();
      },
      20000);
  if (!done) {
    p.dump();
    std::cerr << p.a.summary_json() << "\n";
  }
  EXPECT(done);
  EXPECT(got == msg);
  EXPECT(p.a.counters().tcp_retx >= 1);
}

TEST(tcp_out_of_order_delivery) {
  netstack::SimConfig sim;
  int data_seen = 0;
  sim.delay_if = [&](int dir, std::uint64_t, std::span<const std::uint8_t> frame) -> netstack::Duration {
    if (dir != 0 || frame.size() < 14 + 40) return netstack::Duration::zero();
    const auto* ip = frame.data() + 14;
    if (ip[9] != 6) return netstack::Duration::zero();
    const int ihl = (ip[0] & 0x0f) * 4;
    const auto* tcp = ip + ihl;
    const int doff = (tcp[12] >> 4) * 4;
    const int payload = static_cast<int>(frame.size()) - (14 + ihl + doff);
    if (payload <= 0) return netstack::Duration::zero();
    data_seen++;
    if (data_seen == 1) return std::chrono::milliseconds(40);
    return netstack::Duration::zero();
  };
  test::Pair p(std::move(sim));
  auto listener = p.b.listen(11);
  auto client = p.a.connect(netstack::Ipv4::from_octets(10, 0, 0, 2), 11);
  std::unique_ptr<netstack::TcpSocket> server;
  EXPECT(p.until(
      [&] {
        if (!server) server = listener->accept_nb();
        return client->established() && server;
      },
      2000));
  std::string msg(8000, 'O');
  for (std::size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<char>(i & 0xff);
  std::size_t off = 0;
  std::string got;
  EXPECT(p.until(
      [&] {
        if (off < msg.size()) {
          auto r = client->send(std::span<const std::uint8_t>(
              reinterpret_cast<const std::uint8_t*>(msg.data() + off), msg.size() - off));
          if (r.code == netstack::IoResult::Code::Ok) off += r.n;
        }
        std::uint8_t buf[4096];
        auto r = server->recv(buf);
        if (r.code == netstack::IoResult::Code::Ok) got.append(reinterpret_cast<char*>(buf), r.n);
        return got == msg;
      },
      5000));
  EXPECT(got == msg);
}
