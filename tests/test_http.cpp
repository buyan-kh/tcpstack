#include "fixture.hpp"
#include "netstack/http.hpp"
#include "test_harness.hpp"

TEST(http_parser_splits_across_feeds) {
  netstack::HttpParser p;
  const std::string a = "GET /health HTTP/1.1\r\nHost: x\r\n";
  const std::string b = "Connection: close\r\n\r\n";
  p.feed(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(a.data()), a.size()));
  EXPECT(!p.complete());
  p.feed(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(b.data()), b.size()));
  EXPECT(p.complete());
  auto req = p.take();
  EXPECT_EQ(req.method, std::string("GET"));
  EXPECT_EQ(req.target, std::string("/health"));
  EXPECT_EQ(req.header("Host"), std::string("x"));
  EXPECT_EQ(req.header("connection"), std::string("close"));
}

TEST(http_get_over_tcp) {
  test::Pair p;
  auto listener = p.b.listen(80);
  netstack::HttpApp app(p.b);
  auto client = p.a.connect(netstack::Ipv4::from_octets(10, 0, 0, 2), 80);
  const char* req = "GET /health HTTP/1.1\r\nHost: 10.0.0.2\r\nConnection: close\r\n\r\n";
  bool sent = false;
  std::string resp;
  const bool done = p.until(
      [&] {
        app.service(*listener);
        if (client->established() && !sent) {
          auto r = client->send(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(req),
                                                             std::char_traits<char>::length(req)));
          if (r.code == netstack::IoResult::Code::Ok && r.n > 0) sent = true;
        }
        std::uint8_t buf[2048];
        auto r = client->recv(buf);
        if (r.code == netstack::IoResult::Code::Ok) resp.append(reinterpret_cast<char*>(buf), r.n);
        return resp.find("\r\n\r\nok\n") != std::string::npos;
      },
      4000);
  if (!done) {
    p.dump();
    std::cerr << resp << "\n";
  }
  EXPECT(done);
  EXPECT(resp.find("HTTP/1.1 200") != std::string::npos);
  EXPECT(app.requests() >= 1);
}
