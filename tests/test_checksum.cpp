#include "netstack/checksum.hpp"
#include "netstack/congestion.hpp"
#include "test_harness.hpp"

#include <cmath>
#include <vector>

TEST(checksum_rfc1071_vector) {
  const std::uint8_t data[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
  EXPECT_EQ(netstack::internet_checksum(data), 0x220d);
}

TEST(checksum_roundtrip_detects_a_flipped_bit) {
  std::vector<std::uint8_t> bytes{0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01,
                                  0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02};
  const auto csum = netstack::internet_checksum(bytes);
  bytes[10] = static_cast<std::uint8_t>(csum >> 8);
  bytes[11] = static_cast<std::uint8_t>(csum);
  EXPECT(netstack::checksum_valid(bytes));
  bytes[19] ^= 0x01;
  EXPECT(!netstack::checksum_valid(bytes));
}

TEST(seq_comparison_handles_wrap) {
  EXPECT(netstack::seq_lt(0xfffffff0u, 0x10u));
  EXPECT(netstack::seq_gt(0x10u, 0xfffffff0u));
  EXPECT(netstack::seq_le(5u, 5u));
  EXPECT(!netstack::seq_lt(5u, 5u));
}

TEST(rtt_estimator_jacobson_karels) {
  netstack::RttEstimator r;
  r.rto_min = 0.0;
  r.sample(0.100);
  EXPECT(std::fabs(r.srtt() - 0.100) < 1e-9);
  EXPECT(std::fabs(r.rttvar() - 0.050) < 1e-9);
  EXPECT(std::fabs(r.rto() - 0.300) < 1e-9);
  r.sample(0.100);
  // srtt stays 0.1, rttvar = 0.75*0.05 + 0.25*0 = 0.0375, rto = 0.25
  EXPECT(std::fabs(r.srtt() - 0.100) < 1e-9);
  EXPECT(std::fabs(r.rttvar() - 0.0375) < 1e-9);
  EXPECT(std::fabs(r.rto() - 0.250) < 1e-9);
  const double backed = r.rto();
  r.backoff();
  EXPECT(std::fabs(r.rto() - backed * 2) < 1e-9);
  EXPECT(std::fabs(r.srtt() - 0.100) < 1e-9);
}

TEST(reno_slow_start_and_congestion_avoidance) {
  netstack::CongestionConfig cfg;
  cfg.mss = 1000;
  cfg.initial_cwnd_segs = 10;
  cfg.initial_ssthresh = 10 * 1000;  // already at the threshold, so ACKs are CA
  auto reno = netstack::make_congestion(netstack::CongestionKind::Reno, cfg);
  EXPECT_EQ(reno->cwnd(), 10000u);
  for (int i = 0; i < 10; ++i) reno->on_ack(1000, 0.01, 0);
  EXPECT_EQ(reno->cwnd(), 11000u);

  netstack::CongestionConfig ss = cfg;
  ss.initial_ssthresh = 1000000;
  auto slow = netstack::make_congestion(netstack::CongestionKind::Reno, ss);
  slow->on_ack(1000, 0.01, 0);
  EXPECT_EQ(slow->cwnd(), 11000u);
  slow->on_ack(2000, 0.01, 0);  // ABC L=2 caps a single ACK at 2*MSS
  EXPECT_EQ(slow->cwnd(), 13000u);
}

TEST(reno_fast_recovery_and_timeout) {
  netstack::CongestionConfig cfg;
  cfg.mss = 1000;
  cfg.initial_cwnd_segs = 20;
  auto reno = netstack::make_congestion(netstack::CongestionKind::Reno, cfg);
  const std::uint32_t flight = 20 * 1000;
  reno->on_enter_fast_recovery(flight, 0);
  EXPECT_EQ(reno->ssthresh(), 10000u);
  EXPECT_EQ(reno->cwnd(), 13000u);
  reno->on_dup_ack();
  EXPECT_EQ(reno->cwnd(), 14000u);
  reno->on_exit_fast_recovery();
  EXPECT_EQ(reno->cwnd(), 10000u);
  reno->on_timeout(flight, 0);
  EXPECT_EQ(reno->cwnd(), 1000u);
  EXPECT_EQ(reno->ssthresh(), 10000u);
}

TEST(cubic_returns_toward_wmax_then_grows_past_it) {
  netstack::CongestionConfig cfg;
  cfg.mss = 1000;
  cfg.initial_cwnd_segs = 14;  // beta * 20
  cfg.initial_ssthresh = 14000;
  auto cubic = netstack::make_congestion(netstack::CongestionKind::Cubic, cfg);
  cubic->on_enter_fast_recovery(20000, 0.0);
  cubic->on_exit_fast_recovery();
  const auto after = cubic->cwnd();
  EXPECT(after < 20000u);
  // Sit at the inflection (K) and acknowledge a window repeatedly.
  // K = cbrt((Wmax - cwnd) / C). Drive time forward to well past K.
  for (int i = 0; i < 80; ++i) {
    cubic->on_ack(1000, 0.05, 5.0);
  }
  EXPECT(cubic->cwnd() > after);
  const auto mid = cubic->cwnd();
  for (int i = 0; i < 80; ++i) cubic->on_ack(1000, 0.05, 12.0);
  EXPECT(cubic->cwnd() > mid);
}
