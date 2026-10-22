#pragma once

#include <cstdint>
#include <memory>
#include <string_view>

namespace netstack {

enum class CongestionKind { Reno, Cubic };

// Byte-oriented congestion window. Recovery is NewReno (RFC 6582) for both
// algorithms; the difference is the increase function and the decrease
// factor. CUBIC follows RFC 8312. PRR (RFC 6937) is intentionally not
// implemented — see docs/WALKTHROUGH.md.
class CongestionControl {
 public:
  virtual ~CongestionControl() = default;
  virtual std::string_view name() const = 0;
  virtual std::uint32_t cwnd() const = 0;
  virtual std::uint32_t ssthresh() const = 0;
  virtual void set_mss(std::uint32_t mss) = 0;

  // `acked` is newly acknowledged payload bytes (SYN/FIN excluded).
  // `rtt_sec` and `now_sec` are zero when unknown. CUBIC needs both.
  virtual void on_ack(std::uint32_t acked, double rtt_sec, double now_sec) = 0;
  virtual void on_enter_fast_recovery(std::uint32_t flight, double now_sec) = 0;
  virtual void on_dup_ack() = 0;
  virtual void on_partial_ack(std::uint32_t acked) = 0;
  virtual void on_exit_fast_recovery() = 0;
  virtual void on_timeout(std::uint32_t flight, double now_sec) = 0;
};

struct CongestionConfig {
  std::uint32_t mss = 1460;
  std::uint32_t initial_cwnd_segs = 10;  // RFC 6928
  // "Arbitrarily high" until the first loss (RFC 5681).
  std::uint32_t initial_ssthresh = 0x3fffffff;
};

std::unique_ptr<CongestionControl> make_congestion(CongestionKind kind, CongestionConfig cfg);

// Jacobson/Karels RTT estimator (RFC 6298), in seconds.
// alpha = 1/8, beta = 1/4. The RTO floor defaults to Linux's 200ms rather
// than the RFC's 1s so low-latency TAP measurements are not quantized to
// a full second. The floor is data, not part of the estimator.
class RttEstimator {
 public:
  double rto_min = 0.2;
  double rto_max = 60.0;

  bool have() const { return have_; }
  double srtt() const { return srtt_; }
  double rttvar() const { return rttvar_; }
  double rto() const { return rto_; }

  void sample(double r_sec);
  void backoff();

 private:
  bool have_ = false;
  double srtt_ = 0;
  double rttvar_ = 0;
  double rto_ = 1.0;  // RFC 6298 initial RTO, before any sample
};

}  // namespace netstack
