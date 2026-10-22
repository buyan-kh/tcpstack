#include "netstack/congestion.hpp"

#include <algorithm>
#include <cmath>
#include <utility>

namespace netstack {
namespace {

void clamp_window(std::uint32_t& cwnd, std::uint32_t mss) {
  if (cwnd < mss) cwnd = mss;
}

class Reno final : public CongestionControl {
 public:
  explicit Reno(CongestionConfig cfg)
      : mss_(cfg.mss),
        cwnd_(cfg.mss * std::max<std::uint32_t>(1, cfg.initial_cwnd_segs)),
        ssthresh_(cfg.initial_ssthresh) {}

  std::string_view name() const override { return "reno"; }
  std::uint32_t cwnd() const override { return cwnd_; }
  std::uint32_t ssthresh() const override { return ssthresh_; }
  void set_mss(std::uint32_t mss) override { mss_ = std::max<std::uint32_t>(1, mss); }

  void on_ack(std::uint32_t acked, double, double) override {
    if (acked == 0 || mss_ == 0) return;
    if (cwnd_ < ssthresh_) {
      // Slow start with Appropriate Byte Counting, L=2 (RFC 3465).
      // Delayed ACKs cover two segments; without ABC the window would open
      // at half speed. The cap stays at 2*SMSS per ACK.
      cwnd_ += std::min(acked, 2 * mss_);
      return;
    }
    // Congestion avoidance: +1 SMSS per window of acknowledged bytes.
    ca_credit_ += acked;
    while (ca_credit_ >= cwnd_ && cwnd_ > 0) {
      ca_credit_ -= cwnd_;
      cwnd_ += mss_;
    }
  }

  void on_enter_fast_recovery(std::uint32_t flight, double) override {
    ssthresh_ = std::max(flight / 2, 2 * mss_);
    cwnd_ = ssthresh_ + 3 * mss_;
    ca_credit_ = 0;
  }

  void on_dup_ack() override { cwnd_ += mss_; }

  void on_partial_ack(std::uint32_t acked) override {
    if (cwnd_ > acked) cwnd_ -= acked;
    cwnd_ += mss_;
    clamp_window(cwnd_, mss_);
  }

  void on_exit_fast_recovery() override {
    cwnd_ = std::max(ssthresh_, mss_);
    ca_credit_ = 0;
  }

  void on_timeout(std::uint32_t flight, double) override {
    ssthresh_ = std::max(flight / 2, 2 * mss_);
    cwnd_ = mss_;
    ca_credit_ = 0;
  }

 private:
  std::uint32_t mss_;
  std::uint32_t cwnd_;
  std::uint32_t ssthresh_;
  std::uint32_t ca_credit_ = 0;
};

// RFC 8312 CUBIC. Window math is in segments; the public cwnd is bytes.
// beta = 0.7, C = 0.4. Fast convergence (section 4.6) is enabled.
class Cubic final : public CongestionControl {
 public:
  explicit Cubic(CongestionConfig cfg)
      : mss_(cfg.mss),
        cwnd_(cfg.mss * std::max<std::uint32_t>(1, cfg.initial_cwnd_segs)),
        ssthresh_(cfg.initial_ssthresh) {}

  std::string_view name() const override { return "cubic"; }
  std::uint32_t cwnd() const override { return cwnd_; }
  std::uint32_t ssthresh() const override { return ssthresh_; }
  void set_mss(std::uint32_t mss) override { mss_ = std::max<std::uint32_t>(1, mss); }

  void on_ack(std::uint32_t acked, double rtt_sec, double now_sec) override {
    if (acked == 0 || mss_ == 0) return;
    if (cwnd_ < ssthresh_) {
      // Same ABC L=2 rule as Reno. CUBIC only replaces congestion avoidance.
      cwnd_ += std::min(acked, 2 * mss_);
      credit_ = 0;
      return;
    }
    if (!epoch_) begin_epoch(now_sec);
    const double cwnd_segs = static_cast<double>(cwnd_) / static_cast<double>(mss_);
    const double t = std::max(0.0, now_sec - epoch_start_);
    const double rtt = rtt_sec > 0.000001 ? rtt_sec : 0.001;
    // W_cubic(t) = C*(t - K)^3 + W_max     (RFC 8312 eq. 1)
    const double dt = t - k_;
    const double w_cubic = w_max_segs_ + kC * dt * dt * dt;
    // TCP-friendly estimate (RFC 8312 eq. 4).
    const double w_est =
        w_max_segs_ * kBeta + (3.0 * (1.0 - kBeta) / (1.0 + kBeta)) * (t / rtt);
    const double target = std::max(w_cubic, w_est);
    const double acked_segs = static_cast<double>(acked) / static_cast<double>(mss_);
    if (target > cwnd_segs && cwnd_segs > 0) {
      credit_ += (target - cwnd_segs) / cwnd_segs * acked_segs;
    } else if (cwnd_segs > 0) {
      // Cubic is below the current window: fall back to Reno's +1/window.
      credit_ += acked_segs / cwnd_segs;
    }
    while (credit_ >= 1.0) {
      cwnd_ += mss_;
      credit_ -= 1.0;
    }
  }

  void on_enter_fast_recovery(std::uint32_t flight, double now_sec) override {
    reduce(flight, now_sec);
    cwnd_ = ssthresh_ + 3 * mss_;
  }

  void on_dup_ack() override { cwnd_ += mss_; }

  void on_partial_ack(std::uint32_t acked) override {
    if (cwnd_ > acked) cwnd_ -= acked;
    cwnd_ += mss_;
    clamp_window(cwnd_, mss_);
  }

  void on_exit_fast_recovery() override {
    cwnd_ = std::max(ssthresh_, mss_);
    credit_ = 0;
  }

  void on_timeout(std::uint32_t flight, double now_sec) override {
    reduce(flight, now_sec);
    cwnd_ = mss_;
  }

 private:
  static constexpr double kC = 0.4;
  static constexpr double kBeta = 0.7;

  void reduce(std::uint32_t flight, double now_sec) {
    const double segs = static_cast<double>(std::max(flight, mss_)) / static_cast<double>(mss_);
    // Fast convergence: a flow that is not using W_max eases off further
    // so a new flow can catch up (RFC 8312 section 4.6).
    if (w_max_segs_ > 0 && segs < w_max_segs_) {
      w_max_segs_ = segs * (1.0 + kBeta) / 2.0;
    } else {
      w_max_segs_ = segs;
    }
    const auto reduced = static_cast<std::uint32_t>(std::llround(
        static_cast<double>(std::max(flight, mss_)) * kBeta));
    ssthresh_ = std::max(reduced, 2 * mss_);
    epoch_ = false;
    credit_ = 0;
    // Epoch starts at the congestion event. K is computed when CA resumes
    // and we know the post-reduction window. Stash the timestamp now.
    pending_epoch_at_ = now_sec;
    pending_epoch_ = true;
  }

  void begin_epoch(double now_sec) {
    const double cwnd_segs = static_cast<double>(cwnd_) / static_cast<double>(mss_);
    if (w_max_segs_ < cwnd_segs) w_max_segs_ = cwnd_segs;
    const double gap = std::max(0.0, w_max_segs_ - cwnd_segs);
    k_ = std::cbrt(gap / kC);
    epoch_start_ = pending_epoch_ ? pending_epoch_at_ : now_sec;
    epoch_ = true;
    pending_epoch_ = false;
    credit_ = 0;
  }

  std::uint32_t mss_;
  std::uint32_t cwnd_;
  std::uint32_t ssthresh_;
  double w_max_segs_ = 0;
  double k_ = 0;
  double epoch_start_ = 0;
  double pending_epoch_at_ = 0;
  double credit_ = 0;
  bool epoch_ = false;
  bool pending_epoch_ = false;
};

}  // namespace

std::unique_ptr<CongestionControl> make_congestion(CongestionKind kind, CongestionConfig cfg) {
  if (kind == CongestionKind::Cubic) return std::make_unique<Cubic>(cfg);
  return std::make_unique<Reno>(cfg);
}

void RttEstimator::sample(double r_sec) {
  if (r_sec < 0) r_sec = 0;
  if (!have_) {
    srtt_ = r_sec;
    rttvar_ = r_sec / 2.0;
    have_ = true;
  } else {
    const double err = srtt_ - r_sec;
    rttvar_ = 0.75 * rttvar_ + 0.25 * std::fabs(err);
    srtt_ = 0.875 * srtt_ + 0.125 * r_sec;
  }
  rto_ = std::clamp(srtt_ + 4.0 * rttvar_, rto_min, rto_max);
}

void RttEstimator::backoff() { rto_ = std::min(rto_ * 2.0, rto_max); }

}  // namespace netstack
