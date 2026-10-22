#include "netstack/device.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cstdio>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <deque>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <utility>

namespace netstack {
namespace {

void set_cloexec_nonblock(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  flags = fcntl(fd, F_GETFD, 0);
  if (flags >= 0) fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

}  // namespace

struct SimLink::Impl {
  struct Endpoint final : Device {
    Impl* link = nullptr;
    int index = 0;
    Mac hw{};
    std::deque<std::vector<std::uint8_t>> ingress;

    std::string name() const override { return index == 0 ? "sim0" : "sim1"; }
    Mac mac() const override { return hw; }
    std::uint16_t mtu() const override { return link->cfg.mtu; }

    void send(std::span<const std::uint8_t> frame) override {
      const int dir = index;
      const std::uint64_t n = link->sent_n[static_cast<std::size_t>(dir)]++;
      if (link->cfg.drop_if && link->cfg.drop_if(dir, n, frame)) return;
      if (link->cfg.loss_prob > 0) {
        std::uniform_real_distribution<double> dist(0.0, 1.0);
        if (dist(link->rng) < link->cfg.loss_prob) return;
      }
      Duration delay = link->cfg.delay;
      if (link->cfg.delay_if) delay = link->cfg.delay_if(dir, n, frame);
      InFlight item;
      item.deliver_at = link->clock.now() + delay;
      item.to = 1 - index;
      item.frame.assign(frame.begin(), frame.end());
      link->flight.push_back(std::move(item));
    }

    bool poll_frame(std::vector<std::uint8_t>& out) override {
      if (ingress.empty()) return false;
      out = std::move(ingress.front());
      ingress.pop_front();
      return true;
    }

    void wait_ms(int) override {}
  };

  struct InFlight {
    TimePoint deliver_at{};
    int to = 0;
    std::vector<std::uint8_t> frame;
  };

  explicit Impl(ClockSource& clock_in, SimConfig cfg_in)
      : clock(clock_in), cfg(std::move(cfg_in)), rng(cfg.seed) {
    ep[0].link = this;
    ep[1].link = this;
    ep[0].index = 0;
    ep[1].index = 1;
    ep[0].hw = Mac{{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}};
    ep[1].hw = Mac{{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}};
  }

  ClockSource& clock;
  SimConfig cfg;
  std::mt19937_64 rng;
  Endpoint ep[2];
  std::deque<InFlight> flight;
  std::uint64_t sent_n[2] = {0, 0};
};

SimLink::SimLink(ClockSource& clock, SimConfig cfg) : impl_(std::make_unique<Impl>(clock, std::move(cfg))) {}
SimLink::~SimLink() = default;
Device& SimLink::side(int index) { return impl_->ep[index & 1]; }
std::uint64_t SimLink::sent(int dir) const { return impl_->sent_n[dir & 1]; }

void SimLink::deliver() {
  const TimePoint now = impl_->clock.now();
  std::deque<Impl::InFlight> keep;
  for (auto& item : impl_->flight) {
    if (item.deliver_at <= now) {
      impl_->ep[item.to].ingress.push_back(std::move(item.frame));
    } else {
      keep.push_back(std::move(item));
    }
  }
  impl_->flight.swap(keep);
}

struct ImpairDevice::Impl {
  struct Held {
    TimePoint due{};
    std::vector<std::uint8_t> frame;
  };
  Device& inner;
  ClockSource& clock;
  double loss = 0;
  Duration delay = Duration::zero();
  std::mt19937_64 rng;
  std::deque<Held> outbound;
  std::deque<Held> inbound;
  std::uint64_t drops = 0;

  Impl(Device& inner_in, ClockSource& clock_in, double loss_in, Duration delay_in, std::uint64_t seed)
      : inner(inner_in), clock(clock_in), loss(loss_in), delay(delay_in), rng(seed) {}

  bool is_arp(std::span<const std::uint8_t> frame) const {
    return frame.size() >= 14 && rd16(frame.data() + 12) == static_cast<std::uint16_t>(EtherType::Arp);
  }
  bool drop_roll(std::span<const std::uint8_t> frame) {
    if (loss <= 0 || is_arp(frame)) return false;
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    if (dist(rng) < loss) {
      ++drops;
      return true;
    }
    return false;
  }
  void flush_out() {
    const TimePoint now = clock.now();
    while (!outbound.empty() && outbound.front().due <= now) {
      inner.send(outbound.front().frame);
      outbound.pop_front();
    }
  }
  void pull_in() {
    std::vector<std::uint8_t> frame;
    while (inner.poll_frame(frame)) {
      if (drop_roll(frame)) continue;
      if (delay <= Duration::zero() || is_arp(frame)) {
        inbound.push_back(Held{clock.now(), std::move(frame)});
      } else {
        inbound.push_back(Held{clock.now() + delay, std::move(frame)});
      }
    }
  }
};

ImpairDevice::ImpairDevice(Device& inner, ClockSource& clock, double loss_prob, Duration delay, std::uint64_t seed)
    : impl_(std::make_unique<Impl>(inner, clock, loss_prob, delay, seed)) {}

ImpairDevice::~ImpairDevice() = default;

std::string ImpairDevice::name() const { return impl_->inner.name(); }
Mac ImpairDevice::mac() const { return impl_->inner.mac(); }
std::uint16_t ImpairDevice::mtu() const { return impl_->inner.mtu(); }
std::uint64_t ImpairDevice::dropped() const { return impl_->drops; }

void ImpairDevice::send(std::span<const std::uint8_t> frame) {
  if (impl_->drop_roll(frame)) return;
  if (impl_->delay <= Duration::zero() || impl_->is_arp(frame)) {
    impl_->inner.send(frame);
    return;
  }
  impl_->outbound.push_back(Impl::Held{impl_->clock.now() + impl_->delay, std::vector<std::uint8_t>(frame.begin(), frame.end())});
}

bool ImpairDevice::poll_frame(std::vector<std::uint8_t>& out) {
  impl_->flush_out();
  impl_->pull_in();
  const TimePoint now = impl_->clock.now();
  for (auto it = impl_->inbound.begin(); it != impl_->inbound.end(); ++it) {
    if (it->due <= now) {
      out = std::move(it->frame);
      impl_->inbound.erase(it);
      return true;
    }
  }
  return false;
}

void ImpairDevice::wait_ms(int ms) {
  impl_->flush_out();
  impl_->pull_in();
  const TimePoint now = impl_->clock.now();
  auto slice = std::chrono::milliseconds(std::max(0, ms));
  auto consider = [&](const std::deque<Impl::Held>& q) {
    for (const auto& held : q) {
      if (held.due <= now) {
        slice = std::chrono::milliseconds(0);
        return;
      }
      const auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(held.due - now);
      if (remain < slice) slice = remain;
    }
  };
  consider(impl_->outbound);
  consider(impl_->inbound);
  if (slice.count() > 0) impl_->inner.wait_ms(static_cast<int>(slice.count()));
  impl_->flush_out();
  impl_->pull_in();
}

struct TapDevice::Impl {
  std::string name;
  Mac mac{};
  std::uint16_t mtu = 1500;
  int fd = -1;

  ~Impl() {
    if (fd >= 0) ::close(fd);
  }
};

TapDevice::TapDevice(std::string name, Mac mac, std::uint16_t mtu) : impl_(std::make_unique<Impl>()) {
  impl_->name = std::move(name);
  impl_->mac = mac;
  impl_->mtu = mtu;
  impl_->fd = ::open("/dev/net/tun", O_RDWR);
  if (impl_->fd < 0) {
    throw std::runtime_error(std::string("open /dev/net/tun: ") + std::strerror(errno));
  }
  set_cloexec_nonblock(impl_->fd);
  struct ifreq ifr {};
  std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", impl_->name.c_str());
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  if (ioctl(impl_->fd, TUNSETIFF, &ifr) < 0) {
    throw std::runtime_error(std::string("TUNSETIFF: ") + std::strerror(errno));
  }
  impl_->name = ifr.ifr_name;
}

TapDevice::~TapDevice() = default;
std::string TapDevice::name() const { return impl_->name; }
Mac TapDevice::mac() const { return impl_->mac; }
std::uint16_t TapDevice::mtu() const { return impl_->mtu; }

void TapDevice::send(std::span<const std::uint8_t> frame) {
  const ssize_t n = ::write(impl_->fd, frame.data(), frame.size());
  if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
    // A full tap queue drops the frame. TCP will retransmit.
  }
}

bool TapDevice::poll_frame(std::vector<std::uint8_t>& out) {
  std::uint8_t buf[65536];
  const ssize_t n = ::read(impl_->fd, buf, sizeof(buf));
  if (n < 0) return false;
  out.assign(buf, buf + n);
  return true;
}

void TapDevice::wait_ms(int ms) {
  struct pollfd pfd {};
  pfd.fd = impl_->fd;
  pfd.events = POLLIN;
  ::poll(&pfd, 1, std::max(0, ms));
}

void TapDevice::configure_host(Ipv4 host_ip, Ipv4 mask) {
  const int s = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) throw std::runtime_error(std::string("socket: ") + std::strerror(errno));
  struct IfClose {
    int fd;
    ~IfClose() { ::close(fd); }
  } guard{s};

  struct ifreq ifr {};
  std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", impl_->name.c_str());

  ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
  std::memcpy(ifr.ifr_hwaddr.sa_data, impl_->mac.b.data(), 6);
  if (ioctl(s, SIOCSIFHWADDR, &ifr) < 0) {
    throw std::runtime_error(std::string("SIOCSIFHWADDR: ") + std::strerror(errno));
  }

  ifr.ifr_mtu = impl_->mtu;
  if (ioctl(s, SIOCSIFMTU, &ifr) < 0) {
    throw std::runtime_error(std::string("SIOCSIFMTU: ") + std::strerror(errno));
  }

  auto set_addr = [&](unsigned long req, Ipv4 ip) {
    std::memset(&ifr, 0, sizeof(ifr));
    std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", impl_->name.c_str());
    auto* addr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(ip.host);
    if (ioctl(s, req, &ifr) < 0) {
      throw std::runtime_error(std::string("ioctl addr: ") + std::strerror(errno));
    }
  };
  set_addr(SIOCSIFADDR, host_ip);
  set_addr(SIOCSIFNETMASK, mask);

  std::memset(&ifr, 0, sizeof(ifr));
  std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", impl_->name.c_str());
  if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
    throw std::runtime_error(std::string("SIOCGIFFLAGS: ") + std::strerror(errno));
  }
  ifr.ifr_flags = static_cast<short>(ifr.ifr_flags | IFF_UP | IFF_RUNNING);
  if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
    throw std::runtime_error(std::string("SIOCSIFFLAGS: ") + std::strerror(errno));
  }

  // rp_filter is the max of conf/all and conf/<if>. A strict "all" value
  // drops the stack's replies, whose source address lives on this link but
  // is not a kernel-local address. This process owns the interface.
  const std::string paths[] = {
      "/proc/sys/net/ipv4/conf/" + impl_->name + "/rp_filter",
      "/proc/sys/net/ipv4/conf/all/rp_filter",
  };
  for (const auto& path : paths) {
    std::ofstream out(path);
    if (out) out << "0";
  }
  std::ofstream accept("/proc/sys/net/ipv4/conf/" + impl_->name + "/accept_local");
  if (accept) accept << "1";
}

}  // namespace netstack
