#pragma once

#include "netstack/types.hpp"

#include <functional>
#include <memory>
#include <string>

namespace netstack {

// A frame source and sink. TAP is the production device; SimLink is the
// deterministic one used by tests.
class Device {
 public:
  virtual ~Device() = default;
  virtual std::string name() const = 0;
  virtual Mac mac() const = 0;
  virtual std::uint16_t mtu() const = 0;
  virtual void send(std::span<const std::uint8_t> frame) = 0;
  // Returns false when no frame is waiting (non-blocking).
  virtual bool poll_frame(std::vector<std::uint8_t>& out) = 0;
  // Block until a frame arrives, the timeout expires, or the fd is ready.
  // Sim devices return immediately.
  virtual void wait_ms(int ms) = 0;
};

struct SimConfig {
  std::uint16_t mtu = 1500;
  double loss_prob = 0.0;
  Duration delay = Duration::zero();
  std::uint64_t seed = 1;
  // Optional hooks so a test can drop or delay one specific segment.
  std::function<bool(int dir, std::uint64_t n, std::span<const std::uint8_t> frame)> drop_if;
  std::function<Duration(int dir, std::uint64_t n, std::span<const std::uint8_t> frame)>
      delay_if;
};

// Two devices joined by a queue. send() never re-enters the peer stack;
// the test (or a pump loop) calls deliver() to move due frames.
class SimLink {
 public:
  explicit SimLink(ClockSource& clock, SimConfig cfg = {});
  ~SimLink();
  SimLink(const SimLink&) = delete;
  SimLink& operator=(const SimLink&) = delete;

  Device& side(int index);
  void deliver();
  std::uint64_t sent(int dir) const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Delays and drops frames in front of another device. Used when the kernel
// has no sch_netem (CONFIG_NET_SCH_NETEM). ARP is passed through so neighbor
// resolution is not the thing under test. Delay is wall-clock on `clock`.
class ImpairDevice final : public Device {
 public:
  ImpairDevice(Device& inner, ClockSource& clock, double loss_prob, Duration delay, std::uint64_t seed = 1);
  ~ImpairDevice() override;
  std::string name() const override;
  Mac mac() const override;
  std::uint16_t mtu() const override;
  void send(std::span<const std::uint8_t> frame) override;
  bool poll_frame(std::vector<std::uint8_t>& out) override;
  void wait_ms(int ms) override;
  std::uint64_t dropped() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Opens /dev/net/tun in TAP mode (IFF_NO_PI). `configure` assigns the
// *host* address on the interface. The stack's own address must not be
// assigned to the kernel, or the kernel will answer ARP for it.
class TapDevice final : public Device {
 public:
  TapDevice(std::string name, Mac mac, std::uint16_t mtu = 1500);
  ~TapDevice() override;
  TapDevice(const TapDevice&) = delete;
  TapDevice& operator=(const TapDevice&) = delete;

  std::string name() const override;
  Mac mac() const override;
  std::uint16_t mtu() const override;
  void send(std::span<const std::uint8_t> frame) override;
  bool poll_frame(std::vector<std::uint8_t>& out) override;
  void wait_ms(int ms) override;

  // Needs CAP_NET_ADMIN. `host_ip` is the address the kernel owns.
  void configure_host(Ipv4 host_ip, Ipv4 mask);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace netstack
