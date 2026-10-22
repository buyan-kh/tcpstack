#include "netstack/http.hpp"
#include "netstack/stack.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

volatile std::sig_atomic_t g_stop = 0;

void on_signal(int) { g_stop = 1; }

void usage() {
  std::cerr
      << "usage: http_server --tap NAME --host-ip A.B.C.D --stack-ip A.B.C.D\n"
      << "                  [--mask A.B.C.D] [--port N] [--cc reno|cubic]\n"
      << "                  [--pcap FILE] [--trace FILE] [--summary FILE]\n"
      << "                  [--drop-seg N] [--delay-ms N] [--loss PROB]\n"
      << "                  [--udp-echo PORT] [--setup] [--verbose]\n";
}

}  // namespace

int main(int argc, char** argv) {
  std::string tap = "nstk0";
  std::string host_s = "10.0.0.1";
  std::string stack_s = "10.0.0.2";
  std::string mask_s = "255.255.255.0";
  std::string pcap;
  std::string trace;
  std::string summary;
  std::string cc = "reno";
  int port = 80;
  int drop_seg = -1;
  int udp_echo = 0;
  int delay_ms = 0;
  double loss = 0;
  bool setup = false;
  bool verbose = false;

  for (int i = 1; i < argc; ++i) {
    auto need = [&](const char* flag) -> std::string {
      if (i + 1 >= argc) {
        std::cerr << "missing value for " << flag << "\n";
        std::exit(2);
      }
      return argv[++i];
    };
    const std::string a = argv[i];
    if (a == "--tap") tap = need("--tap");
    else if (a == "--host-ip") host_s = need("--host-ip");
    else if (a == "--stack-ip") stack_s = need("--stack-ip");
    else if (a == "--mask") mask_s = need("--mask");
    else if (a == "--port") port = std::stoi(need("--port"));
    else if (a == "--cc") cc = need("--cc");
    else if (a == "--pcap") pcap = need("--pcap");
    else if (a == "--trace") trace = need("--trace");
    else if (a == "--summary") summary = need("--summary");
    else if (a == "--drop-seg") drop_seg = std::stoi(need("--drop-seg"));
    else if (a == "--delay-ms") delay_ms = std::stoi(need("--delay-ms"));
    else if (a == "--loss") loss = std::stod(need("--loss"));
    else if (a == "--udp-echo") udp_echo = std::stoi(need("--udp-echo"));
    else if (a == "--setup") setup = true;
    else if (a == "--verbose") verbose = true;
    else if (a == "--help") {
      usage();
      return 0;
    } else {
      std::cerr << "unknown argument " << a << "\n";
      usage();
      return 2;
    }
  }

  auto host_ip = netstack::Ipv4::parse(host_s);
  auto stack_ip = netstack::Ipv4::parse(stack_s);
  auto mask = netstack::Ipv4::parse(mask_s);
  if (!host_ip || !stack_ip || !mask) {
    std::cerr << "bad address\n";
    return 2;
  }

  netstack::Mac mac{{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}};
  try {
    netstack::TapDevice dev(tap, mac, 1500);
    if (setup) dev.configure_host(*host_ip, *mask);
    netstack::SteadyClockSource clock;
    netstack::ImpairDevice impair(dev, clock, loss, std::chrono::milliseconds(std::max(0, delay_ms)), 1);
    netstack::Device& face = (loss > 0 || delay_ms > 0) ? static_cast<netstack::Device&>(impair) : dev;
    netstack::Stack::Config cfg;
    cfg.ip = *stack_ip;
    cfg.mask = *mask;
    cfg.congestion = cc == "cubic" ? netstack::CongestionKind::Cubic : netstack::CongestionKind::Reno;
    cfg.drop_data_seg = drop_seg;
    cfg.time_wait = std::chrono::seconds(60);
    netstack::Stack stack(face, cfg, clock);
    stack.set_verbose(verbose);
    if (!pcap.empty()) stack.open_pcap(pcap);
    if (!trace.empty()) {
      stack.open_trace(trace, std::string("TAP ") + cc + " port " + std::to_string(port),
                       drop_seg >= 0 ? "one forced data-segment loss" : "live TAP capture", "tap");
    }
    auto listener = stack.listen(static_cast<std::uint16_t>(port));
    if (!listener) {
      std::cerr << "listen failed\n";
      return 1;
    }
    std::unique_ptr<netstack::UdpSocket> echo;
    if (udp_echo > 0) echo = stack.udp_bind(static_cast<std::uint16_t>(udp_echo));
    netstack::HttpApp app(stack);
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::cout << "READY tap=" << tap << " stack=" << stack_ip->to_string() << " port=" << port
              << " cc=" << cc << " delay_ms=" << delay_ms << " loss=" << loss << std::endl;
    while (!g_stop) {
      stack.poll_for(std::chrono::milliseconds(20));
      app.service(*listener);
      if (echo) {
        while (auto dg = echo->recv_from()) {
          echo->send_to(dg->src, dg->port, dg->data);
        }
      }
    }
    const auto json = stack.summary_json();
    std::cout << "IMPAIR_DROPS " << impair.dropped() << std::endl;
    std::cout << "NETSTACK_SUMMARY " << json << std::endl;
    if (!summary.empty()) {
      std::ofstream out(summary);
      out << json << "\n";
    }
  } catch (const std::exception& ex) {
    std::cerr << "http_server: " << ex.what() << "\n";
    return 1;
  }
  return 0;
}
