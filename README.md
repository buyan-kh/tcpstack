# tcpstack

A userspace TCP/IP stack for Linux, written in C++20. It runs on a TAP device and answers real `ping` and `curl` without using the kernel's TCP.

## Features

- Ethernet, ARP, IPv4 (checksums, fragment reassembly), ICMP echo, UDP
- TCP state machine, sliding window, Jacobson/Karels RTO, fast retransmit
- NewReno recovery with Reno or CUBIC congestion control
- HTTP server on top of the stack's socket API
- pcap and JSON trace output, plus a Next.js trace viewer in `web/`

## Results

From `scripts/measure.py` (see `results/measurements.json`):

- Idle link, 1 MiB download: median 79.1 Mbit/s over 5 runs, 0 retransmits
- 20 ms delay + 1% loss, 512 KiB: median 5.39 Mbit/s (Reno) vs 6.01 Mbit/s (CUBIC)
- Idle ping average: 0.14 to 0.23 ms

The kernel here lacked netem, so loss and delay are injected inside the stack's own device. Details are in docs/WALKTHROUGH.md.

## Quick start

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++
cmake --build build -j
ctest --test-dir build --output-on-failure

sudo ./build/http_server --setup --tap nstk0 --host-ip 10.0.0.1 --stack-ip 10.0.0.2 --port 80
ping -c 3 10.0.0.2
curl http://10.0.0.2/health
```

Use `--cc cubic` for CUBIC, `--pcap out.pcap` for a capture, `--loss 0.01 --delay-ms 20` to impair the link.

Trace viewer:

```bash
cd web && npm ci && npm run dev
```

## Layout

```
include/netstack/   public headers
src/                Ethernet, ARP, IPv4, ICMP, UDP, TCP, Reno, CUBIC
apps/               TAP HTTP server
tests/              in-process tests (no root needed)
scripts/measure.py  live measurements
results/            recorded numbers, pcaps, traces
web/                trace viewer
docs/WALKTHROUGH.md design notes
```
