# Walkthrough

This is the list of decisions I would expect to defend in an interview. The code is the authority if a sentence here and a source file disagree. Numbers quoted from a live run are only the ones in `results/measurements.json`.

## What it is

A single process owns a TAP, parses Ethernet, and implements enough of IPv4, ICMP, UDP, and TCP for `ping` and an unmodified `curl` to use an HTTP server inside that process. The kernel is the other host on the wire. It is not a router, not a VPN, and not a replacement for the kernel stack. There is one local address.

## Process model

One thread. `Stack::poll` reads up to 64 frames, then runs timers. Sockets are non-blocking. A blocking `read` would deadlock the tests, because both ends of a simulated connection live in the same thread and only make progress when `poll` is called. The TAP server calls `poll_for`, which waits on the device until the next timer or the timeout. `poll_for` returns immediately if the clock does not advance, so a `ManualClock` cannot spin.

There are no locks. The cost is that a slow HTTP handler stalls ACKs. The HTTP server only copies bytes, so that cost does not show up in the measurements. A multi-threaded version would need a rule for which thread owns a TCB; I would shard by connection rather than lock the whole stack.

## Why TAP, and who owns which address

TUN would skip Ethernet. The point of the project is ARP and framing, so the device is TAP with `IFF_NO_PI` (no extra packet-info header). Frames are padded to 60 bytes. The FCS is the NIC's job and is not present on a TAP, so it is not generated or checked.

The stack's MAC is `02:00:00:00:00:02`. The `02` bit marks it locally administered, so it will not collide with a burned-in address. The host address (`10.0.0.1/24` in the measurements) is assigned to the interface with `configure_host`. The stack address (`10.0.0.2`) is not. If it were, the kernel would answer ARP for it and the stack would never see the traffic.

`rp_filter` is `max(conf/all, conf/<if>)`. Setting only the interface is not enough when `all` is strict, and a strict filter drops a packet whose source (`10.0.0.2`) is not an address the kernel considers local. `configure_host` writes `0` to both and sets `accept_local=1` on the interface. That was required before the first successful `curl`.

`ImpairDevice` sits in front of the TAP when `--delay-ms` or `--loss` is set. It is the fallback for a kernel built without `sch_netem`. Non-ARP frames can be delayed and randomly dropped in both directions. ARP is exempt: a lossy ARP exchange fails the test for a reason that has nothing to do with TCP. Inbound delivery scans the whole hold queue, not only the front, so a delayed IP frame cannot block an ARP reply that is already due. `scripts/measure.py` probes `tc qdisc replace dev lo root netem delay 1ms`. If that works it uses `tc` and does not also delay in process. If it fails, the JSON records the `tc` error and `shaping.mode = "device"`.

## Checksums

The internet checksum is the one's complement sum of 16-bit big-endian words (RFC 1071), accumulated in a `uint64` and folded at the end. An odd trailing byte is treated as the high half of a word. A header that already contains its checksum folds to `0xffff`, or to `0`, which is one's-complement negative zero. Both are accepted.

TCP and UDP use the IPv4 pseudo-header: source, destination, zero, protocol, TCP/UDP length. UDP checksum `0` on the wire means "not present" and is accepted. A computed UDP checksum of `0` is stored as `0xffff`, because a stored `0` would be read as "no checksum". TCP has no such sentinel.

IP options are not parsed. The receive path skips `IHL * 4` bytes and checksums only the header. The send path always writes IHL 5. On the measured TAP, `checksum_drops` stayed 0, so the kernel was not handing us frames with checksum offload left incomplete. If a future kernel did, the right fix is to detect `CHECKSUM_PARTIAL` equivalent at the device, not to disable checks.

## IPv4

Addresses in the API are host-order `uint32`. The wire format is big-endian at the boundary. TTL is 64. A received TTL of 0 is dropped. The DF bit is left clear. The stack fragments its own datagrams to the device MTU, on 8-byte boundaries, and reassembles what it receives. There is no path MTU discovery. That is a real gap: a smaller hop would black-hole a 1500-byte datagram, and the stack would not learn to shrink. Reassembly keys on source, destination, id, and protocol. Overlapping bytes keep the first copy. A hole that is never filled expires in 15 seconds. More than 64 concurrent datagrams resets the table, and a single datagram may not claim more than 65535 bytes. Those caps are there so a hostile stream of fragments cannot grow memory without bound. They are not a complete defense.

The next hop is the destination when it is on-link, otherwise the configured gateway. There is no forwarding table.

## ARP and ICMP

ARP is the only source of IP-to-MAC mappings. Learning a mapping from the source of an IP packet would be convenient and wrong: a spoofed packet would poison the cache. Entries live 60 seconds. While a request is outstanding, up to 16 datagrams are queued. The request is retried once a second and given up after 5 tries, at which point the queue is dropped.

ICMP echo requests are reflected as echo replies with the same id, sequence, and payload. The stack's own `ping` matches on id, sequence, and payload. A UDP port with no socket draws ICMP destination unreachable, type 3 code 3, quoting the original IP header and the first 8 payload bytes.

## UDP

Checksum as above, including the "zero means none" rule. Delivery is a bound port and a queue of 64 datagrams; past that, the datagram is dropped. The HTTP server can reflect UDP on `--udp-echo` so the measurement script has a check that is not TCP.

## TCP state machine

States follow RFC 9293: closed, listen, SYN-sent, SYN-received, established, FIN-wait-1, FIN-wait-2, closing, time-wait, close-wait, last-ack. Simultaneous open is handled (SYN received in SYN-sent moves to SYN-received). A retransmitted FIN in TIME-WAIT restarts the timer. FIN-WAIT-2 uses the same timer as TIME-WAIT so a peer that disappears does not pin the TCB.

TIME-WAIT defaults to 60 seconds, which is 2 * MSL with MSL 30 seconds. The tests set it to 200 ms because a minute-long wait would make the suite useless. The live server keeps 60 seconds. I would not claim the live server recycles ports quickly.

The ISN is random on the live server. Tests pass a fixed `cfg.isn` so traces are comparable. Ephemeral ports start at 49152 and are not reused while any TCB still holds them.

A FIN is its own segment. It is not coalesced onto the last data segment. That costs one packet per close and makes the teardown in the trace viewer obvious. It is not what a tuned stack does.

## Window, buffers, and sequence numbers

Sequence comparisons use a signed 32-bit difference (`seq_lt` and the rest). That is the only comparison that stays correct across the wrap of a `uint32`.

MSS is the device MTU minus 40 (20 IP + 20 TCP) unless the peer's MSS option is smaller. The congestion window is in bytes. The initial window is 10 segments of the negotiated MSS (RFC 6928). The handshake rebuilds the controller once the peer MSS is known, so the initial window is not 10 times a guessed MSS. Initial `ssthresh` is `0x3fffffff`, the "arbitrarily high" value from RFC 5681, until the first loss.

Window scale is offered as 7, which covers a receive buffer up to about 8 MB in the scaled window. The scale option is sent as NOP + WS so it stays aligned. The SYN segment itself is advertised unscaled (RFC 7323); the scale applies after the handshake. If the peer does not send a scale, we do not scale either. The advertised window is the free application receive buffer, capped at 65535 after scaling, and it does not shrink to account for the out-of-order hold queue. Holding out-of-order data against the window would make a duplicate ACK look like a window update. The hold queue is capped at 128 segments and stored in a vector ordered with the wrap-safe comparison, not in a map keyed by the raw sequence number.

Send and receive buffers default to 256 KB. The application API is `send` / `recv` that return a byte count or "would block". Nagle is off: small writes go out immediately. That matches what `curl` wants and avoids an interaction between the delayed ACK and a corked last segment. Delayed ACK is 40 ms or every second full-sized segment. A hole produces an immediate duplicate ACK. A zero window arms a persist timer that sends a 1-byte probe.

## Retransmission timing

The RTT estimator is Jacobson/Karels (RFC 6298): `srtt` gains 1/8 of the error, `rttvar` gains 1/4 of the deviation, `RTO = srtt + 4 * rttvar`. The first sample sets `srtt` to the measurement and `rttvar` to half of it, so the first RTO is `srtt + 2 * srtt = 3 * srtt` before the floor. The initial RTO, before any sample, is 1 second.

The floor is 200 ms, which is Linux `TCP_RTO_MIN`, not the RFC's 1 second. A 1 second floor would hide the behavior of a sub-millisecond TAP behind a timer. The floor is a parameter (`cfg.rto_min`), not a constant inside the estimator. Karn's algorithm drops the RTT sample whenever the segment was retransmitted. The timer is restarted on a new ACK. The backoff doubles the RTO only on a timeout, not on a fast retransmit. Six timeouts abort the connection with a RST (`cfg.max_retries`).

The unit test locks the estimator to exact values: a 0.1 s sample yields srtt 0.1, rttvar 0.05, rto 0.3; the next sample yields rttvar 0.0375 and rto 0.25; a backoff doubles the RTO and leaves srtt alone.

## Loss recovery

Three duplicate ACKs, each of them pure (no payload, no SYN/FIN, window unchanged, data still in flight, and the head of the flight is not a bare SYN), enter fast recovery. The first two duplicate ACKs also allow one extra segment of transmission (limited transmit, RFC 3042), so a loss near the end of a small window still has a chance to generate the third duplicate.

Recovery is NewReno (RFC 6582) for both congestion algorithms. `recover` is set to `snd_nxt` at the moment of the loss. A partial ACK, one that moves `snd_una` but does not reach `recover`, is treated as evidence that another segment was lost and is retransmitted immediately. Leaving recovery sets `cwnd` back to `ssthresh` rather than leaving the inflated window in place. A timeout leaves recovery, collapses `cwnd` to one MSS, and backs off the RTO.

`drop_data_seg = N` marks the Nth first-transmission data segment to be dropped once. The retransmission is sent. That is how the fast-retransmit test and the live `--drop-seg 4` run are deterministic. The loss sample records `cwnd` before the reduction, the time until the retransmission is acknowledged, and, if it happens, the time until `cwnd` is back to at least the pre-loss value and the connection is not in fast recovery. A transfer that finishes during recovery reports `restored: false`. That is what most of the 512 KB loss runs did, and the table says so.

## Reno and CUBIC

Slow start, for both, uses appropriate byte counting with L = 2 (RFC 3465): each ACK grows `cwnd` by `min(acked, 2 * MSS)`. Reno congestion avoidance adds one MSS per window of ACKs, accumulated as credit so a partial window does not round away.

On a Reno fast retransmit, `ssthresh = max(flight / 2, 2 * MSS)` and `cwnd = ssthresh + 3 * MSS`. Further duplicate ACKs inflate by one MSS. A partial ACK deflates by the acknowledged bytes and then adds one MSS.

CUBIC (RFC 8312) changes the decrease and the congestion-avoidance increase. It does not replace slow start or NewReno recovery. The decrease uses beta 0.7, and fast convergence pulls `W_max` down when the flow was not already at the previous maximum. The increase is `W_cubic(t) = C * (t - K)^3 + W_max` with C = 0.4, compared against the TCP-friendly estimate, and applied as per-ACK credit. The math is in `double`. Linux does this in scaled integers with a C of 717/1024; the curves match closely and are not bit-identical. I would not claim a CUBIC cwnd matches Linux packet for packet. PRR (RFC 6937) is not implemented: during recovery the window is the classic inflated NewReno window, which can send a burst when the ACK arrives. That is the first thing I would replace.

The Reno unit test checks exact window values with MSS 1000. The CUBIC test checks that, after a reduction, advancing time grows the window past the reduced value. It does not lock the cubic polynomial to a bit pattern.

## HTTP

The parser is incremental. A request split across `recv` calls, and a pipeline left in the buffer after one response, both work. The test covers a header split across feeds and a `GET /health` through two stacks and `HttpApp`.

Routes are `GET` and `HEAD` of `/`, `/health` (`ok\n`), `/stats`, and `/download?n=`. The download cap is 8 MB. Every response sets `Content-Length`. HTTP/1.0, or `Connection: close`, closes after the response. HTTP/1.1 stays open otherwise. The server writes until the send buffer returns "would block", then returns to `poll`. That is why a single response used to be split into 256 KB goodput samples: the buffer drained, the burst accounting thought the transfer was over, and the next write started a new sample. A quiet gap of 100 ms now separates samples, which is long enough to split `/health` from the following download and short enough to keep one download together. The headline throughput is still curl's, because curl's clock includes the handshake and the request. The stack figure starts at the first data segment.

## What the measurements mean

Idle TAP, five runs, Reno, `curl` of 1,048,576 bytes: median `speed_download` 79.099752 Mbit/s, zero retransmissions, zero checksum drops, and one fragmented ping reassembled on each run (`ping -M dont -s 2000` returned 2008 bytes, the 2000-byte payload plus the ICMP header).

With 20 ms of delay in each direction, `ping -c 5` averages sat between 40.151 ms and 40.302 ms. That is the check that both directions are delayed. A bug that delayed only one direction would have landed near 20 ms.

At that delay plus a 1% chance of dropping a non-ARP frame, three 524,288-byte downloads gave median curl throughput 5.387584 Mbit/s (Reno) and 6.005744 Mbit/s (CUBIC). No run took an RTO. The forced drop of data segment 4, delay and no random loss, was a fast retransmit in both algorithms: retransmission ACK at 40.047 ms (Reno) and 40.093 ms (CUBIC), which is one RTT, and `cwnd` back to the pre-loss 20,440 bytes at 321 ms and 281 ms.

The 1% loss is not `tc netem`. This kernel returns `Specified qdisc kind is unknown` for `netem`. The script stores that string. I would not describe these runs as netem results.

## Traces

The JSON trace is version 1: title, description, source (`tap` or `sim`), algorithm, and events. An event has `t_us` on the stack clock (zero at process start, not at the first packet), direction, kind (`segment`, `drop`, `rto`, `fast_retransmit`, `recovery_exit`), flags, sequence, ack, length, advertised window, TCP state, `cwnd`, `ssthresh`, flight size, and the connection endpoints. `fast_retransmit` and `rto` are written after the controller applies the reduction, so the cwnd in that event is the post-loss window. The loss sample's `cwnd_before` is the value from before the reduction. The pcap is little-endian classic pcap, magic `d4c3b2a1`, link type 1.

The viewer replays those events. It does not invent a series.

## Left out, on purpose

- SACK, TCP timestamps, and ECN. Loss detection is duplicate ACKs and timeouts only. A reordered network will sometimes look like loss. The out-of-order test delays one segment and checks that the bytes still arrive in order; it does not claim we avoid a spurious retransmit in every reorder.
- PRR, BBR, HyStart, and pacing.
- Path MTU discovery and IP options.
- Nagle, and FIN coalesced with the last data segment.
- Checksum offload, GRO, and GSO. One segment is one write to the TAP, which is a large part of why an idle 1 MB curl is ~79 Mbit/s and not line rate.
- IPv6, multiple addresses, and forwarding.
- A real `tc netem` result on this machine. The code will use it when the qdisc exists.

## Tests and CI

`ctest` runs 17 tests: the RFC 1071 vector, a flipped bit, sequence wrap, the RTT numbers, Reno's window arithmetic, CUBIC growth after a cut, ARP plus ICMP, UDP echo plus port unreachable, fragmentation of a 1000-byte UDP datagram across an MTU of 200, a 100,000-byte TCP transfer that must match on both sides, a timeout via `drop_data_seg`, a fast retransmit of the same knob, a 3% random loss that still delivers the bytes, a delayed segment that is held and then delivered, the HTTP parser, and `GET /health` over the simulated wire. The same 17 pass with AddressSanitizer and UBSan.

CI builds with g++, runs `ctest`, repeats the build with sanitizers, and runs `npm ci && npm run build` in `web/`. It does not open a TAP. That needs `/dev/net/tun` and root, which `scripts/measure.py` asks for explicitly.
