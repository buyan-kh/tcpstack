# Resume bullets

Each number comes from `results/measurements.json`, produced by `scripts/measure.py` on a Linux TAP. Curl figures are `speed_download`. The idle median is five runs. The loss medians are three runs each. Delay and loss were applied in the TAP device because this kernel has no `sch_netem`; ping RTT is the check that both directions were delayed.

- Built a C++20 userspace TCP/IP stack on a Linux TAP (Ethernet/ARP, IPv4 checksums and fragmentation, ICMP echo, UDP, and TCP with a full state machine, Jacobson/Karels RTO, fast retransmit, NewReno recovery, and Reno and CUBIC congestion control) plus a socket-style API and an HTTP server; five unmodified curl downloads of 1,048,576 bytes had a median throughput of 79.099752 Mbit/s and zero retransmissions.

- Recovered one forced TCP loss under a 20 ms each-way TAP delay (ping -c 5 average 40.248 ms on the Reno run, 40.159 ms on the CUBIC run) by fast retransmit rather than timeout: the retransmission was acknowledged in 40.047 ms (Reno) and 40.093 ms (CUBIC), and cwnd returned to the pre-loss 20,440 bytes in 321 ms (Reno) and 281 ms (CUBIC).

- Measured 524,288-byte downloads from that HTTP server with 20 ms each-way delay and 1% random IP loss: median curl throughput was 5.387584 Mbit/s for Reno and 6.005744 Mbit/s for CUBIC across three runs each, every recorded loss was a fast retransmit that was acknowledged, and no run took a retransmission timeout.
