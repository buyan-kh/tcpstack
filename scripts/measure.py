#!/usr/bin/env python3
"""Measure the TAP HTTP server with ping, curl, and tc netem.

Writes results/measurements.json. Every number in that file comes from a
command that ran in this process. The script does not fill in missing runs.
"""

import json
import os
import signal
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build" / "http_server"
OUT = ROOT / "results"
TAP = "nstk0"
HOST = "10.0.0.1"
STACK = "10.0.0.2"
IFB = "ifb_ns"


def run(cmd, check=True, timeout=30):
    return subprocess.run(cmd, check=check, text=True, capture_output=True, timeout=timeout)


def sudo(cmd, check=True, timeout=30):
    return run(["sudo", *cmd], check=check, timeout=timeout)


def kill_server(proc):
    if proc is None or proc.poll() is not None:
        return "", None
    proc.send_signal(signal.SIGTERM)
    try:
        out, err = proc.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate(timeout=3)
    text = (out or "") + (err or "")
    summary = ""
    drops = None
    for line in text.splitlines():
        if line.startswith("NETSTACK_SUMMARY "):
            summary = line[len("NETSTACK_SUMMARY ") :]
        elif line.startswith("IMPAIR_DROPS "):
            try:
                drops = int(line.split()[1])
            except ValueError:
                drops = None
    return summary, drops


NETEM_OK = None
NETEM_ERR = ""


def netem_works():
    global NETEM_OK, NETEM_ERR
    if NETEM_OK is not None:
        return NETEM_OK
    probe = sudo(["tc", "qdisc", "replace", "dev", "lo", "root", "netem", "delay", "1ms"], check=False)
    NETEM_ERR = ((probe.stderr or "") + (probe.stdout or "")).strip()
    sudo(["tc", "qdisc", "del", "dev", "lo", "root"], check=False)
    NETEM_OK = probe.returncode == 0
    return NETEM_OK


def start_server(cc, pcap, trace, summary, drop_seg=None, delay_ms=0, loss=0.0):
    OUT.mkdir(parents=True, exist_ok=True)
    cmd = [
        "sudo",
        str(BUILD),
        "--setup",
        "--tap",
        TAP,
        "--host-ip",
        HOST,
        "--stack-ip",
        STACK,
        "--port",
        "80",
        "--cc",
        cc,
        "--udp-echo",
        "9999",
        "--summary",
        str(summary),
    ]
    if pcap:
        cmd += ["--pcap", str(pcap)]
    if trace:
        cmd += ["--trace", str(trace)]
    if drop_seg is not None:
        cmd += ["--drop-seg", str(drop_seg)]
    if delay_ms:
        cmd += ["--delay-ms", str(delay_ms)]
    if loss:
        cmd += ["--loss", str(loss)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    deadline = time.time() + 5
    ready = ""
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                rest = proc.stdout.read() if proc.stdout else ""
                raise RuntimeError(f"server exited early: {ready}{line}{rest}")
            time.sleep(0.05)
            continue
        ready += line
        if line.startswith("READY"):
            return proc
    kill_server(proc)
    raise RuntimeError(f"server did not become ready: {ready}")


def wait_ping(tries=20):
    for _ in range(tries):
        r = run(["ping", "-c", "1", "-W", "1", STACK], check=False, timeout=5)
        if r.returncode == 0:
            return True
        time.sleep(0.1)
    return False


def clear_netem():
    sudo(["tc", "qdisc", "del", "dev", TAP, "root"], check=False)
    sudo(["tc", "qdisc", "del", "dev", TAP, "ingress"], check=False)
    sudo(["tc", "qdisc", "del", "dev", IFB, "root"], check=False)
    sudo(["ip", "link", "del", IFB], check=False)


def apply_netem(delay_ms, loss_pct):
    """Delay and loss in both directions.

    Root qdisc shapes frames the kernel transmits (client -> stack).
    Ingress is redirected to an IFB device so frames the stack injects
    (stack -> client) are shaped too. loss_pct is a percent, 0 disables loss.
    """
    clear_netem()
    loss = f" loss {loss_pct}%" if loss_pct and float(loss_pct) > 0 else ""
    netem = f"delay {delay_ms}ms{loss}"
    sudo(["tc", "qdisc", "add", "dev", TAP, "root", "netem", *netem.split()])
    mod = sudo(["modprobe", "ifb"], check=False)
    if mod.returncode != 0:
        return {"ifb": False, "note": "modprobe ifb failed; only kernel egress is shaped"}
    add = sudo(["ip", "link", "add", IFB, "type", "ifb"], check=False)
    sudo(["ip", "link", "set", IFB, "up"])
    sudo(["tc", "qdisc", "add", "dev", TAP, "handle", "ffff:", "ingress"])
    sudo(
        [
            "tc",
            "filter",
            "add",
            "dev",
            TAP,
            "parent",
            "ffff:",
            "protocol",
            "all",
            "u32",
            "match",
            "u32",
            "0",
            "0",
            "action",
            "mirred",
            "egress",
            "redirect",
            "dev",
            IFB,
        ]
    )
    sudo(["tc", "qdisc", "add", "dev", IFB, "root", "netem", *netem.split()])
    show = sudo(["tc", "qdisc", "show", "dev", TAP])
    show_ifb = sudo(["tc", "qdisc", "show", "dev", IFB], check=False)
    return {
        "ifb": show_ifb.returncode == 0 and "netem" in show_ifb.stdout,
        "tap_qdisc": show.stdout.strip(),
        "ifb_qdisc": show_ifb.stdout.strip(),
        "delay_ms": delay_ms,
        "loss_pct": loss_pct,
    }


def ping_stats(count):
    r = run(["ping", "-c", str(count), "-i", "0.2", "-W", "2", "-q", STACK], check=False, timeout=count + 10)
    text = (r.stdout or "") + (r.stderr or "")
    # rtt min/avg/max/mdev = 0.051/0.067/0.090/0.013 ms
    stats = None
    for line in text.splitlines():
        if "min/avg/max" in line and "=" in line:
            part = line.split("=", 1)[1].strip().split()[0]
            mn, avg, mx, mdev = [float(x) for x in part.split("/")]
            stats = {"min_ms": mn, "avg_ms": avg, "max_ms": mx, "mdev_ms": mdev}
    return {"ok": r.returncode == 0, "raw": text.strip(), "stats": stats}


def curl_download(n, timeout=30):
    url = f"http://{STACK}/download?n={n}" if n else f"http://{STACK}/health"
    r = run(
        [
            "curl",
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code} %{size_download} %{time_total} %{speed_download}",
            "--max-time",
            str(timeout),
            url,
        ],
        check=False,
        timeout=timeout + 5,
    )
    if r.returncode != 0:
        return {"ok": False, "error": (r.stderr or r.stdout or "").strip(), "url": url}
    parts = (r.stdout or "").split()
    if len(parts) != 4:
        return {"ok": False, "error": f"unexpected curl output {r.stdout!r}", "url": url}
    code, size, sec, speed = parts
    size_i = int(float(size))
    sec_f = float(sec)
    speed_f = float(speed)
    return {
        "ok": code == "200",
        "http_code": int(code),
        "bytes": size_i,
        "seconds": sec_f,
        "bytes_per_sec": speed_f,
        "mbit_per_sec": speed_f * 8 / 1e6,
        "url": url,
    }


def udp_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    try:
        s.sendto(b"netstack-udp", (STACK, 9999))
        data, addr = s.recvfrom(64)
        return {"ok": data == b"netstack-udp", "payload": data.decode(), "from": addr[0]}
    except Exception as exc:  # noqa: BLE001 - recorded as a failed measurement
        return {"ok": False, "error": str(exc)}
    finally:
        s.close()


def one_transfer(cc, nbytes, delay_ms, loss_pct, drop_seg, pcap, trace, summary):
    proc = None
    try:
        use_tc = bool(delay_ms or loss_pct) and netem_works()
        server_delay = 0 if use_tc or not delay_ms else delay_ms
        server_loss = 0.0 if use_tc or not loss_pct else float(loss_pct) / 100.0
        proc = start_server(cc, pcap, trace, summary, drop_seg, server_delay, server_loss)
        if not wait_ping():
            raise RuntimeError("ping did not answer")
        shaping = None
        if delay_ms or loss_pct:
            if use_tc:
                shaping = apply_netem(delay_ms, loss_pct)
                shaping["mode"] = "tc-netem"
            else:
                shaping = {
                    "mode": "device",
                    "delay_ms": server_delay,
                    "loss_prob": server_loss,
                    "tc_error": NETEM_ERR,
                    "reason": "tc netem is unavailable (CONFIG_NET_SCH_NETEM is not set on this kernel). "
                    "Frames were delayed and dropped in the TAP device instead. ARP is not impaired.",
                }
            time.sleep(0.2)
        health = curl_download(0, timeout=10)
        ping = ping_stats(5)
        udp = udp_echo()
        xfer = curl_download(nbytes, timeout=40)
        # Delayed ACKs may still be sitting in the device queue. Let them land
        # so the stack summary covers the same bytes curl already counted.
        time.sleep(0.2)
        big_ping = None
        if nbytes and not loss_pct and not drop_seg:
            # Fragmented ICMP, DF off. Failure is recorded, not invented.
            frag = run(
                ["ping", "-M", "dont", "-c", "1", "-s", "2000", "-W", "2", STACK],
                check=False,
                timeout=8,
            )
            big_ping = {"ok": frag.returncode == 0, "raw": ((frag.stdout or "") + (frag.stderr or "")).strip()}
        summary_line, impair_drops = kill_server(proc)
        proc = None
        stack_summary = None
        if summary.exists():
            try:
                stack_summary = json.loads(summary.read_text())
            except json.JSONDecodeError:
                stack_summary = {"parse_error": summary.read_text()[:500]}
        elif summary_line:
            try:
                stack_summary = json.loads(summary_line)
            except json.JSONDecodeError:
                stack_summary = None
        return {
            "cc": cc,
            "bytes": nbytes,
            "delay_ms": delay_ms,
            "loss_pct": loss_pct,
            "drop_seg": drop_seg,
            "shaping": shaping,
            "health": health,
            "ping": ping,
            "udp_echo": udp,
            "curl": xfer,
            "fragmented_ping": big_ping,
            "stack": stack_summary,
            "impair_drops": impair_drops,
        }
    finally:
        clear_netem()
        if proc is not None:
            kill_server(proc)


def median(values):
    vals = [v for v in values if v is not None]
    if not vals:
        return None
    return statistics.median(vals)


def own_results():
    """Servers run as root and leave root-owned traces. Hand them back."""
    if OUT.exists():
        sudo(["chown", "-R", f"{os.getuid()}:{os.getgid()}", str(OUT)], check=False)


def main():
    quick = "--quick" in sys.argv
    if not BUILD.exists():
        sys.exit(f"missing {BUILD}; build first")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "traces").mkdir(parents=True, exist_ok=True)
    own_results()
    clear_netem()
    runs = []
    # Baseline, no impairment. Five curls would restart the server five times.
    repeats = 1 if quick else 5
    for i in range(repeats):
        runs.append(
            one_transfer(
                "reno",
                262144 if quick else 1048576,
                0,
                0,
                None,
                OUT / "traces" / "baseline.pcap" if i == 0 else None,
                OUT / "traces" / "baseline.json" if i == 0 else None,
                OUT / f"baseline-{i}.sum",
            )
        )
    shaped = []
    if not quick:
        for cc in ("reno", "cubic"):
            for i in range(3):
                shaped.append(
                    one_transfer(
                        cc,
                        524288,
                        20,
                        1,
                        None,
                        None,
                        OUT / "traces" / f"netem-{cc}-{i}.json" if i == 0 else None,
                        OUT / f"netem-{cc}-{i}.sum",
                    )
                )
        # Single forced loss, delay only, so recovery is one event.
        for cc, seg in (("reno", 4), ("cubic", 4)):
            shaped.append(
                one_transfer(
                    cc,
                    524288,
                    20,
                    0,
                    seg,
                    OUT / "traces" / f"drop-{cc}.pcap",
                    OUT / "traces" / f"drop-{cc}.json",
                    OUT / f"drop-{cc}.sum",
                )
            )
    # A plain page fetch with a pcap, no extra load.
    page = one_transfer("reno", 0, 0, 0, None, OUT / "traces" / "http.pcap", OUT / "traces" / "http.json", OUT / "http.sum")

    def mbit(rows):
        return median([r["curl"]["mbit_per_sec"] for r in rows if r.get("curl", {}).get("ok")])

    tc_ok = netem_works()
    doc = {
        "tool": "curl, ping, and UDP against the userspace stack on a TAP",
        "impairment": "tc netem" if tc_ok else "TAP device delay and loss; sch_netem is not in this kernel",
        "tc_netem_available": tc_ok,
        "tc_netem_error": "" if tc_ok else NETEM_ERR,
        "topology": f"kernel {HOST}/24 on {TAP}, stack {STACK}",
        "repeats_baseline": repeats,
        "baseline_mbit_median": mbit(runs),
        "baseline_runs": runs,
        "impaired_runs": shaped,
        "page": page,
    }
    own_results()
    path = OUT / "measurements.json"
    path.write_text(json.dumps(doc, indent=2) + "\n")
    print(path)
    print("baseline median Mbit/s", doc["baseline_mbit_median"])
    if runs and runs[0]["curl"].get("ok"):
        print("sample", runs[0]["curl"])
    if runs:
        print("health", runs[0]["health"])
        print("ping", runs[0]["ping"].get("stats"))
        print("udp", runs[0]["udp_echo"])
    if shaped:
        print("impaired median Mbit/s", mbit(shaped))
        for row in shaped:
            curl = row.get("curl") or {}
            stack = row.get("stack") or {}
            print(
                row["cc"],
                "delay",
                row["delay_ms"],
                "loss",
                row["loss_pct"],
                "drop",
                row["drop_seg"],
                "curl_mbit",
                curl.get("mbit_per_sec"),
                "curl_ok",
                curl.get("ok"),
                "stack_mbit",
                stack.get("goodput_mbps"),
                "stack_bytes",
                stack.get("best_burst_bytes"),
                "retx",
                stack.get("retx"),
                "fast",
                stack.get("fast_retx"),
                "ping",
                (row.get("ping") or {}).get("stats"),
            )


if __name__ == "__main__":
    try:
        main()
    finally:
        clear_netem()
        own_results()
