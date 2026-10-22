"use client";

import { formatBytes, formatUs, SSTHRESH_PLOT_MAX, type TraceEvent } from "@/lib/trace";

const W = 800;
const H = 280;
const PAD = { l: 64, r: 16, t: 16, b: 32 };

export function CwndChart({
  events,
  originUs,
  cursorUs,
}: {
  events: TraceEvent[];
  originUs: number;
  cursorUs: number;
}) {
  const pts = events.filter((ev) => ev.cwnd > 0);
  if (pts.length === 0) {
    return (
      <p className="px-4 py-10 text-sm text-muted-foreground">
        No congestion window was recorded for this connection.
      </p>
    );
  }

  const t0 = pts[0].t_us;
  const t1 = pts[pts.length - 1].t_us;
  const span = Math.max(1, t1 - t0);
  const cwndMax = Math.max(...pts.map((ev) => ev.cwnd));
  const ssValues = pts.map((ev) => ev.ssthresh).filter((v) => v > 0 && v <= SSTHRESH_PLOT_MAX);
  const yMax = Math.max(cwndMax, ...(ssValues.length ? ssValues : [0])) * 1.08 || 1;

  const xOf = (t: number) => PAD.l + ((t - t0) / span) * (W - PAD.l - PAD.r);
  const yOf = (v: number) => PAD.t + (1 - v / yMax) * (H - PAD.t - PAD.b);

  const line = (pick: (ev: TraceEvent) => number | null) =>
    pts
      .map((ev) => {
        const v = pick(ev);
        if (v == null) return null;
        return `${xOf(ev.t_us).toFixed(1)},${yOf(v).toFixed(1)}`;
      })
      .filter(Boolean)
      .join(" ");

  const cwnd = line((ev) => ev.cwnd);
  const ssthresh = line((ev) => (ev.ssthresh > 0 && ev.ssthresh <= SSTHRESH_PLOT_MAX ? ev.ssthresh : null));
  const cursorT = Math.min(Math.max(cursorUs, t0), t1);
  const marks = pts.filter((ev) => ev.kind === "drop" || ev.kind === "fast_retransmit" || ev.kind === "rto");
  const ticks = 4;

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label="Congestion window over time">
      {Array.from({ length: ticks + 1 }, (_, i) => {
        const v = (yMax * i) / ticks;
        const y = yOf(v);
        return (
          <g key={i}>
            <line x1={PAD.l} x2={W - PAD.r} y1={y} y2={y} stroke="#2c261f" />
            <text x={PAD.l - 8} y={y + 4} textAnchor="end" fill="#8d8174" fontSize="11" fontFamily="IBM Plex Mono, ui-monospace, monospace">
              {formatBytes(v)}
            </text>
          </g>
        );
      })}
      <text x={PAD.l} y={H - 8} fill="#8d8174" fontSize="11" fontFamily="IBM Plex Mono, ui-monospace, monospace">
        {formatUs(t0 - originUs)}
      </text>
      <text x={W - PAD.r} y={H - 8} textAnchor="end" fill="#8d8174" fontSize="11" fontFamily="IBM Plex Mono, ui-monospace, monospace">
        {formatUs(t1 - originUs)}
      </text>
      {ssthresh && <polyline fill="none" stroke="#8fbf9f" strokeWidth="1.25" strokeDasharray="4 3" points={ssthresh} />}
      <polyline fill="none" stroke="#e0b07a" strokeWidth="1.75" points={cwnd} />
      {marks.map((ev, i) => (
        <circle
          key={`${ev.kind}-${ev.t_us}-${i}`}
          cx={xOf(ev.t_us)}
          cy={yOf(ev.cwnd)}
          r="3.5"
          fill={ev.kind === "fast_retransmit" ? "#e8b86d" : "#e07a5f"}
        />
      ))}
      <line x1={xOf(cursorT)} x2={xOf(cursorT)} y1={PAD.t} y2={H - PAD.b} stroke="#f3ead7" strokeOpacity="0.7" />
    </svg>
  );
}
