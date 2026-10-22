"use client";

import { useEffect, useRef } from "react";
import { eventLabel, formatUs, type TraceEvent } from "@/lib/trace";

const ROW = 26;
const WINDOW = 42;

function tone(ev: TraceEvent): string {
  if (ev.kind === "drop" || ev.kind === "rto") return "#e07a5f";
  if (ev.kind === "fast_retransmit") return "#e8b86d";
  if (ev.kind === "recovery_exit") return "#8fbf9f";
  if (ev.flags.includes("SYN")) return "#e0b07a";
  if (ev.flags.includes("FIN")) return "#cbbba6";
  if (ev.len > 0) return "#f0d7b4";
  return "#8d8174";
}

export function SequenceDiagram({
  events,
  originUs,
  cursorUs,
}: {
  events: TraceEvent[];
  originUs: number;
  cursorUs: number;
}) {
  const scroller = useRef<HTMLDivElement>(null);
  const cursorIndex = events.reduce((acc, ev, i) => (ev.t_us <= cursorUs ? i : acc), -1);
  const start = Math.max(0, cursorIndex - WINDOW + 1);
  const slice = events.slice(start, Math.max(cursorIndex + 1, 0));
  const height = Math.max(slice.length, 1) * ROW + 36;

  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [cursorIndex, events]);

  if (events.length === 0) {
    return (
      <p className="px-4 py-10 text-sm text-muted-foreground">
        This connection has no segments in the trace.
      </p>
    );
  }

  return (
    <div className="flex h-full min-h-[280px] flex-col">
      <div className="flex items-center justify-between border-b border-border px-4 py-2 text-[11px] tracking-wide text-muted-foreground uppercase">
        <span>Stack</span>
        <span>
          {cursorIndex + 1} / {events.length}
          {slice.length < events.length ? ` · last ${slice.length}` : ""}
        </span>
        <span>Peer</span>
      </div>
      <div ref={scroller} className="min-h-0 flex-1 overflow-auto">
        <svg
          viewBox={`0 0 720 ${height}`}
          className="w-full"
          role="img"
          aria-label="TCP sequence diagram"
        >
          <line x1="150" y1="16" x2="150" y2={height - 12} stroke="#3d3428" strokeWidth="1" />
          <line x1="570" y1="16" x2="570" y2={height - 12} stroke="#3d3428" strokeWidth="1" />
          {slice.map((ev, i) => {
            const y = 28 + i * ROW;
            const fromStack = ev.dir === "tx";
            const x1 = fromStack ? 150 : 570;
            const x2 = fromStack ? 570 : 150;
            const color = tone(ev);
            const dashed = ev.kind === "drop";
            return (
              <g key={`${ev.t_us}-${i}`}>
                <text x="8" y={y + 4} fill="#8d8174" fontSize="11" fontFamily="IBM Plex Mono, ui-monospace, monospace">
                  {formatUs(ev.t_us - originUs)}
                </text>
                <line
                  x1={x1}
                  y1={y}
                  x2={x2}
                  y2={y}
                  stroke={color}
                  strokeWidth={ev.len > 0 || ev.kind !== "segment" ? 1.6 : 1}
                  strokeDasharray={dashed ? "4 3" : undefined}
                />
                <polygon
                  points={
                    fromStack
                      ? `${x2},${y} ${x2 - 7},${y - 3.5} ${x2 - 7},${y + 3.5}`
                      : `${x2},${y} ${x2 + 7},${y - 3.5} ${x2 + 7},${y + 3.5}`
                  }
                  fill={color}
                />
                <text
                  x="360"
                  y={y - 4}
                  textAnchor="middle"
                  fill={color}
                  fontSize="11"
                  fontFamily="IBM Plex Mono, ui-monospace, monospace"
                >
                  {eventLabel(ev)}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
