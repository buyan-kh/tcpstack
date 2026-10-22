export type TraceEvent = {
  t_us: number;
  dir: "tx" | "rx" | string;
  kind: string;
  flags: string;
  seq: number;
  ack: number;
  len: number;
  win: number;
  state: string;
  cwnd: number;
  ssthresh: number;
  flight: number;
  algo: string;
  local: string;
  peer: string;
};

export type TraceFile = {
  v: number;
  title: string;
  description: string;
  source: string;
  algo: string;
  events: TraceEvent[];
};

export type TraceMeta = {
  id: string;
  file: string;
  title: string;
  blurb: string;
};

export type TraceIndex = {
  traces: TraceMeta[];
};

/** Initial ssthresh is a stand-in for infinity (0x3fffffff). Keep it off the chart. */
export const SSTHRESH_PLOT_MAX = 8 * 1024 * 1024;

export function connKey(ev: TraceEvent): string {
  return `${ev.local}  ${ev.peer}`;
}

export function formatUs(us: number): string {
  if (us < 1000) return `${us.toFixed(0)} µs`;
  if (us < 1_000_000) return `${(us / 1000).toFixed(2)} ms`;
  return `${(us / 1_000_000).toFixed(3)} s`;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export function eventLabel(ev: TraceEvent): string {
  if (ev.kind === "segment") {
    const payload = ev.len > 0 ? ` ${ev.len}B` : "";
    return `${ev.flags || "ACK"}${payload}`;
  }
  return ev.kind.replaceAll("_", " ");
}
