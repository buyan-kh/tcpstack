"use client";

import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { CwndChart } from "@/components/cwnd-chart";
import { SequenceDiagram } from "@/components/sequence-diagram";
import {
  connKey,
  formatBytes,
  formatUs,
  type TraceEvent,
  type TraceFile,
  type TraceIndex,
  type TraceMeta,
} from "@/lib/trace";

const SPEEDS = [1, 10, 50];

export function Viewer() {
  const [index, setIndex] = useState<TraceMeta[] | null>(null);
  const [indexError, setIndexError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [trace, setTrace] = useState<TraceFile | null>(null);
  const [traceError, setTraceError] = useState<string | null>(null);
  const [loadingTrace, setLoadingTrace] = useState(false);
  const [conn, setConn] = useState<string>("all");
  const [playhead, setPlayhead] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(10);

  useEffect(() => {
    let cancel = false;
    fetch("/traces/index.json")
      .then((res) => {
        if (!res.ok) throw new Error(`index ${res.status}`);
        return res.json() as Promise<TraceIndex>;
      })
      .then((doc) => {
        if (cancel) return;
        setIndex(doc.traces);
        setSelected(doc.traces[0]?.id ?? null);
      })
      .catch((err: unknown) => {
        if (!cancel) setIndexError(err instanceof Error ? err.message : "could not load the trace index");
      });
    return () => {
      cancel = true;
    };
  }, []);

  useEffect(() => {
    if (!index || !selected) return;
    const meta = index.find((item) => item.id === selected);
    if (!meta) return;
    let cancel = false;
    setLoadingTrace(true);
    setTraceError(null);
    setPlaying(false);
    fetch(`/traces/${meta.file}`)
      .then((res) => {
        if (!res.ok) throw new Error(`${meta.file} ${res.status}`);
        return res.json() as Promise<TraceFile>;
      })
      .then((doc) => {
        if (cancel) return;
        setTrace(doc);
        const counts = new Map<string, number>();
        for (const ev of doc.events) counts.set(connKey(ev), (counts.get(connKey(ev)) ?? 0) + 1);
        const busiest = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "all";
        setConn(busiest);
        setPlayhead(doc.events[0]?.t_us ?? 0);
        setLoadingTrace(false);
      })
      .catch((err: unknown) => {
        if (cancel) return;
        setTrace(null);
        setLoadingTrace(false);
        setTraceError(err instanceof Error ? err.message : "could not load the trace");
      });
    return () => {
      cancel = true;
    };
  }, [index, selected]);

  const events = useMemo(() => trace?.events ?? [], [trace]);
  const origin = events[0]?.t_us ?? 0;
  const end = events[events.length - 1]?.t_us ?? origin;
  const connections = useMemo(() => {
    const counts = new Map<string, number>();
    for (const ev of events) counts.set(connKey(ev), (counts.get(connKey(ev)) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [events]);

  const visible = useMemo(
    () => (conn === "all" ? events : events.filter((ev) => connKey(ev) === conn)),
    [events, conn],
  );

  useEffect(() => {
    if (!playing) return;
    let frame = 0;
    let last = performance.now();
    const step = (now: number) => {
      const dtUs = (now - last) * 1000 * speed;
      last = now;
      setPlayhead((current) => {
        const next = current + dtUs;
        if (next >= end) {
          setPlaying(false);
          return end;
        }
        return next;
      });
      frame = requestAnimationFrame(step);
    };
    frame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame);
  }, [playing, speed, end]);

  const current: TraceEvent | undefined = [...visible].reverse().find((ev) => ev.t_us <= playhead) ?? visible[0];
  const meta = index?.find((item) => item.id === selected);

  if (indexError) {
    return (
      <div className="border border-destructive/40 bg-card px-5 py-8">
        <p className="font-mono text-sm text-destructive">Could not load traces. {indexError}</p>
      </div>
    );
  }

  if (!index) {
    return <p className="font-mono text-sm text-muted-foreground">Loading traces…</p>;
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[240px_minmax(0,1fr)]">
      <aside className="flex gap-2 overflow-x-auto lg:flex-col lg:overflow-visible">
        {index.map((item) => (
          <button
            key={item.id}
            type="button"
            onClick={() => setSelected(item.id)}
            className={`min-w-[200px] border px-3 py-3 text-left lg:min-w-0 ${
              item.id === selected ? "border-primary bg-card" : "border-border bg-transparent hover:bg-card"
            }`}
          >
            <span className="block font-sans text-base text-foreground">{item.title}</span>
            <span className="mt-1 block font-mono text-[11px] leading-snug text-muted-foreground">{item.id}</span>
          </button>
        ))}
      </aside>

      <section className="min-w-0">
        <div className="mb-4 flex flex-col gap-3 border-b border-border pb-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h2 className="font-sans text-3xl tracking-tight text-foreground">{meta?.title}</h2>
            <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted-foreground">{meta?.blurb}</p>
          </div>
          <p className="font-mono text-[11px] text-muted-foreground">
            {trace ? `${trace.source} · ${trace.algo} · ${events.length} events` : "—"}
          </p>
        </div>

        {traceError && <p className="font-mono text-sm text-destructive">Could not load this trace. {traceError}</p>}
        {loadingTrace && <p className="font-mono text-sm text-muted-foreground">Reading the capture…</p>}

        {trace && !loadingTrace && (
          <>
            <div className="mb-4 flex flex-wrap items-center gap-2">
              <Button type="button" onClick={() => setPlaying((on) => !on)} disabled={visible.length === 0}>
                {playing ? "Pause" : "Play"}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setPlaying(false);
                  setPlayhead(origin);
                }}
              >
                Restart
              </Button>
              {SPEEDS.map((value) => (
                <Button
                  key={value}
                  type="button"
                  variant={speed === value ? "secondary" : "ghost"}
                  onClick={() => setSpeed(value)}
                >
                  {value}×
                </Button>
              ))}
              <label className="ml-auto flex min-w-[180px] flex-1 items-center gap-3 font-mono text-[11px] text-muted-foreground">
                <span className="shrink-0">{formatUs(Math.max(0, playhead - origin))}</span>
                <input
                  className="h-1 w-full accent-[#e0b07a]"
                  type="range"
                  min={origin}
                  max={end}
                  step={1}
                  value={Math.min(playhead, end)}
                  onChange={(event) => {
                    setPlaying(false);
                    setPlayhead(Number(event.target.value));
                  }}
                  aria-label="Trace time"
                />
              </label>
            </div>

            <div className="mb-4 flex flex-wrap items-center gap-2">
              <label className="font-mono text-[11px] tracking-wide text-muted-foreground uppercase" htmlFor="conn">
                Connection
              </label>
              <select
                id="conn"
                value={conn}
                onChange={(event) => setConn(event.target.value)}
                className="border border-border bg-card px-2 py-1 font-mono text-xs text-foreground"
              >
                <option value="all">All ({events.length})</option>
                {connections.map(([key, count]) => (
                  <option key={key} value={key}>
                    {key} ({count})
                  </option>
                ))}
              </select>
              <span className="font-mono text-[11px] text-muted-foreground">
                Time is relative to the first event. Raw stack clock starts at process start.
              </span>
            </div>

            <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)]">
              <div className="border border-border bg-card">
                <div className="flex items-baseline justify-between border-b border-border px-4 py-2">
                  <h3 className="font-sans text-lg">Sequence</h3>
                  <p className="font-mono text-[11px] text-muted-foreground">tx leaves the stack · rx arrives</p>
                </div>
                <SequenceDiagram events={visible} originUs={origin} cursorUs={playhead} />
              </div>
              <div className="border border-border bg-card">
                <div className="flex items-baseline justify-between border-b border-border px-4 py-2">
                  <h3 className="font-sans text-lg">Window</h3>
                  <p className="font-mono text-[11px] text-muted-foreground">
                    <span className="text-[#e0b07a]">cwnd</span>
                    {" · "}
                    <span className="text-[#8fbf9f]">ssthresh</span>
                  </p>
                </div>
                <CwndChart events={visible} originUs={origin} cursorUs={playhead} />
                <p className="px-4 pb-3 font-mono text-[11px] text-muted-foreground">
                  Gold is cwnd. Green dashes are ssthresh after it leaves the initial ceiling. Amber marks a fast
                  retransmit. Red marks a drop or an RTO.
                </p>
              </div>
            </div>

            <div className="mt-4 border border-border bg-card">
              <h3 className="border-b border-border px-4 py-2 font-sans text-lg">Segment</h3>
              {current ? (
                <dl className="grid grid-cols-2 gap-x-6 gap-y-2 px-4 py-3 font-mono text-xs sm:grid-cols-4">
                  <Stat label="rel" value={formatUs(Math.max(0, current.t_us - origin))} />
                  <Stat label="dir" value={current.dir} />
                  <Stat label="kind" value={current.kind} />
                  <Stat label="flags" value={current.flags || "—"} />
                  <Stat label="seq" value={String(current.seq)} />
                  <Stat label="ack" value={String(current.ack)} />
                  <Stat label="len" value={String(current.len)} />
                  <Stat label="win" value={String(current.win)} />
                  <Stat label="state" value={current.state || "—"} />
                  <Stat label="cwnd" value={formatBytes(current.cwnd)} />
                  <Stat label="flight" value={formatBytes(current.flight)} />
                  <Stat label="algo" value={current.algo || "—"} />
                </dl>
              ) : (
                <p className="px-4 py-6 text-sm text-muted-foreground">Move the playhead onto a segment.</p>
              )}
            </div>
          </>
        )}
      </section>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[10px] tracking-wide text-muted-foreground uppercase">{label}</dt>
      <dd className="truncate text-foreground">{value}</dd>
    </div>
  );
}
