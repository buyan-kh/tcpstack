import { Viewer } from "@/components/viewer";

export default function Home() {
  return (
    <main className="mx-auto max-w-6xl px-4 py-8 sm:px-6 sm:py-12">
      <header className="mb-8 border-b border-border pb-6">
        <p className="font-mono text-[11px] tracking-[0.22em] text-primary uppercase">netstack</p>
        <h1 className="mt-2 font-sans text-4xl tracking-tight text-foreground sm:text-5xl">Connection traces</h1>
        <p className="mt-3 max-w-2xl text-sm leading-relaxed text-muted-foreground sm:text-base">
          Captures from the userspace TCP stack on a Linux TAP. Each file is the stack&apos;s own event log: sequence
          numbers, flags, the congestion window, and the moments a segment was dropped or fast-retransmitted.
        </p>
      </header>
      <Viewer />
    </main>
  );
}
