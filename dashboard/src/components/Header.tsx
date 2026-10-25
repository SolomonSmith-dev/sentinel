const REPO = "https://github.com/SolomonSmith-dev/sentinel";

const STAGES = [
  { name: "Sensor", detail: "C++ libpcap + Suricata" },
  { name: "Rules + ML", detail: "detections, isolation forest" },
  { name: "Anonymize", detail: "hashed IDs, country codes" },
  { name: "Worker + D1", detail: "60 s rollups" },
  { name: "This page", detail: "polls every 10 s" },
];

function GitHubIcon() {
  return (
    <svg aria-hidden="true" viewBox="0 0 16 16" className="h-4 w-4 fill-current">
      <path d="M8 0C3.58 0 0 3.58 0 8a8 8 0 0 0 5.47 7.59c.4.07.55-.17.55-.38v-1.33c-2.23.48-2.7-1.07-2.7-1.07-.36-.92-.89-1.17-.89-1.17-.73-.5.05-.49.05-.49.8.06 1.23.83 1.23.83.72 1.22 1.87.87 2.33.66.07-.52.28-.87.5-1.07-1.78-.2-3.65-.89-3.65-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.28.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48v2.2c0 .21.15.46.55.38A8 8 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
    </svg>
  );
}

export function SeedBadge() {
  return (
    <p
      role="note"
      className="rise inline-flex items-center gap-2 rounded-full border border-dashed border-seed/45 bg-seed/[0.07] px-3 py-1 text-xs text-ink-2"
    >
      <svg aria-hidden="true" viewBox="0 0 12 12" className="h-3 w-3 shrink-0 fill-none stroke-seed" strokeWidth="1.4">
        <circle cx="6" cy="6" r="4.8" /><path d="M6 5.4v3M6 3.4v.2" strokeLinecap="round" />
      </svg>
      <span><span className="font-medium text-ink">Demo data:</span> synthetic seed until the live sensor reports</span>
    </p>
  );
}

export function Header({ seed, live }: { seed: boolean; live: boolean }) {
  return (
    <header className="rise flex flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
        <div className="min-w-0 max-w-2xl">
          <div className="flex items-center gap-3">
            <svg aria-hidden="true" viewBox="0 0 32 32" className="h-8 w-8 shrink-0">
              <path d="M16 3.5l10 3.9v7.6c0 6.2-4.2 11-10 13-5.8-2-10-6.8-10-13V7.4z" fill="rgb(92 225 166 / 0.08)" stroke="#5ce1a6" strokeWidth="1.8" strokeLinejoin="round" />
              <circle cx="16" cy="15" r="2.8" fill="#5ce1a6" />
            </svg>
            <h1 className="font-display text-3xl font-bold tracking-tight text-ink sm:text-4xl">Sentinel</h1>
            <span className="inline-flex items-center gap-2 rounded-full border border-line px-2.5 py-0.5 font-mono text-[11px] text-ink-2">
              <span className={`h-1.5 w-1.5 rounded-full ${live ? "live-dot bg-live" : "bg-ink-3"}`} aria-hidden="true" />
              {live ? "polling" : "paused"}
            </span>
          </div>
          <p className="mt-2 text-[15px] leading-relaxed text-ink-2">
            A home-network security monitor. A sensor on a home server watches flow metadata, flags floods, port scans,
            new devices and odd outbound geography, scores each device for anomalies, and ships anonymized one-minute
            rollups here. Monitor only: no payloads, no IPs, no MACs.
          </p>
        </div>
        <a
          href={REPO}
          className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-line bg-panel px-3 py-1.5 text-sm text-ink-2 transition-colors hover:border-line-strong hover:text-ink"
        >
          <GitHubIcon />
          Source on GitHub
        </a>
      </div>

      <nav aria-label="How data flows">
        <ol className="flex flex-wrap items-stretch gap-y-2 text-xs">
          {STAGES.map((s, i) => (
            <li key={s.name} className="flex items-center">
              <div className={`rounded-md border px-2.5 py-1 ${i === STAGES.length - 1 ? "border-live/40 bg-live/[0.06]" : "border-line bg-panel/70"}`}>
                <span className="font-medium text-ink">{s.name}</span>
                <span className="ml-1.5 hidden text-ink-3 sm:inline">{s.detail}</span>
              </div>
              {i < STAGES.length - 1 && (
                <svg aria-hidden="true" viewBox="0 0 20 8" className="mx-1 h-2 w-4 shrink-0 text-ink-3 sm:w-5">
                  <path d="M0 4h17M14 1l3 3-3 3" fill="none" stroke="currentColor" strokeWidth="1.2" />
                </svg>
              )}
            </li>
          ))}
        </ol>
      </nav>

      {seed && <div><SeedBadge /></div>}
    </header>
  );
}
