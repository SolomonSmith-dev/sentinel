import { useState } from "react";
import type { TopResponse } from "../lib/types";
import type { PollState } from "../lib/poll";
import { countryName, formatBytes } from "../lib/format";
import { Panel, Skeleton, Empty } from "./Panel";

interface Item { key: string; primary: string; secondary: string; bytes: number }

function Bars({ items, label }: { items: Item[]; label: string }) {
  if (!items.length) return <Empty>Nothing yet.</Empty>;
  const max = Math.max(...items.map((i) => i.bytes), 1);
  const total = items.reduce((a, i) => a + i.bytes, 0);
  return (
    <ol className="space-y-2.5" aria-label={label}>
      {items.map((it) => {
        const pct = total ? (it.bytes / total) * 100 : 0;
        return (
          <li key={it.key} className="group" title={`${it.primary} · ${formatBytes(it.bytes)} (${pct.toFixed(1)}% of top 10)`}>
            <div className="flex items-baseline gap-2 text-xs">
              <span className="font-mono text-ink">{it.primary}</span>
              <span className="min-w-0 flex-1 truncate text-ink-3">{it.secondary}</span>
              <span className="font-mono text-ink-2 tnum">{formatBytes(it.bytes)}</span>
            </div>
            <div className="mt-1 h-1.5 rounded-full bg-line/60" aria-hidden="true">
              <div
                className="h-full rounded-r-[4px] rounded-l-[1px] bg-series-in transition-[width] duration-500 group-hover:brightness-125"
                style={{ width: `${Math.max(1.5, (it.bytes / max) * 100)}%` }}
              />
            </div>
          </li>
        );
      })}
    </ol>
  );
}

export function TopTalkers({ poll, rangeLabel }: { poll: PollState<TopResponse>; rangeLabel: string }) {
  const [tab, setTab] = useState<"devices" | "countries">("devices");
  const data = poll.data;

  const devices: Item[] = (data?.devices ?? []).map((d) => ({ key: d.device_hash, primary: d.device_hash, secondary: d.vendor, bytes: d.bytes }));
  const countries: Item[] = (data?.countries ?? []).map((c) => ({ key: c.country, primary: c.country, secondary: countryName(c.country), bytes: c.bytes }));

  const tabs = (
    <div role="tablist" aria-label="Top talkers by" className="inline-flex rounded-lg border border-line bg-bg/60 p-0.5">
      {(["devices", "countries"] as const).map((t) => (
        <button
          key={t}
          role="tab"
          id={`top-tab-${t}`}
          aria-selected={tab === t}
          aria-controls="top-tabpanel"
          type="button"
          onClick={() => setTab(t)}
          className={`rounded-md px-2.5 py-1 text-xs capitalize transition-colors ${
            tab === t ? "bg-raised text-ink shadow-[0_0_0_1px_var(--color-line-strong)]" : "text-ink-3 hover:text-ink-2"
          }`}
        >
          {t}
        </button>
      ))}
    </div>
  );

  return (
    <Panel id="top" title="Top talkers" subtitle={`Total bytes, last ${rangeLabel}`} poll={poll} actions={tabs} delay={240}>
      {data == null ? (
        <div className="space-y-3" aria-hidden="true">
          {Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-7" />)}
        </div>
      ) : (
        <div id="top-tabpanel" role="tabpanel" aria-labelledby={`top-tab-${tab}`} className={poll.pending ? "opacity-50 transition-opacity" : ""}>
          {tab === "devices"
            ? <Bars items={devices} label="Top devices by bytes" />
            : <Bars items={countries} label="Top countries by bytes" />}
          <p className="mt-4 text-[11px] leading-relaxed text-ink-3">
            Destinations are reduced to country codes on the sensor. No IPs leave the house.
          </p>
        </div>
      )}
    </Panel>
  );
}
