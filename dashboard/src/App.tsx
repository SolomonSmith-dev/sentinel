import { useEffect, useState } from "react";
import { usePoll } from "./lib/poll";
import { isSeed, type AlertsResponse, type DevicesResponse, type FlowsResponse, type MetricsResponse, type TopResponse } from "./lib/types";
import { Header } from "./components/Header";
import { RANGES, TrafficChart, type RangeMinutes } from "./components/TrafficChart";
import { AlertFeed } from "./components/AlertFeed";
import { DeviceGrid } from "./components/DeviceGrid";
import { TopTalkers } from "./components/TopTalkers";
import { MetricsStrip } from "./components/MetricsStrip";

function readRange(): RangeMinutes {
  try {
    const v = Number(localStorage.getItem("sentinel.range"));
    if (RANGES.some((r) => r.minutes === v)) return v as RangeMinutes;
  } catch { /* storage blocked */ }
  return 60;
}

function useVisible() {
  const [visible, setVisible] = useState(() => document.visibilityState === "visible");
  useEffect(() => {
    const on = () => setVisible(document.visibilityState === "visible");
    document.addEventListener("visibilitychange", on);
    return () => document.removeEventListener("visibilitychange", on);
  }, []);
  return visible;
}

export default function App() {
  const [minutes, setMinutes] = useState<RangeMinutes>(readRange);
  const visible = useVisible();

  const flows = usePoll<FlowsResponse>(`/api/flows?minutes=${minutes}`);
  const alerts = usePoll<AlertsResponse>("/api/alerts?limit=50");
  const devices = usePoll<DevicesResponse>("/api/devices");
  const top = usePoll<TopResponse>(`/api/top?minutes=${minutes}`);
  const metrics = usePoll<MetricsResponse>("/api/metrics");

  const onMinutes = (m: RangeMinutes) => {
    setMinutes(m);
    try { localStorage.setItem("sentinel.range", String(m)); } catch { /* ignore */ }
  };

  const seed =
    isSeed(flows.data?.is_seed) ||
    !!alerts.data?.alerts.some((a) => isSeed(a.is_seed)) ||
    !!devices.data?.devices.some((d) => isSeed(d.is_seed)) ||
    !!top.data?.devices.some((d) => isSeed(d.is_seed)) ||
    metrics.data?.seed_active === true;

  const rangeLabel = RANGES.find((r) => r.minutes === minutes)?.label ?? `${minutes}m`;

  return (
    <div className="mx-auto flex w-full max-w-[1400px] flex-col gap-5 px-4 py-6 sm:px-6 sm:py-8 lg:px-8">
      <Header seed={seed} live={visible} />
      <main className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <div className="min-w-0 lg:col-span-2"><TrafficChart poll={flows} minutes={minutes} onMinutes={onMinutes} /></div>
        <div className="min-w-0"><AlertFeed poll={alerts} /></div>
        <div className="min-w-0 lg:col-span-2"><DeviceGrid poll={devices} /></div>
        <div className="min-w-0"><TopTalkers poll={top} rangeLabel={rangeLabel} /></div>
      </main>
      <footer className="flex flex-col gap-3">
        <MetricsStrip poll={metrics} />
        <p className="text-center text-[11px] text-ink-3">
          Device IDs are salted hashes. Times shown in your local time zone. Data refreshes every 10 s while this tab is visible.
        </p>
      </footer>
    </div>
  );
}
