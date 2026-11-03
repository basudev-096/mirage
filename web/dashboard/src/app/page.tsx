"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Activity, BarChart3, CircleDot, Globe2, LayoutDashboard, Menu, Radio,
  ShieldAlert, ShieldCheck, Timer, TrendingUp,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface TelemetryEvent {
  timestamp: string;
  source_ip: string;
  method: string;
  path: string;
  verdict: string;
  category?: string;
  action: string;
  phase: string;
  score?: number;
  inspection_time_us?: number;
  tarpit_duration_ms?: number;
  bytes_served?: number;
}

const SOCKET_URL = process.env.NEXT_PUBLIC_MIRAGE_WS_URL;

function Sidebar({ mobileOpen, close }: { mobileOpen: boolean; close: () => void }) {
  const links = [
    { label: "Overview", icon: LayoutDashboard, href: "/", active: true },
    { label: "Live Events", icon: Radio, href: "/events" },
    { label: "Source IPs", icon: Globe2, href: "/sources" },
    { label: "Attack Categories", icon: BarChart3, href: "/categories" },
    { label: "Tarpit Activity", icon: Timer, href: "/tarpits" },
    { label: "System Health", icon: Activity, href: "/health" },
  ];
  return <aside className={`fixed inset-y-0 left-0 z-40 flex w-72 flex-col border-r border-[#26302d] bg-[#090d13] transition-transform lg:translate-x-0 ${mobileOpen ? "translate-x-0" : "-translate-x-full"}`}>
    <div className="flex h-16 items-center gap-3 border-b border-[#26302d] bg-[#111720] px-6">
      <div className="flex h-8 w-8 items-center justify-center rounded bg-[#4edea3] text-[#062519]"><ShieldCheck className="h-5 w-5" /></div>
      <div><div className="font-mono text-sm font-semibold uppercase tracking-[0.18em] text-[#4edea3]">Mirage</div><div className="font-mono text-[9px] uppercase tracking-[0.2em] text-[#86948a]">Active Defense</div></div>
    </div>
    <div className="px-5 pb-2 pt-7 font-mono text-[10px] uppercase tracking-[0.18em] text-[#66736d]">Sinks &amp; monitors</div>
    <nav className="flex flex-col gap-1 px-3">{links.map(({ label, icon: Icon, href, active }) => <a key={href} href={href} onClick={close} className={`flex items-center gap-3 rounded px-4 py-3 font-mono text-xs uppercase tracking-wide transition-colors ${active ? "bg-[#202b2a] font-semibold text-[#4edea3]" : "text-[#aab7b0] hover:bg-[#17201f] hover:text-[#dfe2ef]"}`}><Icon className="h-[18px] w-[18px]" />{label}</a>)}</nav>
    <div className="mt-auto border-t border-[#26302d] bg-[#111720] p-5"><div className="mb-3 flex items-center justify-between font-mono text-[10px] uppercase tracking-wider text-[#86948a]"><span>Telemetry stream</span><span className="flex items-center gap-2 text-[#4edea3]"><span className="h-2 w-2 animate-pulse rounded-full bg-[#4edea3]" /> Live</span></div><div className="rounded bg-[#090d13] p-3 font-mono text-[10px] text-[#66736d]">Current browser session only</div></div>
  </aside>;
}

function formatDuration(ms: number) {
  return ms ? `${(ms / 1000).toFixed(1)}s` : "—";
}

function formatTime(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleTimeString([], { hour12: false });
}

export default function Home() {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [status, setStatus] = useState<"connecting" | "live" | "offline">(SOCKET_URL ? "connecting" : "offline");

  useEffect(() => {
    if (!SOCKET_URL) return;
    let stopped = false;
    let socket: WebSocket | undefined;
    let reconnect: ReturnType<typeof setTimeout> | undefined;
    const connect = () => {
      if (stopped) return;
      setStatus("connecting");
      socket = new WebSocket(SOCKET_URL);
      socket.onopen = () => setStatus("live");
      socket.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data) as TelemetryEvent;
          if (!event.timestamp || !event.source_ip || !event.path) return;
          setEvents((current) => [event, ...current].slice(0, 100));
        } catch {
          // Ignore malformed telemetry without interrupting the stream.
        }
      };
      socket.onerror = () => socket?.close();
      socket.onclose = () => {
        if (!stopped) {
          setStatus("offline");
          reconnect = setTimeout(connect, 2000);
        }
      };
    };
    connect();
    return () => {
      stopped = true;
      if (reconnect) clearTimeout(reconnect);
      socket?.close();
    };
  }, []);

  const malicious = events.filter((event) => event.verdict.toLowerCase() === "malicious");
  const tarpits = events.filter((event) => event.action.toLowerCase() === "tarpit");
  const honeypots = events.filter((event) => event.action.toLowerCase() === "honeypot");
  const uniqueSources = new Set(events.map((event) => event.source_ip)).size;
  const avgInspection = events.length ? events.reduce((sum, event) => sum + (event.inspection_time_us ?? 0), 0) / events.length / 1000 : 0;
  const avgTarpit = tarpits.length ? tarpits.reduce((sum, event) => sum + (event.tarpit_duration_ms ?? 0), 0) / tarpits.length : 0;
  const categoryCounts = useMemo(() => {
    const counts = new Map<string, number>();
    malicious.forEach((event) => counts.set(event.category || "Unknown", (counts.get(event.category || "Unknown") ?? 0) + 1));
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [malicious]);
  const recent = events.slice(0, 8);

  return <div className="min-h-screen bg-[#0f131c] text-[#dfe2ef]">
    <Sidebar mobileOpen={mobileOpen} close={() => setMobileOpen(false)} />
    <div className="lg:pl-72">
      <header className="fixed left-0 right-0 top-0 z-30 flex h-16 items-center justify-between border-b border-[#26302d] bg-[#0f131c]/95 px-5 backdrop-blur lg:left-72 lg:px-8">
        <div className="flex items-center gap-3"><button onClick={() => setMobileOpen(true)} className="rounded p-2 text-[#aab7b0] hover:bg-[#202b2a] lg:hidden" aria-label="Open navigation"><Menu className="h-5 w-5" /></button><span className="font-mono text-xs uppercase tracking-[0.18em] text-[#4edea3]">Mirage</span><span className="font-mono text-xs uppercase tracking-[0.18em] text-[#86948a]">/ Live Telemetry Console</span></div>
        <div className={`flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider ${status === "live" ? "text-[#4edea3]" : "text-[#ffb86b]"}`}><CircleDot className="h-3 w-3" />{status === "live" ? "Stream live" : status}</div>
      </header>
      <main className="min-h-screen px-5 pb-14 pt-24 lg:px-10">
        <section className="mb-6 flex flex-col justify-between gap-5 rounded-xl border border-[#26302d] bg-[#181b25] p-6 lg:flex-row lg:items-center">
          <div className="flex gap-4"><div className="flex h-11 w-11 shrink-0 items-center justify-center rounded bg-[#202b2a] text-[#4edea3]"><Activity className="h-5 w-5" /></div><div><div className="mb-1 flex items-center gap-2 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-[#4edea3]"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[#4edea3]" /> Operational status</div><h1 className="text-2xl font-semibold tracking-tight">Live Overview</h1><p className="mt-1 font-mono text-xs text-[#86948a]">Real-time active-defense telemetry from the current browser session.</p></div></div>
          <div className="rounded bg-[#202b2a] px-4 py-2 font-mono text-[10px] uppercase tracking-wider text-[#86948a]">Buffer <strong className="ml-2 text-[#dfe2ef]">{events.length} / 100</strong></div>
        </section>

        <section className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {([
            ["Events received", events.length, "Current session", Activity, "text-[#4edea3]"],
            ["Malicious events", malicious.length, events.length ? `${((malicious.length / events.length) * 100).toFixed(1)}% of buffer` : "Awaiting data", ShieldAlert, "text-[#ff746c]"],
            ["Active defense", honeypots.length + tarpits.length, `${tarpits.length} tarpit · ${honeypots.length} honeypot`, ShieldCheck, "text-[#4edea3]"],
            ["Observed sources", uniqueSources, `${formatDuration(avgTarpit)} avg tarpit`, Globe2, "text-[#c0c1ff]"],
          ] as [string, number, string, LucideIcon, string][]).map(([label, value, note, Icon, color]) => <div key={String(label)} className="rounded-xl border border-[#26302d] bg-[#181b25] p-5"><div className="flex items-center justify-between"><span className="font-mono text-[10px] uppercase tracking-wider text-[#86948a]">{label}</span><Icon className={`h-4 w-4 ${color}`} /></div><div className="mt-4 flex items-baseline gap-2"><span className="font-mono text-3xl font-semibold text-[#dfe2ef]">{value}</span></div><div className="mt-2 font-mono text-[10px] text-[#66736d]">{note}</div></div>)}
        </section>

        <section className="mb-6 grid gap-5 xl:grid-cols-[1.4fr_0.6fr]">
          <div className="rounded-xl border border-[#26302d] bg-[#181b25] p-5"><div className="mb-5 flex items-center justify-between"><div><h2 className="font-mono text-xs font-semibold uppercase tracking-[0.14em]">Live event activity</h2><p className="mt-1 font-mono text-[10px] text-[#66736d]">Latest events received · no historical data</p></div><TrendingUp className="h-4 w-4 text-[#4edea3]" /></div><div className="flex h-44 items-end gap-1 border-b border-l border-[#26302d] px-3 pb-0">{Array.from({ length: 32 }, (_, index) => { const count = events.filter((event) => new Date(event.timestamp).getMinutes() === new Date(Date.now() - (31 - index) * 60000).getMinutes()).length; return <div key={index} className="flex-1 rounded-t bg-[#4edea3]/70 transition-all" style={{ height: `${Math.max(count ? Math.min(count * 18, 100) : 2, 2)}%` }} />; })}</div><div className="mt-3 flex justify-between font-mono text-[9px] uppercase text-[#66736d]"><span>32 min ago</span><span>Now</span></div></div>
          <div className="rounded-xl border border-[#26302d] bg-[#181b25] p-5"><div className="mb-5 flex items-center justify-between"><div><h2 className="font-mono text-xs font-semibold uppercase tracking-[0.14em]">Attack categories</h2><p className="mt-1 font-mono text-[10px] text-[#66736d]">Malicious events only</p></div><BarChart3 className="h-4 w-4 text-[#4edea3]" /></div>{categoryCounts.length ? <div className="space-y-4">{categoryCounts.slice(0, 5).map(([category, count]) => <div key={category}><div className="mb-1 flex justify-between font-mono text-[10px]"><span className="text-[#aab7b0]">{category}</span><span className="text-[#4edea3]">{count}</span></div><div className="h-1.5 rounded bg-[#26302d]"><div className="h-full rounded bg-[#4edea3]" style={{ width: `${(count / malicious.length) * 100}%` }} /></div></div>)}</div> : <div className="py-12 text-center font-mono text-[10px] uppercase tracking-wider text-[#66736d]">Waiting for attack telemetry</div>}</div>
        </section>

        <section className="grid gap-5 xl:grid-cols-[1.4fr_0.6fr]">
          <div className="overflow-hidden rounded-xl border border-[#26302d] bg-[#181b25]"><div className="flex items-center justify-between border-b border-[#26302d] px-5 py-4"><div><h2 className="font-mono text-xs font-semibold uppercase tracking-[0.14em]">Recent event stream</h2><p className="mt-1 font-mono text-[10px] text-[#66736d]">Current session · latest 8 events</p></div><a href="/events" className="font-mono text-[10px] uppercase tracking-wider text-[#4edea3] hover:underline">Open stream →</a></div><div className="overflow-x-auto"><table className="w-full min-w-[720px] text-left"><thead className="border-b border-[#26302d] bg-[#111720] font-mono text-[10px] uppercase tracking-wider text-[#66736d]"><tr><th className="px-5 py-3">Time</th><th className="px-3 py-3">Source IP</th><th className="px-3 py-3">Request</th><th className="px-3 py-3">Verdict</th><th className="px-3 py-3">Action</th></tr></thead><tbody className="divide-y divide-[#26302d] font-mono text-xs">{recent.map((event, index) => <tr key={`${event.timestamp}-${index}`} className="hover:bg-[#202b2a]"><td className="px-5 py-4 text-[#86948a]">{formatTime(event.timestamp)}</td><td className="px-3 py-4 text-[#dfe2ef]">{event.source_ip}</td><td className="max-w-[260px] truncate px-3 py-4 text-[#aab7b0]">{event.method} {event.path}</td><td className={`px-3 py-4 uppercase ${event.verdict.toLowerCase() === "malicious" ? "text-[#ff746c]" : "text-[#4edea3]"}`}>{event.verdict}</td><td className="px-3 py-4 text-[#aab7b0]">{event.action}</td></tr>)}</tbody></table>{!recent.length && <div className="flex flex-col items-center justify-center px-6 py-16 text-center"><Radio className="mb-3 h-6 w-6 text-[#66736d]" /><p className="font-mono text-xs uppercase tracking-wider text-[#aab7b0]">Waiting for live telemetry</p><p className="mt-2 font-mono text-[10px] text-[#66736d]">No demo data is displayed.</p></div>}</div></div>
          <div className="rounded-xl border border-[#26302d] bg-[#181b25] p-5"><h2 className="font-mono text-xs font-semibold uppercase tracking-[0.14em]">Session metrics</h2><div className="mt-5 space-y-4">{[["Average inspection", avgInspection ? `${avgInspection.toFixed(1)}ms` : "—"], ["Average tarpit duration", formatDuration(avgTarpit)], ["Bytes served", events.reduce((sum, event) => sum + (event.bytes_served ?? 0), 0).toLocaleString()], ["Telemetry buffer", `${events.length} / 100`]].map(([label, value]) => <div key={label} className="flex items-center justify-between border-b border-[#26302d] pb-3 font-mono text-xs"><span className="text-[#86948a]">{label}</span><span className="text-[#dfe2ef]">{value}</span></div>)}</div><div className="mt-6 rounded bg-[#111720] p-3 font-mono text-[10px] leading-relaxed text-[#66736d]">All metrics are calculated from events received in this browser session.</div></div>
        </section>
      </main>
    </div>
  </div>;
}
