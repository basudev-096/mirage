"use client";

import { useEffect, useMemo, useState } from "react";
import { Activity, BarChart3, CircleDot, Eraser, Globe2, LayoutDashboard, Menu, Radio, ShieldCheck, Timer } from "lucide-react";

interface Event {
  timestamp: string; source_ip: string; method: string; path: string; verdict: string;
  action: string; phase: string; response_type?: string; tarpit_duration_ms?: number; bytes_served?: number;
}
const SOCKET_URL = process.env.NEXT_PUBLIC_MIRAGE_WS_URL;
const fmt = (ms?: number) => ms ? `${(ms / 1000).toFixed(1)}s` : "—";
const clock = (v: string) => { const d = new Date(v); return Number.isNaN(d.getTime()) ? "—" : d.toLocaleTimeString([], { hour12: false }); };

function Sidebar({ open, close }: { open: boolean; close: () => void }) {
  const links = [
    ["Overview", LayoutDashboard, "/"], ["Live Events", Radio, "/events"], ["Source IPs", Globe2, "/sources"],
    ["Attack Categories", BarChart3, "/categories"], ["Tarpit Activity", Timer, "/tarpits"], ["System Health", Activity, "/health"],
  ] as const;
  return <aside className={`fixed inset-y-0 left-0 z-40 flex w-72 flex-col border-r border-[#26302d] bg-[#090d13] transition-transform lg:translate-x-0 ${open ? "translate-x-0" : "-translate-x-full"}`}>
    <div className="flex h-16 items-center gap-3 border-b border-[#26302d] bg-[#111720] px-6"><div className="flex h-8 w-8 items-center justify-center rounded bg-[#4edea3] text-[#062519]"><ShieldCheck className="h-5 w-5" /></div><div><div className="font-mono text-sm font-semibold uppercase tracking-[0.18em] text-[#4edea3]">Mirage</div><div className="font-mono text-[9px] uppercase tracking-[0.2em] text-[#86948a]">Active Defense</div></div></div>
    <div className="px-5 pb-2 pt-7 font-mono text-[10px] uppercase tracking-[0.18em] text-[#66736d]">Sinks &amp; monitors</div>
    <nav className="flex flex-col gap-1 px-3">{links.map(([label, Icon, href]) => <a key={href} href={href} onClick={close} className={`flex items-center gap-3 rounded px-4 py-3 font-mono text-xs uppercase tracking-wide ${href === "/tarpits" ? "bg-[#202b2a] font-semibold text-[#4edea3]" : "text-[#aab7b0] hover:bg-[#17201f] hover:text-[#dfe2ef]"}`}><Icon className="h-[18px] w-[18px]" />{label}</a>)}</nav>
    <div className="mt-auto border-t border-[#26302d] bg-[#111720] p-5 font-mono text-[10px] text-[#66736d]">Current browser session only</div>
  </aside>;
}

export default function TarpitsPage() {
  const [events, setEvents] = useState<Event[]>([]);
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState<"connecting" | "live" | "offline">(SOCKET_URL ? "connecting" : "offline");
  useEffect(() => {
    if (!SOCKET_URL) return;
    let stopped = false; let socket: WebSocket | undefined; let retry: ReturnType<typeof setTimeout> | undefined;
    const connect = () => {
      if (stopped) return;
      setStatus("connecting"); socket = new WebSocket(SOCKET_URL); socket.onopen = () => setStatus("live");
      socket.onmessage = (message) => { try { const event = JSON.parse(message.data) as Event; if (event.action.toLowerCase() === "tarpit") setEvents((current) => [event, ...current].slice(0, 100)); } catch { /* ignore malformed telemetry */ } };
      socket.onerror = () => socket?.close(); socket.onclose = () => { if (!stopped) { setStatus("offline"); retry = setTimeout(connect, 2000); } };
    };
    connect(); return () => { stopped = true; if (retry) clearTimeout(retry); socket?.close(); };
  }, []);
  const completed = events.filter((event) => event.phase.toLowerCase() === "completed");
  const totalDuration = events.reduce((sum, event) => sum + (event.tarpit_duration_ms ?? 0), 0);
  const bytes = events.reduce((sum, event) => sum + (event.bytes_served ?? 0), 0);
  const average = completed.length ? completed.reduce((sum, event) => sum + (event.tarpit_duration_ms ?? 0), 0) / completed.length : 0;
  const buckets = useMemo(() => [0, 10, 30, 60, 120].map((min, index, list) => ({ label: index === list.length - 1 ? `${min}s+` : `${min}–${list[index + 1]}s`, count: events.filter((event) => { const seconds = (event.tarpit_duration_ms ?? 0) / 1000; return index === list.length - 1 ? seconds >= min : seconds >= min && seconds < list[index + 1]; }).length })), [events]);
  return <div className="min-h-screen bg-[#0f131c] text-[#dfe2ef]"><Sidebar open={open} close={() => setOpen(false)} /><div className="lg:pl-72"><header className="fixed left-0 right-0 top-0 z-30 flex h-16 items-center justify-between border-b border-[#26302d] bg-[#0f131c]/95 px-5 backdrop-blur lg:left-72 lg:px-8"><div className="flex items-center gap-3"><button onClick={() => setOpen(true)} className="rounded p-2 lg:hidden" aria-label="Open navigation"><Menu className="h-5 w-5" /></button><span className="font-mono text-xs uppercase tracking-[0.18em] text-[#86948a]">Mirage / Tarpit Activity</span></div><span className={`flex items-center gap-2 font-mono text-[10px] uppercase ${status === "live" ? "text-[#4edea3]" : "text-[#ffb86b]"}`}><CircleDot className="h-3 w-3" />{status}</span></header>
    <main className="px-5 pb-14 pt-24 lg:px-10"><section className="mb-6 flex flex-col justify-between gap-5 rounded-xl border border-[#26302d] bg-[#181b25] p-6 lg:flex-row lg:items-center"><div className="flex gap-4"><div className="flex h-11 w-11 items-center justify-center rounded bg-[#202b2a] text-[#4edea3]"><Timer className="h-5 w-5" /></div><div><div className="font-mono text-[10px] uppercase tracking-[0.18em] text-[#4edea3]">Current session</div><h1 className="mt-1 text-2xl font-semibold">Tarpit Sink Telemetry</h1><p className="mt-1 font-mono text-xs text-[#86948a]">Only completed and observed tarpit events received from the backend are shown.</p></div></div><div className="rounded bg-[#202b2a] px-4 py-2 font-mono text-[10px] uppercase text-[#86948a]">Buffer <strong className="ml-2 text-[#dfe2ef]">{events.length} / 100</strong></div></section>
    <section className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">{[["Tarpit events", events.length], ["Completed verdicts", completed.length], ["Avg stall duration", fmt(average)], ["Bytes served", bytes.toLocaleString()]].map(([label, value]) => <div key={String(label)} className="rounded-xl border border-[#26302d] bg-[#181b25] p-5"><div className="font-mono text-[10px] uppercase tracking-wider text-[#86948a]">{label}</div><div className="mt-4 font-mono text-3xl font-semibold text-[#dfe2ef]">{value}</div><div className="mt-2 font-mono text-[10px] text-[#66736d]">Current session only</div></div>)}</section>
    <section className="mb-6 grid gap-5 xl:grid-cols-2"><div className="rounded-xl border border-[#26302d] bg-[#181b25] p-5"><div className="mb-5 flex items-center justify-between"><div><h2 className="font-mono text-xs font-semibold uppercase tracking-wider">Stall duration distribution</h2><p className="mt-1 font-mono text-[10px] text-[#66736d]">Buckets from received tarpit events</p></div><BarChart3 className="h-4 w-4 text-[#4edea3]" /></div><div className="flex h-44 items-end gap-3 border-b border-l border-[#26302d] px-4">{buckets.map((bucket) => <div key={bucket.label} className="flex flex-1 flex-col items-center justify-end gap-2"><span className="font-mono text-[10px] text-[#4edea3]">{bucket.count}</span><div className="w-full rounded-t bg-[#4edea3]/70" style={{ height: `${Math.max(bucket.count ? bucket.count / Math.max(...buckets.map((item) => item.count), 1) * 100 : 2, 2)}%` }} /><span className="font-mono text-[9px] text-[#66736d]">{bucket.label}</span></div>)}</div></div><div className="rounded-xl border border-[#26302d] bg-[#181b25] p-5"><h2 className="font-mono text-xs font-semibold uppercase tracking-wider">Session observability</h2><div className="mt-5 space-y-4">{[["Aggregated stall time", fmt(totalDuration)], ["Longest observed session", fmt(Math.max(...events.map((event) => event.tarpit_duration_ms ?? 0), 0))], ["Unique targets", new Set(events.map((event) => event.path)).size], ["Engine status", status === "live" ? "Receiving" : "Unavailable"]].map(([label, value]) => <div key={String(label)} className="flex justify-between border-b border-[#26302d] pb-3 font-mono text-xs"><span className="text-[#86948a]">{label}</span><span className="text-[#dfe2ef]">{value}</span></div>)}</div></div></section>
    <section className="overflow-hidden rounded-xl border border-[#26302d] bg-[#181b25]"><div className="flex items-center justify-between border-b border-[#26302d] px-5 py-4"><div><h2 className="font-mono text-xs font-semibold uppercase tracking-wider">Tarpit execution log</h2><p className="mt-1 font-mono text-[10px] text-[#66736d]">Aggregated session telemetry · no live socket state exposed</p></div><Eraser className="h-4 w-4 text-[#66736d]" /></div><div className="overflow-x-auto"><table className="w-full min-w-[800px] text-left"><thead className="border-b border-[#26302d] bg-[#111720] font-mono text-[10px] uppercase tracking-wider text-[#66736d]"><tr><th className="px-5 py-3">Time</th><th className="px-3 py-3">Source IP</th><th className="px-3 py-3">Target</th><th className="px-3 py-3">Phase</th><th className="px-3 py-3">Duration</th><th className="px-3 py-3">Bytes</th><th className="px-5 py-3">Response</th></tr></thead><tbody className="divide-y divide-[#26302d] font-mono text-xs">{events.map((event, index) => <tr key={`${event.timestamp}-${index}`} className="hover:bg-[#202b2a]"><td className="px-5 py-4 text-[#86948a]">{clock(event.timestamp)}</td><td className="px-3 py-4">{event.source_ip}</td><td className="max-w-[260px] truncate px-3 py-4 text-[#aab7b0]">{event.method} {event.path}</td><td className="px-3 py-4 text-[#4edea3]">{event.phase}</td><td className="px-3 py-4">{fmt(event.tarpit_duration_ms)}</td><td className="px-3 py-4">{event.bytes_served ?? "—"}</td><td className="px-5 py-4 text-[#86948a]">{event.response_type ?? "—"}</td></tr>)}</tbody></table>{!events.length && <div className="flex flex-col items-center py-20 text-center"><Radio className="mb-3 h-6 w-6 text-[#66736d]" /><span className="font-mono text-xs uppercase tracking-wider text-[#aab7b0]">Waiting for tarpit telemetry</span><span className="mt-2 font-mono text-[10px] text-[#66736d]">No demo data is displayed.</span></div>}</div></section></main></div></div>;
}
