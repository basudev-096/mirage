"use client";

import { useEffect, useMemo, useState } from "react";
import { Activity, BarChart3, CircleDot, Globe2, LayoutDashboard, Menu, Radio, ShieldAlert, ShieldCheck, Timer } from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface Event {
  timestamp: string;
  source_ip: string;
  method: string;
  path: string;
  verdict: string;
  category?: string;
  action: string;
  score?: number;
  inspection_time_us?: number;
  tarpit_duration_ms?: number;
}

const SOCKET_URL = process.env.NEXT_PUBLIC_MIRAGE_WS_URL;
const time = (value: string) => { const date = new Date(value); return Number.isNaN(date.getTime()) ? "—" : date.toLocaleTimeString([], { hour12: false }); };

function Sidebar({ open, close }: { open: boolean; close: () => void }) {
  const links = [["Overview", LayoutDashboard, "/"], ["Live Events", Radio, "/events"], ["Source IPs", Globe2, "/sources"], ["Attack Categories", BarChart3, "/categories"], ["Tarpit Activity", Timer, "/tarpits"], ["System Health", Activity, "/health"]] as const;
  return <aside className={`fixed inset-y-0 left-0 z-40 flex w-72 flex-col border-r border-[#26302d] bg-[#090d13] transition-transform lg:translate-x-0 ${open ? "translate-x-0" : "-translate-x-full"}`}><div className="flex h-16 items-center gap-3 border-b border-[#26302d] bg-[#111720] px-6"><div className="flex h-8 w-8 items-center justify-center rounded bg-[#4edea3] text-[#062519]"><ShieldCheck className="h-5 w-5" /></div><div><div className="font-mono text-sm font-semibold uppercase tracking-[0.18em] text-[#4edea3]">Mirage</div><div className="font-mono text-[9px] uppercase tracking-[0.2em] text-[#86948a]">Active Defense</div></div></div><div className="px-5 pb-2 pt-7 font-mono text-[10px] uppercase tracking-[0.18em] text-[#66736d]">Sinks &amp; monitors</div><nav className="flex flex-col gap-1 px-3">{links.map(([label, Icon, href]) => <a key={href} href={href} onClick={close} className={`flex items-center gap-3 rounded px-4 py-3 font-mono text-xs uppercase tracking-wide ${href === "/categories" ? "bg-[#202b2a] font-semibold text-[#4edea3]" : "text-[#aab7b0] hover:bg-[#17201f] hover:text-[#dfe2ef]"}`}><Icon className="h-[18px] w-[18px]" />{label}</a>)}</nav><div className="mt-auto border-t border-[#26302d] bg-[#111720] p-5 font-mono text-[10px] text-[#66736d]">Current browser session only</div></aside>;
}

export default function CategoriesPage() {
  const [events, setEvents] = useState<Event[]>([]);
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState<"connecting" | "live" | "offline">(SOCKET_URL ? "connecting" : "offline");
  useEffect(() => {
    if (!SOCKET_URL) return;
    let stopped = false; let socket: WebSocket | undefined; let retry: ReturnType<typeof setTimeout> | undefined;
    const connect = () => {
      if (stopped) return;
      setStatus("connecting"); socket = new WebSocket(SOCKET_URL); socket.onopen = () => setStatus("live");
      socket.onmessage = (message) => { try { const event = JSON.parse(message.data) as Event; if (event.timestamp && event.source_ip) setEvents((current) => [event, ...current].slice(0, 100)); } catch { /* ignore malformed telemetry */ } };
      socket.onerror = () => socket?.close(); socket.onclose = () => { if (!stopped) { setStatus("offline"); retry = setTimeout(connect, 2000); } };
    };
    connect(); return () => { stopped = true; if (retry) clearTimeout(retry); socket?.close(); };
  }, []);

  const malicious = events.filter((event) => event.verdict.toLowerCase() === "malicious");
  const categories = useMemo(() => {
    const map = new Map<string, Event[]>();
    malicious.forEach((event) => { const key = event.category || "Unknown"; map.set(key, [...(map.get(key) ?? []), event]); });
    return [...map.entries()].map(([name, items]) => ({ name, items, count: items.length, avgScore: items.reduce((sum, item) => sum + (item.score ?? 0), 0) / items.length, avgInspection: items.reduce((sum, item) => sum + (item.inspection_time_us ?? 0), 0) / items.length / 1000, actions: [...new Set(items.map((item) => item.action))] })).sort((a, b) => b.count - a.count);
  }, [malicious]);
  const top = categories[0];
  const topSource = top ? [...new Set(top.items.map((event) => event.source_ip))][0] : undefined;
  return <div className="min-h-screen bg-[#0f131c] text-[#dfe2ef]"><Sidebar open={open} close={() => setOpen(false)} /><div className="lg:pl-72"><header className="fixed left-0 right-0 top-0 z-30 flex h-16 items-center justify-between border-b border-[#26302d] bg-[#0f131c]/95 px-5 backdrop-blur lg:left-72 lg:px-8"><div className="flex items-center gap-3"><button onClick={() => setOpen(true)} className="rounded p-2 lg:hidden" aria-label="Open navigation"><Menu className="h-5 w-5" /></button><span className="font-mono text-xs uppercase tracking-[0.18em] text-[#86948a]">Mirage / Attack Categories</span></div><span className={`flex items-center gap-2 font-mono text-[10px] uppercase ${status === "live" ? "text-[#4edea3]" : "text-[#ffb86b]"}`}><CircleDot className="h-3 w-3" />{status}</span></header>
    <main className="px-5 pb-14 pt-24 lg:px-10"><section className="mb-6 flex flex-col justify-between gap-5 rounded-xl border border-[#26302d] bg-[#181b25] p-6 lg:flex-row lg:items-center"><div className="flex gap-4"><div className="flex h-11 w-11 items-center justify-center rounded bg-[#202b2a] text-[#4edea3]"><BarChart3 className="h-5 w-5" /></div><div><div className="font-mono text-[10px] uppercase tracking-[0.18em] text-[#4edea3]">Current session intelligence</div><h1 className="mt-1 text-2xl font-semibold">Attack Category Analysis</h1><p className="mt-1 font-mono text-xs text-[#86948a]">Malicious vectors observed in the current browser telemetry session.</p></div></div><div className="rounded bg-[#202b2a] px-4 py-2 font-mono text-[10px] uppercase text-[#86948a]">Events <strong className="ml-2 text-[#dfe2ef]">{events.length} / 100</strong></div></section>
    <section className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">{([["Flagged events", malicious.length, ShieldAlert], ["Active vectors", categories.length, BarChart3], ["Top vector", top?.name ?? "—", Activity], ["In-memory", events.length ? "100%" : "—", ShieldCheck]] as [string, string | number, LucideIcon][]).map(([label, value, Icon]) => <div key={String(label)} className="rounded-xl border border-[#26302d] bg-[#181b25] p-5"><div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-wider text-[#86948a]"><span>{label}</span><Icon className="h-4 w-4 text-[#4edea3]" /></div><div className="mt-4 truncate font-mono text-3xl font-semibold text-[#dfe2ef]">{value}</div><div className="mt-2 font-mono text-[10px] text-[#66736d]">Derived from received events</div></div>)}</section>
    <section className="mb-6 grid gap-5 xl:grid-cols-[1.1fr_0.9fr]"><div className="rounded-xl border border-[#26302d] bg-[#181b25] p-5"><div className="mb-5 flex items-center justify-between"><div><h2 className="font-mono text-xs font-semibold uppercase tracking-wider">Vector distribution</h2><p className="mt-1 font-mono text-[10px] text-[#66736d]">Relative share of malicious events</p></div><BarChart3 className="h-4 w-4 text-[#4edea3]" /></div>{categories.length ? <div className="space-y-5">{categories.map((category) => <div key={category.name}><div className="mb-2 flex justify-between font-mono text-xs"><span className="text-[#dfe2ef]">{category.name}</span><span className="text-[#4edea3]">{category.count} · {((category.count / malicious.length) * 100).toFixed(0)}%</span></div><div className="h-2 rounded bg-[#26302d]"><div className="h-full rounded bg-[#4edea3]" style={{ width: `${(category.count / malicious.length) * 100}%` }} /></div></div>)}</div> : <div className="py-16 text-center font-mono text-[10px] uppercase tracking-wider text-[#66736d]">Waiting for attack telemetry</div>}</div><div className="rounded-xl border border-[#26302d] bg-[#181b25] p-5"><h2 className="font-mono text-xs font-semibold uppercase tracking-wider">Highest-volume vector</h2>{top ? <div className="mt-6"><div className="font-mono text-2xl font-semibold text-[#ffb3ad]">{top.name}</div><div className="mt-2 font-mono text-xs text-[#86948a]">{top.count} observed events · source {topSource}</div><div className="mt-6 space-y-3">{[["Average WAF score", top.avgScore.toFixed(1)], ["Average inspection", `${top.avgInspection.toFixed(1)}ms`], ["Observed actions", top.actions.join(", ")], ["Latest event", time(top.items[0]?.timestamp ?? "")]].map(([label, value]) => <div key={label} className="flex justify-between border-b border-[#26302d] pb-3 font-mono text-xs"><span className="text-[#86948a]">{label}</span><span className="text-[#dfe2ef]">{value}</span></div>)}</div></div> : <div className="py-16 text-center font-mono text-[10px] uppercase text-[#66736d]">No malicious category data</div>}</div></section>
    <section className="overflow-hidden rounded-xl border border-[#26302d] bg-[#181b25]"><div className="border-b border-[#26302d] px-5 py-4"><h2 className="font-mono text-xs font-semibold uppercase tracking-wider">Category execution detail</h2><p className="mt-1 font-mono text-[10px] text-[#66736d]">Only categories present in current-session telemetry are listed.</p></div><div className="overflow-x-auto"><table className="w-full min-w-[800px] text-left"><thead className="border-b border-[#26302d] bg-[#111720] font-mono text-[10px] uppercase tracking-wider text-[#66736d]"><tr><th className="px-5 py-3">Category</th><th className="px-3 py-3">Events</th><th className="px-3 py-3">Share</th><th className="px-3 py-3">Avg score</th><th className="px-3 py-3">Inspection</th><th className="px-3 py-3">Actions</th><th className="px-5 py-3">Latest</th></tr></thead><tbody className="divide-y divide-[#26302d] font-mono text-xs">{categories.map((category) => <tr key={category.name} className="hover:bg-[#202b2a]"><td className="px-5 py-4 text-[#dfe2ef]">{category.name}</td><td className="px-3 py-4 text-[#4edea3]">{category.count}</td><td className="px-3 py-4">{((category.count / malicious.length) * 100).toFixed(1)}%</td><td className="px-3 py-4">{category.avgScore.toFixed(1)}</td><td className="px-3 py-4">{category.avgInspection.toFixed(1)}ms</td><td className="px-3 py-4 text-[#aab7b0]">{category.actions.join(" · ")}</td><td className="px-5 py-4 text-[#86948a]">{time(category.items[0]?.timestamp ?? "")}</td></tr>)}</tbody></table>{!categories.length && <div className="flex flex-col items-center py-20 text-center"><Radio className="mb-3 h-6 w-6 text-[#66736d]" /><span className="font-mono text-xs uppercase tracking-wider text-[#aab7b0]">Waiting for live telemetry</span><span className="mt-2 font-mono text-[10px] text-[#66736d]">No demo data is displayed.</span></div>}</div></section></main></div></div>;
}
