"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  BarChart3,
  Check,
  ChevronRight,
  CircleDot,
  Copy,
  Eraser,
  Filter,
  Globe2,
  LayoutDashboard,
  Menu,
  Pause,
  Play,
  Radio,
  Search,
  ShieldCheck,
  Timer,
  X,
} from "lucide-react";

interface TelemetryEvent {
  timestamp: string;
  source_ip: string;
  method: string;
  path: string;
  request_summary?: string;
  user_agent?: string;
  ja3?: string;
  ja4?: string;
  verdict: string;
  category?: string;
  payload_class?: string;
  rule_ids?: string[];
  score?: number;
  inspection_time_us?: number;
  action: string;
  phase: string;
  response_type?: string;
  response_preview?: string;
  tarpit_duration_ms?: number;
  bytes_served?: number;
}

type EventFilter = "all" | "malicious" | "clean" | "honeypot" | "tarpit";
const SOCKET_URL = process.env.NEXT_PUBLIC_MIRAGE_WS_URL;

function time(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleTimeString([], { hour12: false });
}

function duration(value?: number) {
  return value ? `${(value / 1000).toFixed(1)}s` : "—";
}

function Sidebar({ mobileOpen, close }: { mobileOpen: boolean; close: () => void }) {
  const links = [
    { label: "Overview", icon: LayoutDashboard, href: "/" },
    { label: "Event Stream", icon: Radio, href: "/events", active: true },
    { label: "Source IPs", icon: Globe2, href: "/sources" },
    { label: "Attack Categories", icon: BarChart3, href: "/categories" },
    { label: "Tarpit Activity", icon: Timer, href: "/tarpits" },
    { label: "System Health", icon: Activity, href: "/health" },
  ];
  return (
    <aside className={`fixed inset-y-0 left-0 z-40 flex w-72 flex-col border-r border-[#26302d] bg-[#090d13] transition-transform lg:translate-x-0 ${mobileOpen ? "translate-x-0" : "-translate-x-full"}`}>
      <div className="flex h-16 items-center gap-3 border-b border-[#26302d] bg-[#111720] px-6">
        <div className="flex h-8 w-8 items-center justify-center rounded bg-[#4edea3] text-[#062519]"><ShieldCheck className="h-5 w-5" /></div>
        <div><div className="font-mono text-sm font-semibold uppercase tracking-[0.18em] text-[#4edea3]">Mirage</div><div className="font-mono text-[9px] uppercase tracking-[0.2em] text-[#86948a]">Active Defense</div></div>
      </div>
      <div className="px-5 pb-2 pt-7 font-mono text-[10px] uppercase tracking-[0.18em] text-[#66736d]">Operations</div>
      <nav className="flex flex-col gap-1 px-3">
        {links.map(({ label, icon: Icon, href, active }) => <a key={href} href={href} onClick={close} className={`flex items-center gap-3 rounded px-4 py-3 font-mono text-xs uppercase tracking-wide transition-colors ${active ? "bg-[#202b2a] font-semibold text-[#4edea3]" : "text-[#aab7b0] hover:bg-[#17201f] hover:text-[#dfe2ef]"}`}><Icon className="h-[18px] w-[18px]" />{label}</a>)}
      </nav>
      <div className="mt-auto border-t border-[#26302d] bg-[#111720] p-5"><div className="mb-3 flex items-center justify-between font-mono text-[10px] uppercase tracking-wider text-[#86948a]"><span>Telemetry stream</span><span className="flex items-center gap-2 text-[#4edea3]"><span className="h-2 w-2 animate-pulse rounded-full bg-[#4edea3]" /> Live</span></div><div className="rounded bg-[#090d13] p-3 font-mono text-[10px] text-[#66736d]">Current browser session only</div></div>
    </aside>
  );
}

export default function EventsPage() {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<EventFilter>("all");
  const [paused, setPaused] = useState(false);
  const [pausedEvents, setPausedEvents] = useState<TelemetryEvent[]>([]);
  const [selected, setSelected] = useState<TelemetryEvent>();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [status, setStatus] = useState<"connecting" | "live" | "offline">(SOCKET_URL ? "connecting" : "offline");
  const [copied, setCopied] = useState<string>();

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

  const visibleEvents = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return events.filter((event) => {
      const malicious = event.verdict.toLowerCase() === "malicious";
      const action = event.action.toLowerCase();
      const matchesFilter = filter === "all" || (filter === "malicious" && malicious) || (filter === "clean" && !malicious) || (filter === "honeypot" && action === "honeypot") || (filter === "tarpit" && action === "tarpit");
      const haystack = [event.source_ip, event.path, event.category, event.action, event.verdict, ...(event.rule_ids ?? [])].filter(Boolean).join(" ").toLowerCase();
      return matchesFilter && (!needle || haystack.includes(needle));
    });
  }, [events, filter, query]);
  const renderedEvents = paused ? pausedEvents : visibleEvents;

  const copy = async (label: string, value: string) => {
    await navigator.clipboard.writeText(value);
    setCopied(label);
    setTimeout(() => setCopied(undefined), 1500);
  };

  return (
    <div className="min-h-screen bg-[#0f131c] text-[#dfe2ef]">
      <Sidebar mobileOpen={mobileOpen} close={() => setMobileOpen(false)} />
      <div className="lg:pl-72">
        <header className="fixed left-0 right-0 top-0 z-30 flex h-16 items-center justify-between border-b border-[#26302d] bg-[#0f131c]/95 px-5 backdrop-blur lg:left-72 lg:px-8">
          <div className="flex items-center gap-3"><button onClick={() => setMobileOpen(true)} className="rounded p-2 text-[#aab7b0] hover:bg-[#202b2a] lg:hidden" aria-label="Open navigation"><Menu className="h-5 w-5" /></button><span className="font-mono text-xs uppercase tracking-[0.18em] text-[#86948a]">Mirage /</span><span className="font-mono text-xs uppercase tracking-[0.18em] text-[#dfe2ef]">Live Events</span></div>
          <div className={`flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider ${status === "live" ? "text-[#4edea3]" : "text-[#ffb86b]"}`}><CircleDot className="h-3 w-3" />{status === "live" ? "Stream live" : status}</div>
        </header>

        <main className="min-h-screen px-5 pb-14 pt-24 lg:px-10">
          <section className="mb-6 flex flex-col justify-between gap-5 rounded-xl border border-[#26302d] bg-[#181b25] p-6 lg:flex-row lg:items-center">
            <div className="flex gap-4"><div className="flex h-11 w-11 shrink-0 items-center justify-center rounded bg-[#202b2a] text-[#4edea3]"><Radio className="h-5 w-5" /></div><div><div className="mb-1 flex items-center gap-2 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-[#4edea3]"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[#4edea3]" /> Live telemetry</div><h1 className="text-2xl font-semibold tracking-tight">Event Stream</h1><p className="mt-1 font-mono text-xs text-[#86948a]">Real-time events received from the Mirage ingest WebSocket.</p></div></div>
            <div className="flex gap-2"><div className="rounded bg-[#202b2a] px-4 py-2 font-mono text-[10px] uppercase tracking-wider text-[#86948a]">Buffer <strong className="ml-2 text-[#dfe2ef]">{events.length} / 100</strong></div><button onClick={() => { if (!paused) setPausedEvents(visibleEvents); setPaused((value) => !value); }} className="flex items-center gap-2 rounded bg-[#4edea3] px-4 py-2 font-mono text-[10px] font-semibold uppercase tracking-wider text-[#062519]">{paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}{paused ? "Resume" : "Pause"}</button><button onClick={() => { setEvents([]); setPausedEvents([]); }} className="flex items-center gap-2 rounded bg-[#202b2a] px-4 py-2 font-mono text-[10px] uppercase tracking-wider text-[#aab7b0] hover:text-[#ffb4ab]"><Eraser className="h-3.5 w-3.5" /> Clear</button></div>
          </section>

          <section className="mb-5 flex flex-col gap-3 rounded-lg border border-[#26302d] bg-[#181b25] p-4 xl:flex-row xl:items-center">
            <div className="relative flex-1"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#66736d]" /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search IP, path, category, action, or rule ID..." className="w-full rounded bg-[#0f131c] py-2.5 pl-10 pr-4 font-mono text-xs text-[#dfe2ef] outline-none placeholder:text-[#66736d] focus:ring-1 focus:ring-[#4edea3]" /></div>
            <div className="flex flex-wrap items-center gap-1 rounded bg-[#0f131c] p-1">{(["all", "malicious", "clean", "honeypot", "tarpit"] as EventFilter[]).map((value) => <button key={value} onClick={() => setFilter(value)} className={`rounded px-3 py-2 font-mono text-[10px] uppercase tracking-wider ${filter === value ? "bg-[#4edea3] font-semibold text-[#062519]" : "text-[#86948a] hover:text-[#dfe2ef]"}`}>{value}</button>)}</div><Filter className="hidden h-4 w-4 text-[#66736d] xl:block" />
          </section>

          <section className="overflow-hidden rounded-lg border border-[#26302d] bg-[#181b25]">
            <div className="flex items-center justify-between border-b border-[#26302d] px-5 py-4"><div><h2 className="font-mono text-xs font-semibold uppercase tracking-[0.14em]">Live event buffer</h2><p className="mt-1 font-mono text-[10px] text-[#66736d]">Showing {renderedEvents.length} filtered events · current session only</p></div><span className="font-mono text-[10px] uppercase text-[#4edea3]">{status === "live" ? "Receiving" : "No live connection"}</span></div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1120px] text-left"><thead className="border-b border-[#26302d] bg-[#111720] font-mono text-[10px] uppercase tracking-wider text-[#66736d]"><tr><th className="px-5 py-3">Time</th><th className="px-3 py-3">Source IP</th><th className="px-3 py-3">Request</th><th className="px-3 py-3">Verdict</th><th className="px-3 py-3">Category</th><th className="px-3 py-3">Score</th><th className="px-3 py-3">Action</th><th className="px-3 py-3">Phase</th><th className="px-3 py-3">Latency</th><th className="px-3 py-3">Tarpit</th><th className="px-5 py-3 text-right">View</th></tr></thead>
                <tbody className="divide-y divide-[#26302d] font-mono text-xs">
                  {renderedEvents.map((event, index) => <tr key={`${event.timestamp}-${event.source_ip}-${index}`} className="cursor-pointer hover:bg-[#202b2a]" onClick={() => setSelected(event)}><td className="px-5 py-4 text-[#86948a]">{time(event.timestamp)}</td><td className="px-3 py-4 text-[#dfe2ef]">{event.source_ip}</td><td className="max-w-[260px] px-3 py-4"><div className="flex gap-2"><span className="text-[#4edea3]">{event.method}</span><span className="truncate text-[#aab7b0]">{event.path}</span></div></td><td className={`px-3 py-4 uppercase ${event.verdict.toLowerCase() === "malicious" ? "text-[#ff746c]" : "text-[#4edea3]"}`}>{event.verdict}</td><td className="px-3 py-4 text-[#aab7b0]">{event.category ?? "—"}</td><td className="px-3 py-4 text-[#dfe2ef]">{event.score ?? "—"}</td><td className="px-3 py-4"><span className={`rounded px-1.5 py-1 text-[9px] uppercase ${event.action.toLowerCase() === "tarpit" ? "bg-[#26302d] text-[#4edea3]" : "bg-[#202b2a] text-[#aab7b0]"}`}>{event.action}</span></td><td className="px-3 py-4 text-[#86948a]">{event.phase}</td><td className="px-3 py-4 text-[#86948a]">{event.inspection_time_us ? `${(event.inspection_time_us / 1000).toFixed(1)}ms` : "—"}</td><td className="px-3 py-4 text-[#4edea3]">{duration(event.tarpit_duration_ms)}</td><td className="px-5 py-4 text-right text-[#4edea3]"><ChevronRight className="ml-auto h-4 w-4" /></td></tr>)}
                </tbody>
              </table>
              {!renderedEvents.length && <div className="flex flex-col items-center justify-center px-6 py-24 text-center"><Radio className="mb-3 h-7 w-7 text-[#66736d]" /><p className="font-mono text-xs uppercase tracking-wider text-[#aab7b0]">{status === "offline" ? "Telemetry stream offline" : "Waiting for live telemetry"}</p><p className="mt-2 max-w-md font-mono text-[10px] text-[#66736d]">Events received from the backend will appear here. No demo data is displayed.</p></div>}
              {paused && <div className="flex items-center justify-center gap-2 border-t border-[#26302d] px-6 py-4 font-mono text-[10px] uppercase tracking-wider text-[#ffb86b]"><Pause className="h-3.5 w-3.5" /> Rendering paused · incoming events remain in the buffer</div>}
            </div>
          </section>
        </main>
      </div>

      {selected && <div className="fixed inset-0 z-50 bg-black/50" onClick={() => setSelected(undefined)}><aside className="absolute right-0 top-0 h-full w-full max-w-xl overflow-y-auto border-l border-[#26302d] bg-[#111720] p-6 shadow-2xl" onClick={(event) => event.stopPropagation()}><div className="mb-6 flex items-start justify-between border-b border-[#26302d] pb-5"><div><div className="mb-2 font-mono text-[10px] uppercase tracking-[0.16em] text-[#4edea3]">Event detail</div><h2 className="font-mono text-lg text-[#dfe2ef]">{selected.method} {selected.path}</h2><p className="mt-1 font-mono text-xs text-[#86948a]">{selected.source_ip} · {time(selected.timestamp)}</p></div><button onClick={() => setSelected(undefined)} className="rounded p-2 text-[#86948a] hover:bg-[#202b2a] hover:text-[#dfe2ef]" aria-label="Close event details"><X className="h-5 w-5" /></button></div><div className="grid grid-cols-2 gap-3">{[["Verdict", selected.verdict], ["Category", selected.category ?? "—"], ["Action", selected.action], ["Phase", selected.phase], ["Score", String(selected.score ?? "—")], ["Latency", selected.inspection_time_us ? `${(selected.inspection_time_us / 1000).toFixed(1)}ms` : "—"], ["Tarpit", duration(selected.tarpit_duration_ms)], ["Bytes served", String(selected.bytes_served ?? "—")]].map(([label, value]) => <div key={label} className="rounded bg-[#181b25] p-3"><div className="font-mono text-[10px] uppercase text-[#66736d]">{label}</div><div className="mt-2 break-all font-mono text-xs text-[#dfe2ef]">{value}</div></div>)}</div><div className="mt-5 space-y-4">{[["Request summary", selected.request_summary], ["User agent", selected.user_agent], ["JA3", selected.ja3], ["JA4", selected.ja4], ["Rule IDs", selected.rule_ids?.join(", ")], ["Response preview", selected.response_preview]].map(([label, value]) => value ? <div key={label}><div className="mb-2 flex items-center justify-between font-mono text-[10px] uppercase tracking-wider text-[#86948a]"><span>{label}</span><button onClick={() => copy(String(label), String(value))} className="flex items-center gap-1 text-[#4edea3]">{copied === label ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}{copied === label ? "Copied" : "Copy"}</button></div><pre className="max-h-44 overflow-auto whitespace-pre-wrap rounded bg-[#0f131c] p-3 font-mono text-xs text-[#aab7b0]">{value}</pre></div> : null)}</div><button onClick={() => copy("JSON", JSON.stringify(selected, null, 2))} className="mt-6 flex items-center gap-2 rounded bg-[#4edea3] px-4 py-2 font-mono text-[10px] font-semibold uppercase tracking-wider text-[#062519]">{copied === "JSON" ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />} Copy event JSON</button></aside></div>}
    </div>
  );
}
