"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  ChevronRight,
  CircleDot,
  Copy,
  Database,
  Filter,
  Globe2,
  LayoutDashboard,
  Menu,
  Radio,
  Search,
  ShieldCheck,
  Timer,
  UserRound,
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
  rule_ids?: string[];
  score?: number;
  action: string;
  phase: string;
  tarpit_duration_ms?: number;
  bytes_served?: number;
}

interface SourceSummary {
  ip: string;
  events: TelemetryEvent[];
  malicious: number;
  categories: string[];
  actions: string[];
  lastSeen: string;
  avgTarpit: number;
  userAgents: string[];
  fingerprints: string[];
}

const SOCKET_URL = process.env.NEXT_PUBLIC_MIRAGE_WS_URL;

function formatDuration(ms: number) {
  if (!ms) return "—";
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatTime(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

function aggregate(events: TelemetryEvent[]) {
  const map = new Map<string, TelemetryEvent[]>();
  for (const event of events) {
    if (!event.source_ip) continue;
    map.set(event.source_ip, [...(map.get(event.source_ip) ?? []), event]);
  }

  return [...map.entries()]
    .map(([ip, sourceEvents]): SourceSummary => {
      const sorted = [...sourceEvents].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
      const tarpitEvents = sourceEvents.filter((event) => (event.tarpit_duration_ms ?? 0) > 0);
      return {
        ip,
        events: sorted,
        malicious: sourceEvents.filter((event) => event.verdict.toLowerCase() === "malicious").length,
        categories: [...new Set(sourceEvents.map((event) => event.category).filter(Boolean))] as string[],
        actions: [...new Set(sourceEvents.map((event) => event.action).filter(Boolean))],
        lastSeen: sorted[0]?.timestamp ?? "",
        avgTarpit: tarpitEvents.length
          ? tarpitEvents.reduce((total, event) => total + (event.tarpit_duration_ms ?? 0), 0) / tarpitEvents.length
          : 0,
        userAgents: [...new Set(sourceEvents.map((event) => event.user_agent).filter(Boolean))] as string[],
        fingerprints: [
          ...new Set(
            sourceEvents.flatMap((event) => [event.ja3 && `JA3 ${event.ja3}`, event.ja4 && `JA4 ${event.ja4}`].filter(Boolean)),
          ),
        ] as string[],
      };
    })
    .sort((a, b) => b.events.length - a.events.length);
}

function Sidebar({ mobileOpen, close }: { mobileOpen: boolean; close: () => void }) {
  const links = [
    { label: "Overview", icon: LayoutDashboard, href: "/" },
    { label: "Event Stream", icon: Radio, href: "/events" },
    { label: "Source IPs", icon: Globe2, href: "/sources", active: true },
    { label: "Attack Categories", icon: BarChart3, href: "/categories" },
    { label: "Tarpit Activity", icon: Timer, href: "/tarpits" },
    { label: "System Health", icon: Activity, href: "/health" },
  ];

  return (
    <aside
      className={`fixed inset-y-0 left-0 z-40 flex w-72 flex-col border-r border-[#26302d] bg-[#090d13] transition-transform lg:translate-x-0 ${
        mobileOpen ? "translate-x-0" : "-translate-x-full"
      }`}
    >
      <div className="flex h-16 items-center gap-3 border-b border-[#26302d] bg-[#111720] px-6">
        <div className="flex h-8 w-8 items-center justify-center rounded bg-[#4edea3] text-[#062519]">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div>
          <div className="font-mono text-sm font-semibold uppercase tracking-[0.18em] text-[#4edea3]">Mirage</div>
          <div className="font-mono text-[9px] uppercase tracking-[0.2em] text-[#86948a]">Active Defense</div>
        </div>
      </div>
      <div className="px-5 pb-2 pt-7 font-mono text-[10px] uppercase tracking-[0.18em] text-[#66736d]">Operations</div>
      <nav className="flex flex-col gap-1 px-3">
        {links.map(({ label, icon: Icon, href, active }) => (
          <a
            key={href}
            href={href}
            onClick={close}
            className={`flex items-center gap-3 rounded px-4 py-3 font-mono text-xs uppercase tracking-wide transition-colors ${
              active ? "bg-[#202b2a] font-semibold text-[#4edea3]" : "text-[#aab7b0] hover:bg-[#17201f] hover:text-[#dfe2ef]"
            }`}
          >
            <Icon className="h-[18px] w-[18px]" />
            {label}
          </a>
        ))}
      </nav>
      <div className="mt-auto border-t border-[#26302d] bg-[#111720] p-5">
        <div className="mb-3 flex items-center justify-between font-mono text-[10px] uppercase tracking-wider text-[#86948a]">
          <span>Telemetry stream</span>
          <span className="flex items-center gap-2 text-[#4edea3]"><span className="h-2 w-2 animate-pulse rounded-full bg-[#4edea3]" /> Live</span>
        </div>
        <div className="rounded bg-[#090d13] p-3">
          <div className="mb-2 flex justify-between font-mono text-[10px] text-[#86948a]"><span>Session buffer</span><span className="text-[#4edea3]">100 max</span></div>
          <div className="h-1 overflow-hidden rounded bg-[#26302d]"><div className="h-full w-1/4 bg-[#4edea3]" /></div>
          <div className="mt-2 font-mono text-[10px] text-[#66736d]">Current browser session only</div>
        </div>
      </div>
    </aside>
  );
}

export default function SourcesPage() {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [query, setQuery] = useState("");
  const [selectedIP, setSelectedIP] = useState<string>();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [status, setStatus] = useState<"connecting" | "live" | "offline">(SOCKET_URL ? "connecting" : "offline");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!SOCKET_URL) {
      return;
    }
    let stopped = false;
    let socket: WebSocket | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const connect = () => {
      if (stopped) return;
      setStatus("connecting");
      socket = new WebSocket(SOCKET_URL);
      socket.onopen = () => setStatus("live");
      socket.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data) as TelemetryEvent;
          if (!event.source_ip || !event.timestamp) return;
          setEvents((current) => [event, ...current].slice(0, 100));
        } catch {
          // A malformed event is ignored; the stream remains available.
        }
      };
      socket.onerror = () => socket?.close();
      socket.onclose = () => {
        if (!stopped) {
          setStatus("offline");
          timer = setTimeout(connect, 2000);
        }
      };
    };
    connect();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      socket?.close();
    };
  }, []);

  const sources = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return aggregate(events).filter((source) => {
      if (!needle) return true;
      return [source.ip, ...source.categories, ...source.actions, ...source.userAgents].some((value) =>
        value.toLowerCase().includes(needle),
      );
    });
  }, [events, query]);

  const selected = sources.find((source) => source.ip === selectedIP) ?? sources[0];
  const malicious = events.filter((event) => event.verdict.toLowerCase() === "malicious").length;
  const tarpit = events.filter((event) => event.action.toLowerCase() === "tarpit").length;

  const copy = async (value: string) => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="min-h-screen bg-[#0f131c] text-[#dfe2ef]">
      <Sidebar mobileOpen={mobileOpen} close={() => setMobileOpen(false)} />
      <div className="lg:pl-72">
        <header className="fixed left-0 right-0 top-0 z-30 flex h-16 items-center justify-between border-b border-[#26302d] bg-[#0f131c]/95 px-5 backdrop-blur lg:left-72 lg:px-8">
          <div className="flex items-center gap-3">
            <button onClick={() => setMobileOpen(true)} className="rounded p-2 text-[#aab7b0] hover:bg-[#202b2a] lg:hidden" aria-label="Open navigation"><Menu className="h-5 w-5" /></button>
            <span className="font-mono text-xs uppercase tracking-[0.18em] text-[#86948a]">Mirage /</span>
            <span className="font-mono text-xs uppercase tracking-[0.18em] text-[#dfe2ef]">Source IPs</span>
          </div>
          <div className="flex items-center gap-4 font-mono text-[10px] uppercase tracking-wider">
            <span className={`flex items-center gap-2 ${status === "live" ? "text-[#4edea3]" : "text-[#ffb86b]"}`}><CircleDot className="h-3 w-3" />{status === "live" ? "Stream live" : status}</span>
            <span className="hidden text-[#86948a] md:block">{events.length} events buffered</span>
          </div>
        </header>

        <main className="min-h-screen px-5 pb-14 pt-24 lg:px-10">
          <section className="mb-6 flex flex-col justify-between gap-5 rounded-xl border border-[#26302d] bg-[#181b25] p-6 shadow-sm lg:flex-row lg:items-center">
            <div className="flex gap-4">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded bg-[#202b2a] text-[#4edea3]"><Globe2 className="h-5 w-5" /></div>
              <div>
                <div className="mb-1 flex items-center gap-2 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-[#4edea3]"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[#4edea3]" /> Current session</div>
                <h1 className="text-2xl font-semibold tracking-tight text-[#dfe2ef]">Source IP Intelligence</h1>
                <p className="mt-1 font-mono text-xs text-[#86948a]">Aggregated activity from events received in this browser session.</p>
              </div>
            </div>
            <div className="flex gap-2 font-mono text-[10px] uppercase tracking-wider">
              <div className="rounded bg-[#202b2a] px-4 py-2 text-[#86948a]">Observed <strong className="ml-2 text-[#dfe2ef]">{sources.length}</strong></div>
              <div className="rounded bg-[#202b2a] px-4 py-2 text-[#86948a]">Malicious <strong className="ml-2 text-[#ffb4ab]">{malicious}</strong></div>
              <div className="hidden rounded bg-[#202b2a] px-4 py-2 text-[#86948a] sm:block">Tarpits <strong className="ml-2 text-[#4edea3]">{tarpit}</strong></div>
            </div>
          </section>

          <section className="mb-5 flex flex-col gap-3 rounded-lg border border-[#26302d] bg-[#181b25] p-4 sm:flex-row sm:items-center">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#66736d]" />
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter by IP, category, action, or user agent..." className="w-full rounded bg-[#0f131c] py-2.5 pl-10 pr-4 font-mono text-xs text-[#dfe2ef] outline-none ring-[#4edea3] placeholder:text-[#66736d] focus:ring-1" />
            </div>
            <button className="flex items-center justify-center gap-2 rounded bg-[#202b2a] px-4 py-2.5 font-mono text-[10px] uppercase tracking-wider text-[#aab7b0] hover:text-[#dfe2ef]"><Filter className="h-3.5 w-3.5" /> Session filter</button>
          </section>

          <section className="grid gap-5 xl:grid-cols-[minmax(0,1.35fr)_minmax(360px,0.65fr)]">
            <div className="overflow-hidden rounded-lg border border-[#26302d] bg-[#181b25]">
              <div className="flex items-center justify-between border-b border-[#26302d] px-5 py-4">
                <div><h2 className="font-mono text-xs font-semibold uppercase tracking-[0.14em] text-[#dfe2ef]">Observed source addresses</h2><p className="mt-1 font-mono text-[10px] text-[#66736d]">Sorted by event volume · max 100 events</p></div>
                <Database className="h-4 w-4 text-[#66736d]" />
              </div>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[720px] text-left">
                  <thead className="border-b border-[#26302d] bg-[#111720] font-mono text-[10px] uppercase tracking-wider text-[#66736d]"><tr><th className="px-5 py-3">Source IP</th><th className="px-3 py-3">Events</th><th className="px-3 py-3">Vectors</th><th className="px-3 py-3">Actions</th><th className="px-3 py-3">Last observed</th><th className="px-5 py-3 text-right">Inspect</th></tr></thead>
                  <tbody className="divide-y divide-[#26302d] font-mono text-xs">
                    {sources.map((source) => (
                      <tr key={source.ip} onClick={() => setSelectedIP(source.ip)} className={`cursor-pointer transition-colors hover:bg-[#202b2a] ${selected?.ip === source.ip ? "bg-[#202b2a]" : ""}`}>
                        <td className="px-5 py-4"><div className="flex items-center gap-2 text-[#dfe2ef]"><span className={`h-1.5 w-1.5 rounded-full ${source.malicious ? "bg-[#ff746c]" : "bg-[#4edea3]"}`} />{source.ip}</div><div className="mt-1 text-[10px] text-[#66736d]">{source.malicious ? `${source.malicious} malicious` : "No malicious verdicts"}</div></td>
                        <td className="px-3 py-4 text-[#dfe2ef]">{source.events.length}</td>
                        <td className="max-w-[180px] px-3 py-4 text-[#aab7b0]">{source.categories.length ? source.categories.join(" · ") : "—"}</td>
                        <td className="px-3 py-4"><div className="flex flex-wrap gap-1">{source.actions.map((action) => <span key={action} className="rounded bg-[#26302d] px-1.5 py-1 text-[9px] uppercase text-[#aab7b0]">{action}</span>)}</div></td>
                        <td className="px-3 py-4 text-[#86948a]">{formatTime(source.lastSeen)}</td>
                        <td className="px-5 py-4 text-right text-[#4edea3]"><ChevronRight className="ml-auto h-4 w-4" /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!sources.length && <div className="flex flex-col items-center justify-center px-6 py-20 text-center"><Radio className="mb-3 h-6 w-6 text-[#66736d]" /><p className="font-mono text-xs uppercase tracking-wider text-[#aab7b0]">Waiting for live telemetry</p><p className="mt-2 max-w-xs font-mono text-[10px] text-[#66736d]">Source addresses will appear when events arrive on the current WebSocket session.</p></div>}
              </div>
            </div>

            <aside className="rounded-lg border border-[#26302d] bg-[#181b25]">
              {selected ? (
                <>
                  <div className="border-b border-[#26302d] p-5"><div className="mb-3 flex items-center justify-between"><span className="font-mono text-[10px] uppercase tracking-[0.14em] text-[#86948a]">Selected source</span><button onClick={() => setSelectedIP(undefined)} className="text-[#66736d] hover:text-[#dfe2ef]" aria-label="Clear selected source"><X className="h-4 w-4" /></button></div><div className="flex items-center justify-between"><h2 className="font-mono text-lg font-semibold text-[#4edea3]">{selected.ip}</h2><button onClick={() => copy(selected.ip)} className="rounded p-2 text-[#86948a] hover:bg-[#202b2a] hover:text-[#4edea3]" aria-label="Copy source IP">{copied ? <ShieldCheck className="h-4 w-4" /> : <Copy className="h-4 w-4" />}</button></div><div className="mt-2 flex gap-2 font-mono text-[10px] uppercase text-[#86948a]"><span>{selected.events.length} events</span><span>·</span><span>{selected.categories.length} vectors</span></div></div>
                  <div className="grid grid-cols-2 gap-3 border-b border-[#26302d] p-5"><div className="rounded bg-[#111720] p-3"><div className="font-mono text-[10px] uppercase text-[#66736d]">Last observed</div><div className="mt-2 font-mono text-sm text-[#dfe2ef]">{formatTime(selected.lastSeen)}</div></div><div className="rounded bg-[#111720] p-3"><div className="font-mono text-[10px] uppercase text-[#66736d]">Avg tarpit</div><div className="mt-2 font-mono text-sm text-[#4edea3]">{formatDuration(selected.avgTarpit)}</div></div></div>
                  <div className="border-b border-[#26302d] p-5"><div className="mb-3 flex items-center gap-2 font-mono text-[10px] font-semibold uppercase tracking-wider text-[#86948a]"><Activity className="h-3.5 w-3.5 text-[#4edea3]" />Activity timeline</div><div className="space-y-3">{selected.events.slice(0, 8).map((event, index) => <div key={`${event.timestamp}-${index}`} className="flex gap-3"><div className="flex flex-col items-center"><span className={`mt-1 h-2 w-2 rounded-full ${event.verdict.toLowerCase() === "malicious" ? "bg-[#ff746c]" : "bg-[#4edea3]"}`} />{index < Math.min(selected.events.length, 8) - 1 && <span className="mt-1 h-full w-px bg-[#26302d]" />}</div><div className="min-w-0 pb-2"><div className="flex gap-2 font-mono text-[10px] text-[#66736d]"><span>{formatTime(event.timestamp)}</span><span className="text-[#4edea3]">{event.method}</span></div><div className="truncate font-mono text-xs text-[#dfe2ef]">{event.path}</div><div className="mt-1 font-mono text-[10px] uppercase text-[#86948a]">{event.category ?? event.action}</div></div></div>)}</div></div>
                  <div className="p-5"><div className="mb-4 flex items-center gap-2 font-mono text-[10px] font-semibold uppercase tracking-wider text-[#86948a]"><UserRound className="h-3.5 w-3.5 text-[#4edea3]" />Observed fingerprints</div>{selected.userAgents.length ? <div className="mb-4"><div className="mb-2 font-mono text-[10px] uppercase text-[#66736d]">User agents</div>{selected.userAgents.map((agent) => <div key={agent} className="mb-1 truncate rounded bg-[#111720] px-3 py-2 font-mono text-[10px] text-[#aab7b0]">{agent}</div>)}</div> : null}{selected.fingerprints.length ? <div><div className="mb-2 font-mono text-[10px] uppercase text-[#66736d]">JA3 / JA4</div>{selected.fingerprints.map((fingerprint) => <div key={fingerprint} className="mb-1 rounded bg-[#111720] px-3 py-2 font-mono text-[10px] text-[#aab7b0]">{fingerprint}</div>)}</div> : <div className="font-mono text-[10px] text-[#66736d]">No fingerprints received for this source.</div>}</div>
                </>
              ) : <div className="flex min-h-[420px] flex-col items-center justify-center p-8 text-center"><Globe2 className="mb-3 h-7 w-7 text-[#66736d]" /><p className="font-mono text-xs uppercase tracking-wider text-[#aab7b0]">No source selected</p><p className="mt-2 font-mono text-[10px] text-[#66736d]">Select a source after telemetry arrives.</p></div>}
            </aside>
          </section>
          <p className="mt-5 flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-[#66736d]"><AlertTriangle className="h-3 w-3" /> Source activity is derived from the current browser session; no historical reputation data is available.</p>
        </main>
      </div>
    </div>
  );
}
