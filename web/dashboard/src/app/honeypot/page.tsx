"use client";

import { useCallback, useEffect, useState } from "react";
import { Activity, ArrowDownToLine, Bug, CircleDot, Database, LoaderCircle, Play, Radio, ShieldCheck } from "lucide-react";
import type { LucideIcon } from "lucide-react";

type Event = { request_id?: string; session_id?: string; session_requests?: number; timestamp: string; source_ip: string; principal?: string; authorization?: string; method: string; path: string; request_summary?: string; request_preview?: string; body_preview?: string; content_type?: string; user_agent?: string; verdict: string; category?: string; action: string; phase: string; response_type?: string; response_preview?: string; response_status?: number; duration_ms?: number; tarpit_duration_ms?: number; bytes_served?: number; rule_ids?: string[] };
type Session = { session_id: string; source_ip: string; principal: string; authorization: string; first_seen: string; last_seen: string; requests: number; flagged: number; saw_unauthorized: boolean; diverted: number; tarpitted: number; bytes_served: number; categories: string[] };
type Scenario = "authorized" | "unauthorized" | "sqli" | "xss" | "traversal" | "rce";
const API = process.env.NEXT_PUBLIC_MIRAGE_API_URL || "http://localhost:8090";
const WS = process.env.NEXT_PUBLIC_MIRAGE_WS_URL;
const scenarios: { id: Scenario; label: string; sample: string; fake: string }[] = [
  { id: "authorized", label: "Authorized user", sample: "GET /api/profile · valid bearer credential", fake: "Forwarded to the protected backend with the verified principal" },
  { id: "unauthorized", label: "Unauthorized user", sample: "GET /api/profile · no bearer credential", fake: "Diverted to a generated fake profile; backend is not contacted" },
  { id: "sqli", label: "SQL injection", sample: "GET /api/users?id=1' OR '1'='1", fake: "Generated user rows and schema-shaped SQL response" },
  { id: "xss", label: "Cross-site scripting", sample: "GET /search?q=<script>alert(1)</script>", fake: "Search result page with inert, escaped content" },
  { id: "traversal", label: "Path traversal", sample: "GET /files?name=../../etc/passwd", fake: "Synthetic file listing; no host files are read" },
  { id: "rce", label: "Command injection", sample: "GET /admin?cmd=whoami; id", fake: "Plausible command output generated in memory" },
];

function stamp(value: string) { const date = new Date(value); return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString([], { hour12: false }); }

export default function HoneypotPage() {
  const [events, setEvents] = useState<Event[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [busy, setBusy] = useState<Scenario | "all" | null>(null);
  const [notice, setNotice] = useState("");
  const [response, setResponse] = useState("");
  const [connected, setConnected] = useState(false);

  const loadHistory = useCallback(async () => {
    try {
      const [eventResult, sessionResult] = await Promise.all([
        fetch(`${API}/events?limit=500`, { cache: "no-store" }),
        fetch(`${API}/sessions?limit=100`, { cache: "no-store" }),
      ]);
      if (!eventResult.ok || !sessionResult.ok) throw new Error("Recorded activity service is unavailable");
      const [rows, activitySessions] = await Promise.all([eventResult.json() as Promise<Event[]>, sessionResult.json() as Promise<Session[]>]);
      setEvents(rows);
      setSessions(activitySessions);
    } catch { setNotice("Cannot load saved events. Start the full Mirage stack to enable recording."); }
  }, []);

  useEffect(() => { void loadHistory(); const timer = setInterval(() => void loadHistory(), 5000); return () => clearInterval(timer); }, [loadHistory]);
  useEffect(() => {
    if (!WS) return;
    const socket = new WebSocket(WS);
    socket.onopen = () => setConnected(true);
    socket.onclose = () => setConnected(false);
    socket.onerror = () => setConnected(false);
    socket.onmessage = (message) => {
      try { const event = JSON.parse(message.data) as Event; if (event.timestamp && event.path) setEvents((old) => [event, ...old.filter((item) => !(item.timestamp === event.timestamp && item.phase === event.phase && item.source_ip === event.source_ip))].slice(0, 200)); } catch { /* Ignore malformed telemetry. */ }
    };
    return () => socket.close();
  }, []);

  const trigger = async (scenario: Scenario) => {
    setBusy(scenario); setNotice(""); setResponse("");
    try {
      const result = await fetch(`${API}/demo/trigger`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scenario }) });
      const payload = await result.json();
      if (!result.ok) throw new Error(payload.error || "Walkthrough request failed");
      setResponse(JSON.stringify(payload, null, 2));
      setNotice(`Request reached the proxy and received HTTP ${payload.status}. Check the saved event below.`);
      window.setTimeout(() => void loadHistory(), 800);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Walkthrough request failed"); }
    finally { setBusy(null); }
  };

  const completed = events.filter((event) => event.phase === "completed");
  const malicious = completed.filter((event) => event.verdict.toLowerCase() !== "clean");
  const fakeReplies = completed.filter((event) => event.response_type?.includes("fake"));

  return <div className="min-h-screen bg-[#0f131c] text-[#dfe2ef]">
    <aside className="fixed inset-y-0 left-0 hidden w-72 border-r border-[#26302d] bg-[#090d13] lg:block"><div className="flex h-16 items-center gap-3 border-b border-[#26302d] bg-[#111720] px-6"><div className="flex h-8 w-8 items-center justify-center rounded bg-[#4edea3] text-[#062519]"><ShieldCheck className="h-5 w-5" /></div><div><div className="font-mono text-sm font-semibold uppercase tracking-[0.18em] text-[#4edea3]">Mirage</div><div className="font-mono text-[9px] uppercase tracking-[0.2em] text-[#86948a]">Active Defense</div></div></div><div className="px-5 pb-2 pt-7 font-mono text-[10px] uppercase tracking-[0.18em] text-[#66736d]">Control room</div><nav className="flex flex-col gap-1 px-3">{[["Overview", "/"], ["Live Events", "/events"], ["Honeypot Sandbox", "/honeypot"], ["Source IPs", "/sources"], ["Attack Categories", "/categories"], ["Tarpit Activity", "/tarpits"], ["System Health", "/health"]].map(([label, href]) => <a key={href} href={href} className={`rounded px-4 py-3 font-mono text-xs uppercase tracking-wide ${href === "/honeypot" ? "bg-[#202b2a] font-semibold text-[#4edea3]" : "text-[#aab7b0] hover:bg-[#17201f]"}`}>{label}</a>)}</nav><div className="absolute bottom-5 left-5 flex items-center gap-2 font-mono text-[10px] uppercase text-[#86948a]"><CircleDot className={`h-3 w-3 ${connected ? "text-[#4edea3]" : "text-[#ffb86b]"}`} />{connected ? "Live stream connected" : "Connecting to event stream"}</div></aside>
    <main className="px-5 pb-12 pt-8 lg:ml-72 lg:px-10 lg:pt-10">
      <div className="mb-6 flex items-center gap-3 font-mono text-xs uppercase tracking-[0.18em] text-[#86948a]"><a className="text-[#4edea3]" href="/">Mirage</a> / Honeypot Sandbox</div>
      <section className="mb-6 rounded-xl border border-[#26302d] bg-[#181b25] p-6"><div className="flex items-start gap-4"><div className="flex h-11 w-11 shrink-0 items-center justify-center rounded bg-[#202b2a] text-[#4edea3]"><Bug className="h-5 w-5" /></div><div><div className="mb-1 flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.18em] text-[#4edea3]"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[#4edea3]" /> In-process deception</div><h1 className="text-2xl font-semibold">Honeypot Sandbox</h1><p className="mt-2 max-w-3xl font-mono text-xs leading-6 text-[#aab7b0]">Use a fixed lab scenario to send an attack-shaped request through the TLS reverse proxy. The detector chooses the response path; flagged traffic receives synthetic content while the same connection stays open. The real backend is bypassed.</p></div></div>
        <div className="mt-6 grid gap-3 md:grid-cols-4">{[["1 · Inspect", "WAF evaluates HTTP request"], ["2 · Divert", "Flagged request stays in proxy"], ["3 · Deceive", "Sandbox returns generated data"], ["4 · Record", "Redis → PostgreSQL → dashboard"]].map(([title, desc]) => <div key={title} className="rounded border border-[#26302d] bg-[#111720] p-4"><div className="font-mono text-[10px] font-semibold uppercase tracking-wider text-[#4edea3]">{title}</div><div className="mt-2 font-mono text-[10px] leading-5 text-[#86948a]">{desc}</div></div>)}</div>
      </section>

      <section className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-5">{([["Observed sessions", sessions.length, Radio], ["Completed requests", completed.length, Activity], ["Sessions with unauthorized attempts", sessions.filter((session) => session.saw_unauthorized).length, Bug], ["Requests diverted", completed.filter((event) => event.action === "honeypot" || event.action === "tarpit").length, ShieldCheck], ["Fake replies served", fakeReplies.length, Database]] as [string, number, LucideIcon][]).map(([label, value, Icon]) => <div key={label} className="rounded-xl border border-[#26302d] bg-[#181b25] p-5"><div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-wider text-[#86948a]"><span>{label}</span><Icon className="h-4 w-4 text-[#4edea3]" /></div><div className="mt-4 font-mono text-3xl">{value}</div><div className="mt-2 font-mono text-[10px] text-[#66736d]">Persisted in PostgreSQL</div></div>)}</section>

      <section className="mb-6 rounded-xl border border-[#26302d] bg-[#181b25] p-5">
        <div className="mb-4 flex items-center gap-3"><Play className="h-4 w-4 text-[#4edea3]" /><div><h2 className="font-mono text-xs font-semibold uppercase tracking-wider">Run a controlled walkthrough</h2><p className="mt-1 font-mono text-[10px] text-[#66736d]">These fixed lab requests pass through the same TLS proxy and WAF as normal traffic.</p></div></div>
        <div className="grid gap-3 md:grid-cols-2">{scenarios.map((item) => <div key={item.id} className="rounded border border-[#26302d] bg-[#111720] p-4"><div className="flex items-center justify-between gap-2"><span className="font-mono text-xs font-semibold text-[#dfe2ef]">{item.label}</span><button disabled={busy !== null} onClick={() => void trigger(item.id)} className="flex shrink-0 items-center gap-2 rounded bg-[#4edea3] px-3 py-2 font-mono text-[9px] font-semibold uppercase text-[#062519] disabled:opacity-50">{busy === item.id ? <LoaderCircle className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}Send through proxy</button></div><code className="mt-3 block break-all font-mono text-[10px] text-[#ffb86b]">{item.sample}</code><p className="mt-2 font-mono text-[10px] text-[#86948a]">Expected route: {item.fake}</p></div>)}</div>
        {notice && <div className="mt-4 rounded border border-[#26302d] bg-[#0f131c] p-3 font-mono text-xs text-[#aab7b0]">{notice}</div>}
        {response && <div className="mt-4"><div className="mb-2 font-mono text-[10px] uppercase tracking-wider text-[#4edea3]">Response returned through the client TLS session</div><pre className="max-h-60 overflow-auto whitespace-pre-wrap rounded bg-[#0f131c] p-4 font-mono text-[10px] leading-5 text-[#aab7b0]">{response}</pre></div>}
      </section>

      <section className="mb-6 overflow-hidden rounded-xl border border-[#26302d] bg-[#181b25]">
        <div className="border-b border-[#26302d] px-5 py-4"><h2 className="font-mono text-xs font-semibold uppercase tracking-wider">Observed client sessions</h2><p className="mt-1 font-mono text-[10px] text-[#66736d]">Grouped by source and client fingerprint · counts are read from PostgreSQL</p></div>
        <div className="overflow-x-auto"><table className="w-full min-w-[920px] text-left"><thead className="border-b border-[#26302d] bg-[#111720] font-mono text-[10px] uppercase tracking-wider text-[#66736d]"><tr><th className="px-5 py-3">Source / Session</th><th className="px-3 py-3">Identity</th><th className="px-3 py-3">Authorization</th><th className="px-3 py-3">Requests</th><th className="px-3 py-3">Flagged</th><th className="px-3 py-3">Diverted</th><th className="px-3 py-3">Fake bytes</th><th className="px-5 py-3">Last activity</th></tr></thead><tbody className="divide-y divide-[#26302d] font-mono text-xs">{sessions.map((session) => <tr key={session.session_id} className="hover:bg-[#202b2a]"><td className="px-5 py-4"><div className="text-[#dfe2ef]">{session.source_ip}</div><div className="mt-1 text-[9px] text-[#66736d]">{session.session_id}</div></td><td className="px-3 py-4 text-[#aab7b0]">{session.principal}</td><td className={`px-3 py-4 uppercase ${session.authorization === "authorized" ? "text-[#4edea3]" : "text-[#ff746c]"}`}>{session.authorization}</td><td className="px-3 py-4">{session.requests}</td><td className="px-3 py-4 text-[#ffb86b]">{session.flagged}</td><td className="px-3 py-4 text-[#4edea3]">{session.diverted}</td><td className="px-3 py-4">{session.bytes_served}</td><td className="px-5 py-4 text-[#86948a]">{stamp(session.last_seen)}</td></tr>)}</tbody></table>{!sessions.length && <div className="py-12 text-center font-mono text-[10px] uppercase text-[#66736d]">No sessions recorded yet</div>}</div>
      </section>

      <section className="overflow-hidden rounded-xl border border-[#26302d] bg-[#181b25]"><div className="flex items-center justify-between border-b border-[#26302d] px-5 py-4"><div><h2 className="font-mono text-xs font-semibold uppercase tracking-wider">Request and deception timeline</h2><p className="mt-1 font-mono text-[10px] text-[#66736d]">Persisted inspection, diversion, and completion events · bearer tokens and sensitive fields are redacted before recording</p></div><button onClick={() => void loadHistory()} className="flex items-center gap-2 rounded bg-[#202b2a] px-3 py-2 font-mono text-[9px] uppercase text-[#aab7b0]"><ArrowDownToLine className="h-3 w-3" /> Refresh saved activity</button></div><div className="divide-y divide-[#26302d]">{events.slice(0, 100).map((event, index) => <article key={`${event.request_id || event.timestamp}-${event.phase}-${index}`} className="grid gap-3 p-5 lg:grid-cols-[190px_1fr_200px]"><div><div className="font-mono text-[10px] text-[#86948a]">{stamp(event.timestamp)}</div><div className="mt-2 font-mono text-xs text-[#dfe2ef]">{event.source_ip}</div><div className="mt-1 break-all font-mono text-[9px] text-[#66736d]">{event.session_id || "No session ID"}</div><div className="mt-2 font-mono text-[9px] uppercase text-[#4edea3]">{event.phase} · request {event.session_requests ?? "—"}</div></div><div><div className="font-mono text-xs text-[#4edea3]">{event.method} {event.path}</div><div className="mt-2 font-mono text-[10px] text-[#aab7b0]">{event.request_summary || "No request summary"}</div>{event.body_preview && <pre className="mt-2 max-h-28 overflow-auto whitespace-pre-wrap rounded bg-[#0f131c] p-3 font-mono text-[10px] leading-5 text-[#ffb86b]">Captured body: {event.body_preview}</pre>}{event.response_preview && <pre className="mt-2 max-h-36 overflow-auto whitespace-pre-wrap rounded bg-[#0f131c] p-3 font-mono text-[10px] leading-5 text-[#86948a]">Fake response: {event.response_preview}</pre>}</div><div className="flex flex-wrap content-start gap-2 lg:justify-end"><span className={`h-fit rounded px-2 py-1 font-mono text-[9px] uppercase ${event.authorization === "authorized" ? "bg-[#202b2a] text-[#4edea3]" : "bg-[#3b252a] text-[#ff746c]"}`}>{event.principal || "anonymous"} · {event.authorization || "unknown"}</span><span className="h-fit rounded bg-[#202b2a] px-2 py-1 font-mono text-[9px] uppercase text-[#aab7b0]">{event.category || "Clean"}</span><span className="h-fit rounded bg-[#202b2a] px-2 py-1 font-mono text-[9px] uppercase text-[#4edea3]">{event.action}</span><span className="h-fit rounded bg-[#202b2a] px-2 py-1 font-mono text-[9px] text-[#aab7b0]">{event.response_type || "passthrough"}</span>{event.phase === "completed" && <span className="h-fit rounded bg-[#202b2a] px-2 py-1 font-mono text-[9px] text-[#aab7b0]">HTTP {event.response_status ?? "—"} · {event.duration_ms ?? 0} ms · {event.bytes_served ?? 0} B</span>}</div></article>)}{!events.length && <div className="flex flex-col items-center py-16 text-center"><Database className="mb-3 h-6 w-6 text-[#66736d]" /><span className="font-mono text-xs uppercase text-[#aab7b0]">No saved activity yet</span><span className="mt-2 font-mono text-[10px] text-[#66736d]">Run a walkthrough above to create a session and timeline.</span></div>}</div></section>
    </main>
  </div>;
}
