"use client";

import { useEffect, useState } from "react";
import { Activity, BarChart3, CircleDot, Globe2, LayoutDashboard, Menu, Radio, ShieldCheck, Timer, Wifi, WifiOff } from "lucide-react";

const SOCKET_URL = process.env.NEXT_PUBLIC_MIRAGE_WS_URL;
const HEALTH_URL = process.env.NEXT_PUBLIC_MIRAGE_HEALTH_URL || "http://localhost:8090/healthz";
type Status = "connecting" | "connected" | "offline";

function Sidebar({ open, close }: { open: boolean; close: () => void }) {
  const links = [["Overview", LayoutDashboard, "/"], ["Live Events", Radio, "/events"], ["Source IPs", Globe2, "/sources"], ["Attack Categories", BarChart3, "/categories"], ["Tarpit Activity", Timer, "/tarpits"], ["System Health", Activity, "/health"]] as const;
  return <aside className={`fixed inset-y-0 left-0 z-40 flex w-72 flex-col border-r border-[#26302d] bg-[#090d13] transition-transform lg:translate-x-0 ${open ? "translate-x-0" : "-translate-x-full"}`}><div className="flex h-16 items-center gap-3 border-b border-[#26302d] bg-[#111720] px-6"><div className="flex h-8 w-8 items-center justify-center rounded bg-[#4edea3] text-[#062519]"><ShieldCheck className="h-5 w-5" /></div><div><div className="font-mono text-sm font-semibold uppercase tracking-[0.18em] text-[#4edea3]">Mirage</div><div className="font-mono text-[9px] uppercase tracking-[0.2em] text-[#86948a]">Active Defense</div></div></div><div className="px-5 pb-2 pt-7 font-mono text-[10px] uppercase tracking-[0.18em] text-[#66736d]">Sinks &amp; monitors</div><nav className="flex flex-col gap-1 px-3">{links.map(([label, Icon, href]) => <a key={href} href={href} onClick={close} className={`flex items-center gap-3 rounded px-4 py-3 font-mono text-xs uppercase tracking-wide ${href === "/health" ? "bg-[#202b2a] font-semibold text-[#4edea3]" : "text-[#aab7b0] hover:bg-[#17201f] hover:text-[#dfe2ef]"}`}><Icon className="h-[18px] w-[18px]" />{label}</a>)}</nav><div className="mt-auto border-t border-[#26302d] bg-[#111720] p-5 font-mono text-[10px] text-[#66736d]">Browser-observed health only</div></aside>;
}

export default function HealthPage() {
  const [open, setOpen] = useState(false);
  const [socketStatus, setSocketStatus] = useState<Status>(SOCKET_URL ? "connecting" : "offline");
  const [healthStatus, setHealthStatus] = useState<"checking" | "healthy" | "failed">("checking");
  const [lastHealth, setLastHealth] = useState<string>();
  const [probes, setProbes] = useState<{ time: string; ok: boolean; status: number }[]>([]);
  const [lastEvent, setLastEvent] = useState<string>();
  const [reconnects, setReconnects] = useState(0);
  const [eventCount, setEventCount] = useState(0);

  useEffect(() => {
    let stopped = false; let socket: WebSocket | undefined; let retry: ReturnType<typeof setTimeout> | undefined;
    const connect = () => {
      if (stopped || !SOCKET_URL) return;
      setSocketStatus("connecting"); socket = new WebSocket(SOCKET_URL);
      socket.onopen = () => setSocketStatus("connected");
      socket.onmessage = (message) => { try { const event = JSON.parse(message.data) as { timestamp?: string }; if (event.timestamp) { setLastEvent(event.timestamp); setEventCount((count) => count + 1); } } catch { /* ignore malformed telemetry */ } };
      socket.onerror = () => socket?.close(); socket.onclose = () => { if (!stopped) { setSocketStatus("offline"); setReconnects((count) => count + 1); retry = setTimeout(connect, 2000); } };
    };
    connect(); return () => { stopped = true; if (retry) clearTimeout(retry); socket?.close(); };
  }, []);

  useEffect(() => {
    let stopped = false;
    const probe = async () => {
      try { const response = await fetch(HEALTH_URL, { cache: "no-store" }); if (!stopped) { setHealthStatus(response.ok ? "healthy" : "failed"); setLastHealth(new Date().toISOString()); setProbes((current) => [{ time: new Date().toISOString(), ok: response.ok, status: response.status }, ...current].slice(0, 10)); } }
      catch { if (!stopped) { setHealthStatus("failed"); setLastHealth(new Date().toISOString()); setProbes((current) => [{ time: new Date().toISOString(), ok: false, status: 0 }, ...current].slice(0, 10)); } }
    };
    probe(); const interval = setInterval(probe, 10000); return () => { stopped = true; clearInterval(interval); };
  }, []);

  const badge = (value: string) => <span className={`rounded px-2 py-1 font-mono text-[10px] uppercase ${value === "healthy" || value === "connected" ? "bg-[#173b2d] text-[#4edea3]" : value === "checking" || value === "connecting" ? "bg-[#3a3020] text-[#ffb86b]" : "bg-[#3d2025] text-[#ff746c]"}`}>{value}</span>;
  return <div className="min-h-screen bg-[#0f131c] text-[#dfe2ef]"><Sidebar open={open} close={() => setOpen(false)} /><div className="lg:pl-72"><header className="fixed left-0 right-0 top-0 z-30 flex h-16 items-center justify-between border-b border-[#26302d] bg-[#0f131c]/95 px-5 backdrop-blur lg:left-72 lg:px-8"><div className="flex items-center gap-3"><button onClick={() => setOpen(true)} className="rounded p-2 lg:hidden" aria-label="Open navigation"><Menu className="h-5 w-5" /></button><span className="font-mono text-xs uppercase tracking-[0.18em] text-[#86948a]">Mirage / Backend Health</span></div><span className={`flex items-center gap-2 font-mono text-[10px] uppercase ${healthStatus === "healthy" ? "text-[#4edea3]" : "text-[#ffb86b]"}`}><CircleDot className="h-3 w-3" />{healthStatus}</span></header><main className="px-5 pb-14 pt-24 lg:px-10"><section className="mb-6 rounded-xl border border-[#26302d] bg-[#181b25] p-6"><div className="flex gap-4"><div className="flex h-11 w-11 items-center justify-center rounded bg-[#202b2a] text-[#4edea3]"><Activity className="h-5 w-5" /></div><div><div className="font-mono text-[10px] uppercase tracking-[0.18em] text-[#4edea3]">Telemetry console</div><h1 className="mt-1 text-2xl font-semibold">Backend Ingest &amp; Probe Health</h1><p className="mt-1 font-mono text-xs text-[#86948a]">Health status measured by this browser against the configured backend endpoints.</p></div></div></section><section className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">{[["WebSocket", socketStatus], ["/healthz", healthStatus], ["Last event", lastEvent ? new Date(lastEvent).toLocaleTimeString([], { hour12: false }) : "—"], ["Reconnects", reconnects]].map(([label, value]) => <div key={String(label)} className="rounded-xl border border-[#26302d] bg-[#181b25] p-5"><div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-wider text-[#86948a]"><span>{label}</span>{label === "WebSocket" ? <Wifi className="h-4 w-4 text-[#4edea3]" /> : <WifiOff className="h-4 w-4 text-[#86948a]" />}</div><div className="mt-4">{typeof value === "string" ? badge(value) : <span className="font-mono text-3xl">{value}</span>}</div></div>)}</section><section className="grid gap-5 xl:grid-cols-2"><div className="rounded-xl border border-[#26302d] bg-[#181b25] p-5"><div className="mb-5 flex items-center justify-between"><h2 className="font-mono text-xs font-semibold uppercase tracking-wider">Browser WebSocket lifecycle</h2><Radio className="h-4 w-4 text-[#4edea3]" /></div><div className="space-y-3 font-mono text-xs"><div className="flex justify-between border-b border-[#26302d] pb-3"><span className="text-[#86948a]">Endpoint</span><span className="max-w-[250px] truncate text-[#dfe2ef]">{SOCKET_URL || "Not configured"}</span></div><div className="flex justify-between border-b border-[#26302d] pb-3"><span className="text-[#86948a]">State</span>{badge(socketStatus)}</div><div className="flex justify-between border-b border-[#26302d] pb-3"><span className="text-[#86948a]">Events received</span><span>{eventCount}</span></div><div className="flex justify-between"><span className="text-[#86948a]">Reconnect attempts</span><span>{reconnects}</span></div></div></div><div className="rounded-xl border border-[#26302d] bg-[#181b25] p-5"><div className="mb-5 flex items-center justify-between"><h2 className="font-mono text-xs font-semibold uppercase tracking-wider">Probe log</h2><span className="font-mono text-[10px] uppercase text-[#66736d]">Last 10 checks</span></div><div className="space-y-2">{probes.map((probe) => <div key={`${probe.time}-${probe.status}`} className="flex items-center justify-between rounded bg-[#111720] px-3 py-2 font-mono text-[10px]"><span className={probe.ok ? "text-[#4edea3]" : "text-[#ff746c]"}>{probe.ok ? "200 OK" : probe.status ? `${probe.status} FAILED` : "UNREACHABLE"}</span><span className="text-[#86948a]">{new Date(probe.time).toLocaleTimeString([], { hour12: false })}</span></div>)}{!probes.length && <div className="py-10 text-center font-mono text-[10px] text-[#66736d]">Waiting for first probe</div>}</div></div></section><div className="mt-5 flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-[#66736d]"><CircleDot className="h-3 w-3" /> Last probe: {lastHealth ? new Date(lastHealth).toLocaleTimeString([], { hour12: false }) : "pending"} · Redis and PostgreSQL health are not exposed to the browser.</div></main></div></div>;
}
