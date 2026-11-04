# Project Mirage

Project Mirage is a defensive Layer 7 reverse proxy with Coraza detection,
synthetic deception responses, an adaptive RTT-aware tarpit, and a live
telemetry command center.

## Run the lab

```bash
make test
make build
make docker-up
```

The lab exposes the proxy on `https://localhost:8443`, the dashboard on
`http://localhost:3000` (override with `DASHBOARD_PORT`), ingest health on `http://localhost:8090/healthz`,
Redis on `localhost:6380`, and Postgres on `localhost:5433`.

The compose lab enables automatic active defense by default. Ordinary malicious
requests receive immediate synthetic honeypot responses; scanner-like user
agents and sensitive probe paths are automatically sent through the adaptive
tarpit. No runtime mode switch is needed. Set `MIRAGE_TARPIT=false` only to
disable tarpit capability entirely.
Telemetry remains asynchronous and bounded when Redis is slow or unavailable.

## Development checks

```bash
make test
make vet
make dashboard-lint
make dashboard-build
```

The dashboard can also run independently with `cd web/dashboard && npm run dev`.
Set `NEXT_PUBLIC_MIRAGE_WS_URL=ws://localhost:8090/ws` to connect it to the
ingest service during local development.
