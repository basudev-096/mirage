# Project Aegis

Project Aegis is a Go Layer 7 active-defense reverse proxy and honeypot gateway. It detects malicious HTTP requests, routes them to synthetic deception responses or an adaptive tarpit, and publishes telemetry to a live Next.js dashboard.

## Architecture

```text
Client
  -> Aegis HTTPS proxy (:8443)
      -> clean requests: demo backend (:8080)
      -> malicious requests: deception sandbox / adaptive tarpit
      -> telemetry: Redis Streams -> ingest -> PostgreSQL
                                      -> WebSocket dashboard (:8090)
```

## Prerequisites

Install the following:

- Docker Desktop with Docker Compose
- GNU Make
- OpenSSL
- Go 1.25 or newer for local Go development
- Node.js and npm for local dashboard development

Start Docker Desktop before running the project:

```bash
open -a Docker
```

Verify that Docker is ready:

```bash
docker info
```

## Configure the project

The default Docker Compose configuration starts the complete lab:

- Demo backend: `http://localhost:8080`
- Aegis HTTPS proxy: `https://localhost:8443`
- Redis: `localhost:6380`
- PostgreSQL: `localhost:5433`
- Telemetry ingest and WebSocket: `http://localhost:8090`
- Dashboard: `http://localhost:3000`

The `make docker-up` target generates a self-signed development certificate in `deploy/certs/` when one does not already exist.

Optional environment variables can be set before starting:

```bash
export AEGIS_WAF_TIMEOUT=250ms
export AEGIS_TARPIT=true
export DASHBOARD_PORT=3000
```

Important proxy settings:

- `AEGIS_WAF_TIMEOUT`: maximum WAF inspection time
- `AEGIS_TARPIT`: enables adaptive tarpit handling
- `REDIS_ADDR`: Redis address used by the proxy and ingest service
- `REDIS_STREAM`: Redis telemetry stream name
- `DATABASE_URL`: PostgreSQL connection string for the ingest service
- `INGEST_LISTEN_ADDR`: ingest HTTP/WebSocket listen address

The dashboard WebSocket is configured by Docker Compose with:

```text
ws://localhost:8090/ws
```

## Start the complete project

From the repository root:

```bash
make docker-up
```

This generates development certificates, rebuilds the images, recreates the containers, and starts the stack in the background.

Check service status:

```bash
docker compose -f deploy/docker-compose.yml ps
```

Follow service logs:

```bash
docker compose -f deploy/docker-compose.yml logs -f
```

## Open the dashboard

Available live dashboard pages:

```text
http://localhost:3000/
http://localhost:3000/events
http://localhost:3000/sources
http://localhost:3000/categories
http://localhost:3000/tarpits
http://localhost:3000/health
```

The pages use live events from the ingest WebSocket. On connection, the ingest service replays the latest persisted events from PostgreSQL, followed by new live events. The dashboard does not connect directly to Redis or PostgreSQL and does not display fabricated telemetry.

## Verify the services

Check the ingest health endpoint:

```bash
curl -i http://localhost:8090/healthz
```

Check the demo backend directly:

```bash
curl -i "http://localhost:8080/search?q=normal"
```

Check the Aegis proxy:

```bash
curl -k -i "https://localhost:8443/search?q=normal"
```

The proxied clean response should include the demo backend header:

```text
X-Backend-Server: aegis-demo-backend
```

## Generate demonstration traffic

Keep the dashboard open at `/events`, then send a clean request:

```bash
curl -k "https://localhost:8443/search?q=normal"
```

Generate a SQL injection event:

```bash
curl -k --get "https://localhost:8443/search" \
  --data-urlencode "q=' OR '1'='1' --"
```

Generate an XSS event:

```bash
curl -k --get "https://localhost:8443/search" \
  --data-urlencode "q=<script>alert(1)</script>"
```

Generate a path traversal event:

```bash
curl -k --get "https://localhost:8443/search" \
  --data-urlencode "q=../../../../etc/passwd"
```

Generate scanner-style tarpit telemetry. The short timeout prevents the terminal from waiting for the full tarpit duration:

```bash
curl -k --max-time 8 \
  -A "sqlmap/1.8" \
  "https://localhost:8443/search?q=' OR '1'='1' --"
```

The proxy selects tarpit handling for scanner-style user agents such as `sqlmap`, `nikto`, `masscan`, `nmap`, and `python-requests`, and for probe paths such as `/.env`, `/.git`, `/wp-admin`, and `/actuator`.

## Run locally without Docker

Run the Go tests:

```bash
make test
```

Build the Go services:

```bash
make build
```

Run Go static checks:

```bash
make vet
```

Run dashboard checks:

```bash
cd web/dashboard
npm ci
npm run lint
npm run build
```

To run the dashboard locally:

```bash
cd web/dashboard
export NEXT_PUBLIC_AEGIS_WS_URL=ws://localhost:8090/ws
export NEXT_PUBLIC_AEGIS_HEALTH_URL=http://localhost:8090/healthz
npm run dev
```

Then open `http://localhost:3000`.

The Go proxy, Redis, PostgreSQL, and ingest services must still be running for live telemetry.

## Benchmarks

Run the k6 baseline benchmark:

```bash
make bench
```

Run the adaptive tarpit probe:

```bash
make tarpit-bench
```

## Stop the project

```bash
make docker-down
```

Remove generated binaries and local development certificates:

```bash
make clean
```

`make clean` does not remove Docker volumes or images.

## Troubleshooting

### Docker daemon is unavailable

Start Docker Desktop and retry:

```bash
open -a Docker
docker info
make docker-up
```

### Docker cannot pull images from Docker Hub

If the build fails with an error such as `certificate is valid for blocked.anexgate.com, not registry-1.docker.io`, Docker Desktop is using a proxy or network filter that is blocking Docker Hub. This is a network configuration issue, not an Aegis application error.

1. Open Docker Desktop settings and check **Resources > Proxies**.
2. Disable the proxy or replace it with the correct proxy for your network.
3. If your organization requires the proxy, ask the network administrator to allow `registry-1.docker.io` and `auth.docker.io` with valid TLS certificates.
4. Restart Docker Desktop, verify the connection, and retry:

```bash
docker pull golang:1.23-alpine
make docker-up
```

Do not disable TLS verification or add Docker Hub to Docker's insecure registries.

### Dashboard shows a 404 after adding a page

Rebuild the dashboard image:

```bash
make docker-up
```

### Dashboard shows offline or waiting for telemetry

Check the ingest service:

```bash
curl -i http://localhost:8090/healthz
docker compose -f deploy/docker-compose.yml logs ingest proxy
```

Then generate a request through the proxy. The dashboard aggregates events received during the current browser session only.

### Browser health probe fails

Verify the endpoint directly:

```bash
curl -i http://localhost:8090/healthz
```

If curl succeeds but the browser page reports failure, the browser may be enforcing cross-origin restrictions. The terminal response confirms whether the ingest service itself is healthy.
