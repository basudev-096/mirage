# Project Mirage Makefile

GO := ~/.local/go/bin/go
GO_FLAGS := -race
PATH := $(HOME)/.local/go/bin:$(PATH)

.PHONY: all build test vet lint docker-up docker-down bench clean certs

all: build test

certs:
	@mkdir -p deploy/certs
	@if [ ! -f deploy/certs/server.crt ]; then \
		echo "Generating self-signed TLS certificates for development lab..."; \
		openssl req -x509 -newkey rsa:2048 -nodes -keyout deploy/certs/server.key -out deploy/certs/server.crt -days 365 -subj "/CN=localhost/O=Project Mirage Lab" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"; \
	fi

build:
	@echo "Building mirage-proxy..."
	@$(GO) build -o bin/mirage-proxy ./cmd/mirage-proxy

test: certs
	@echo "Running unit tests..."
	@$(GO) test $(GO_FLAGS) -v ./...

vet:
	@echo "Running go vet..."
	@$(GO) vet ./...

lint: vet
	@echo "Linting..."

docker-up: certs
	@echo "Starting Docker Compose lab environment..."
	docker-compose -f deploy/docker-compose.yml down --remove-orphans 2>/dev/null || true
	docker-compose -f deploy/docker-compose.yml up --build -d

docker-down:
	@echo "Stopping Docker Compose lab environment..."
	docker-compose -f deploy/docker-compose.yml down

bench:
	@echo "Running k6 baseline performance benchmarks..."
	@if command -v k6 >/dev/null 2>&1; then \
		k6 run bench/k6_baseline.js; \
	elif command -v docker >/dev/null 2>&1; then \
		docker run --rm -i --net=host grafana/k6 run - < bench/k6_baseline.js; \
	else \
		echo "k6 not installed and docker unavailable."; \
	fi

clean:
	rm -rf bin/ deploy/certs/*.crt deploy/certs/*.key
