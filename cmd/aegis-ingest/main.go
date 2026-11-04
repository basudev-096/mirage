package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aegis-proxy/aegis/internal/telemetry"
	"github.com/redis/go-redis/v9"
)

func main() {
	listenAddr := getEnv("INGEST_LISTEN_ADDR", ":8090")
	redisAddr := getEnv("REDIS_ADDR", "127.0.0.1:6380")
	redisStream := getEnv("REDIS_STREAM", "aegis:events")
	redisGroup := getEnv("REDIS_GROUP", "aegis-ingest")
	redisConsumer := getEnv("REDIS_CONSUMER", hostname())
	databaseURL := getEnv("DATABASE_URL", "postgres://aegis:aegis_password@127.0.0.1:5433/aegis_telemetry")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	redisClient := redis.NewClient(&redis.Options{Addr: redisAddr})
	defer redisClient.Close()
	store, err := telemetry.NewPostgresStore(ctx, databaseURL)
	if err != nil {
		log.Fatalf("initialize postgres store: %v", err)
	}
	defer store.Close()
	if err := ensureSchema(ctx, store); err != nil {
		log.Fatalf("ensure telemetry schema: %v", err)
	}

	hub := telemetry.NewHub(store)
	consumer, err := telemetry.NewConsumer(redisClient, store, hub, redisStream, redisGroup, redisConsumer, 100)
	if err != nil {
		log.Fatalf("initialize telemetry consumer: %v", err)
	}
	go func() {
		if err := consumer.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("telemetry consumer stopped: %v", err)
		}
	}()

	server := &http.Server{
		Addr:              listenAddr,
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isLocalDashboardOrigin(r.Header.Get("Origin")) {
				w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
				w.Header().Add("Vary", "Origin")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			switch r.URL.Path {
			case "/healthz":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok\n"))
			case "/ws":
				hub.ServeHTTP(w, r)
			case "/events":
				if r.Method != http.MethodGet {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
				events, err := store.Latest(r.Context(), limit)
				if err != nil {
					http.Error(w, "event history unavailable", http.StatusServiceUnavailable)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(events)
			case "/sessions":
				if r.Method != http.MethodGet {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
				sessions, err := store.Sessions(r.Context(), limit)
				if err != nil {
					http.Error(w, "session history unavailable", http.StatusServiceUnavailable)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(sessions)
			case "/demo/trigger":
				if getEnv("AEGIS_DEMO_ENABLED", "false") != "true" {
					http.Error(w, "lab walkthrough is disabled", http.StatusNotFound)
					return
				}
				demoTrigger(w, r)
			default:
				http.NotFound(w, r)
			}
		}),
	}

	go func() {
		log.Printf("Aegis ingest listening on %s", listenAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("ingest HTTP server stopped: %v", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}

// demoTrigger sends one of five fixed, benign lab requests through the
// local lab proxy. It does not accept arbitrary URLs or payloads from callers.
func demoTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		Scenario string `json:"scenario"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&input); err != nil {
		http.Error(w, "invalid scenario", http.StatusBadRequest)
		return
	}
	type scenario struct {
		path       string
		authorized bool
	}
	scenarios := map[string]scenario{
		"authorized":   {path: "/api/profile", authorized: true},
		"unauthorized": {path: "/api/profile"},
		"sqli":         {path: "/api/users?id=1%27%20OR%20%271%27=%271"},
		"xss":          {path: "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"},
		"traversal":    {path: "/files?name=..%2F..%2Fetc%2Fpasswd"},
		"rce":          {path: "/admin?cmd=whoami%3B%20id"},
	}
	selected, ok := scenarios[input.Scenario]
	if !ok {
		http.Error(w, "unknown scenario", http.StatusBadRequest)
		return
	}
	base := getEnv("AEGIS_PROXY_URL", "https://localhost:8443")
	target, err := url.Parse(base)
	if err != nil || (target.Scheme != "https" && target.Scheme != "http") {
		http.Error(w, "invalid lab proxy URL", http.StatusInternalServerError)
		return
	}
	requestTarget, err := url.Parse(selected.path)
	if err != nil {
		http.Error(w, "invalid lab scenario", http.StatusInternalServerError)
		return
	}
	target.Path, target.RawQuery = requestTarget.Path, requestTarget.RawQuery
	tlsConfig := &tls.Config{ServerName: getEnv("AEGIS_PROXY_TLS_NAME", "localhost"), MinVersion: tls.VersionTLS12}
	if caPath := getEnv("AEGIS_PROXY_CA", "deploy/certs/server.crt"); target.Scheme == "https" {
		pem, readErr := os.ReadFile(caPath)
		pool := x509.NewCertPool()
		if readErr != nil || !pool.AppendCertsFromPEM(pem) {
			http.Error(w, "lab proxy certificate unavailable", http.StatusServiceUnavailable)
			return
		}
		tlsConfig.RootCAs = pool
	}
	client := &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target.String(), nil)
	if err != nil {
		http.Error(w, "could not create lab request", http.StatusInternalServerError)
		return
	}
	request.Header.Set("User-Agent", "Aegis-Dashboard-Demo/1.0")
	request.Header.Set("Accept", "application/json, text/html;q=0.9, */*;q=0.8")
	if selected.authorized {
		request.Header.Set("Authorization", "Bearer "+getEnv("AEGIS_DEMO_AUTH_TOKEN", "aegis-demo-token"))
	}
	response, err := client.Do(request)
	if err != nil {
		http.Error(w, fmt.Sprintf("lab proxy request failed: %v", err), http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"scenario": input.Scenario, "status": response.StatusCode, "content_type": response.Header.Get("Content-Type"), "body": string(body)})
}

func isLocalDashboardOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" {
		return false
	}
	switch strings.ToLower(parsed.Hostname()) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func ensureSchema(ctx context.Context, store *telemetry.PostgresStore) error {
	backoff := 500 * time.Millisecond
	for {
		if err := store.EnsureSchema(ctx); err == nil {
			return nil
		}
		if err := wait(ctx, backoff); err != nil {
			return err
		}
		if backoff < 10*time.Second {
			backoff *= 2
		}
	}
}

func wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func hostname() string {
	if value, err := os.Hostname(); err == nil && value != "" {
		return value
	}
	return "worker-" + strconv.FormatInt(time.Now().UnixNano(), 10)
}
