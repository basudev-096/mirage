package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirage-proxy/mirage/internal/deception"
	"github.com/mirage-proxy/mirage/internal/detect"
	"github.com/mirage-proxy/mirage/internal/tarpit"
	"github.com/mirage-proxy/mirage/internal/telemetry"
)

type fixedDetector struct {
	malicious bool
}

func (d fixedDetector) Inspect(ctx context.Context, req *http.Request) (detect.Verdict, error) {
	return detect.Verdict{Malicious: d.malicious, Category: "SQLi"}, nil
}

func TestProxy_TransparentPassthrough(t *testing.T) {
	// 1. Upstream backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "" {
			t.Error("Expected X-Forwarded-For header to be present")
		}
		w.Header().Set("X-Backend-Header", "passed-through")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	// 2. Initialize Mirage Proxy
	cfg := Config{
		TargetURL:     backend.URL,
		FlushInterval: 10 * time.Millisecond,
	}
	p, err := NewProxy(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	// 3. Make request to proxy
	resp, err := http.Get(proxyServer.URL + "/search?q=test")
	if err != nil {
		t.Fatalf("Request to proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d", resp.StatusCode)
	}

	if val := resp.Header.Get("X-Backend-Header"); val != "passed-through" {
		t.Errorf("Expected backend header 'passed-through', got %q", val)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if string(body) != "backend response" {
		t.Errorf("Expected body 'backend response', got %q", string(body))
	}
}

func TestProxy_BadGateway(t *testing.T) {
	// Target invalid unreachable port
	cfg := Config{
		TargetURL: "http://127.0.0.1:59999",
	}
	p, err := NewProxy(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	resp, err := http.Get(proxyServer.URL)
	if err != nil {
		t.Fatalf("Request to proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("Expected status 502 Bad Gateway, got %d", resp.StatusCode)
	}
}

func TestProxy_TLSTermination(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Proto") != "https" {
			t.Errorf("Expected X-Forwarded-Proto 'https', got %q", r.Header.Get("X-Forwarded-Proto"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("tls backend response"))
	}))
	defer backend.Close()

	cfg := Config{
		TargetURL: backend.URL,
	}
	p, err := NewProxy(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// Use httptest TLS server
	proxyTLSServer := httptest.NewTLSServer(p)
	defer proxyTLSServer.Close()

	// Configure client to trust httptest certificate
	client := proxyTLSServer.Client()
	resp, err := client.Get(proxyTLSServer.URL + "/secure")
	if err != nil {
		t.Fatalf("Request to TLS proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	if string(body) != "tls backend response" {
		t.Errorf("Expected body 'tls backend response', got %q", string(body))
	}
}

func TestProxy_DetectorTagging(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verdict := r.Header.Get("X-Mirage-Verdict")
		w.Header().Set("X-Received-Verdict", verdict)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend ok"))
	}))
	defer backend.Close()

	detCfg := detect.DefaultConfig()
	detCfg.Timeout = 5 * time.Second
	detector, err := detect.NewCorazaDetector(detCfg)
	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	cfg := Config{
		TargetURL: backend.URL,
		Detector:  detector,
		EvalBlock: false,
	}
	p, err := NewProxy(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	// Malicious request passed through in Tag-only mode
	client := &http.Client{}
	req, _ := http.NewRequest("GET", proxyServer.URL+"/search?q="+url.QueryEscape("' OR '1'='1' --"), nil)
	req.Host = "localhost"
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 in tag-only mode, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Received-Verdict") != "Malicious" {
		t.Errorf("Expected backend to receive X-Mirage-Verdict 'Malicious', got %q", resp.Header.Get("X-Received-Verdict"))
	}
}

func TestProxy_EvalBlock(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Backend should NOT be reached when request is blocked in EvalBlock mode")
	}))
	defer backend.Close()

	detCfg := detect.DefaultConfig()
	detCfg.Timeout = 5 * time.Second
	detector, err := detect.NewCorazaDetector(detCfg)
	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	cfg := Config{
		TargetURL: backend.URL,
		Detector:  detector,
		EvalBlock: true,
	}
	p, err := NewProxy(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{}
	req, _ := http.NewRequest("GET", proxyServer.URL+"/search?q="+url.QueryEscape("' OR '1'='1' --"), nil)
	req.Host = "localhost"
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected status 403 Forbidden in EvalBlock mode, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Mirage-Verdict") != "Malicious" {
		t.Errorf("Expected X-Mirage-Verdict header 'Malicious', got %q", resp.Header.Get("X-Mirage-Verdict"))
	}
}

func TestProxy_SQLiUsesStructuredDeception(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("backend should not receive a request diverted to the SQL deception handler")
	}))
	defer backend.Close()

	sink := &eventSink{}
	publisher := telemetry.NewPublisher(context.Background(), 8, sink)
	defer publisher.Close()

	p, err := NewProxy(Config{
		TargetURL: backend.URL,
		Detector: fixedDetectorWithVerdict{verdict: detect.Verdict{
			Malicious: true,
			Category:  "SQLi",
			Score:     10,
		}},
		Deception: deception.New(),
		Telemetry: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(p)
	defer server.Close()
	response, err := http.Get(server.URL + "/search?q=" + url.QueryEscape("UNION SELECT username, password FROM users --"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"deception",
		"engine",
		"mirage-sql-honeypot",
		"target_database",
		"target_schema",
		"target_table",
		"target_columns",
		"records_generated",
	} {
		if strings.Contains(strings.ToLower(string(body)), forbidden) {
			t.Fatalf("attacker-facing response exposed %q: %s", forbidden, body)
		}
	}
	for _, header := range []string{"X-Mirage-Deception", "X-Mirage-Target-Table"} {
		if value := response.Header.Get(header); value != "" {
			t.Fatalf("attacker-facing response exposed %s: %q", header, value)
		}
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		sink.mu.Lock()
		for _, event := range sink.events {
			if event.Phase == "completed" {
				sink.mu.Unlock()
				if event.Action != "honeypot" || event.TargetTable != "users" ||
					event.Operation != "SELECT" || len(event.TargetColumns) < 2 ||
					!strings.Contains(event.ResponseMetadata, `"engine":"mirage-sql-honeypot"`) {
					t.Fatalf("unexpected deception event: %+v", event)
				}
				return
			}
		}
		sink.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("deception telemetry event was not published")
}

func TestProxy_PublishesMaliciousTelemetry(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	sink := &eventSink{}
	publisher := telemetry.NewPublisher(context.Background(), 4, sink)
	defer publisher.Close()

	p, err := NewProxy(Config{
		TargetURL: backend.URL,
		Detector: fixedDetectorWithVerdict{verdict: detect.Verdict{
			Malicious: true,
			Category:  "SQLi",
			RuleIDs:   []detect.RuleID{"942100"},
			Score:     10,
		}},
		Telemetry: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(p)
	defer server.Close()
	response, err := http.Get(server.URL + "/search?q=test")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		sink.mu.Lock()
		if len(sink.events) >= 2 {
			event := sink.events[len(sink.events)-1]
			sink.mu.Unlock()
			if event.Verdict != "Malicious" || event.Category != "SQLi" || event.Action != "passthrough" || event.Score != 10 {
				t.Fatalf("unexpected event: %+v", event)
			}
			if event.SourceIP == "" || len(event.RuleIDs) != 1 || event.RuleIDs[0] != "942100" {
				t.Fatalf("incomplete event: %+v", event)
			}
			if event.Phase != "completed" {
				t.Fatalf("phase = %q, want completed", event.Phase)
			}
			return
		}
		sink.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("malicious telemetry event was not published")
}

func TestShouldTarpitOnlyScannerLikeRequests(t *testing.T) {
	ordinary := httptest.NewRequest(http.MethodGet, "/search?q=test", nil)
	ordinary.Header.Set("User-Agent", "Mozilla/5.0")
	if shouldTarpit(ordinary) {
		t.Fatal("ordinary exploit request should not use the adaptive tarpit")
	}

	scanner := httptest.NewRequest(http.MethodGet, "/search?q=test", nil)
	scanner.Header.Set("User-Agent", "sqlmap/1.8")
	if !shouldTarpit(scanner) {
		t.Fatal("sqlmap request should use the adaptive tarpit")
	}

	probe := httptest.NewRequest(http.MethodGet, "/.env", nil)
	probe.Header.Set("User-Agent", "Mozilla/5.0")
	if !shouldTarpit(probe) {
		t.Fatal("sensitive probe path should use the adaptive tarpit")
	}
}

func TestServerWriteTimeoutAllowsConfiguredTarpitDuration(t *testing.T) {
	adaptive, err := tarpit.New(tarpit.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProxy(Config{TargetURL: "http://127.0.0.1:8080", Tarpit: adaptive})
	if err != nil {
		t.Fatal(err)
	}
	server := p.Server(nil)
	if server.WriteTimeout <= adaptive.Duration() {
		t.Fatalf("write timeout = %s, tarpit duration = %s", server.WriteTimeout, adaptive.Duration())
	}
}

type fixedDetectorWithVerdict struct{ verdict detect.Verdict }

func (d fixedDetectorWithVerdict) Inspect(context.Context, *http.Request) (detect.Verdict, error) {
	return d.verdict, nil
}

type eventSink struct {
	mu     sync.Mutex
	events []telemetry.Event
}

func (s *eventSink) Write(_ context.Context, event telemetry.Event) error {
	s.mu.Lock()
	s.events = append(s.events, event)
	s.mu.Unlock()
	return nil
}
