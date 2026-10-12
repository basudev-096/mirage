package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/mirage-proxy/mirage/internal/detect"
)

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
