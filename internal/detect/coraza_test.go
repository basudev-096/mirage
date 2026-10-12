package detect

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestDetector(t *testing.T) *CorazaDetector {
	cfg := DefaultConfig()
	cfg.Timeout = 10 * time.Second
	d, err := NewCorazaDetector(cfg)
	if err != nil {
		t.Fatalf("Failed to initialize CorazaDetector: %v", err)
	}
	return d
}

func makeCleanRequest(method, target string, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r.Host = "localhost"
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	return r
}

func TestCoraza_SQLi(t *testing.T) {
	d := newTestDetector(t)
	ctx := context.Background()

	req := makeCleanRequest("GET", "/search?q="+url.QueryEscape("' OR '1'='1' --"), "")
	v, err := d.Inspect(ctx, req)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if !v.Malicious {
		t.Errorf("Expected SQLi payload to be flagged as malicious, got score=%d", v.Score)
	}
	if v.Category != "SQLi" && v.Category != "Attack" {
		t.Errorf("Expected Category SQLi or Attack, got %q", v.Category)
	}
}

func TestCoraza_XSS(t *testing.T) {
	d := newTestDetector(t)
	ctx := context.Background()

	req := makeCleanRequest("GET", "/comment?msg="+url.QueryEscape("<script>alert(1)</script>"), "")
	v, err := d.Inspect(ctx, req)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if !v.Malicious {
		t.Errorf("Expected XSS payload to be flagged as malicious, got score=%d", v.Score)
	}
}

func TestCoraza_PathTraversal(t *testing.T) {
	d := newTestDetector(t)
	ctx := context.Background()

	req := makeCleanRequest("GET", "/download?file=../../../../etc/passwd", "")
	v, err := d.Inspect(ctx, req)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if !v.Malicious {
		t.Errorf("Expected Path Traversal to be flagged as malicious, got score=%d", v.Score)
	}
}

func TestCoraza_CommandInjection(t *testing.T) {
	d := newTestDetector(t)
	ctx := context.Background()

	req := makeCleanRequest("POST", "/api/ping", "ip=127.0.0.1; cat /etc/passwd")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	v, err := d.Inspect(ctx, req)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if !v.Malicious {
		t.Errorf("Expected Command Injection to be flagged, got score=%d", v.Score)
	}
}

func TestCoraza_GzipDecompression(t *testing.T) {
	d := newTestDetector(t)
	ctx := context.Background()

	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	_, _ = gzWriter.Write([]byte("query=' OR '1'='1' --"))
	gzWriter.Close()

	req := httptest.NewRequest("POST", "/api/search", &buf)
	req.Host = "localhost"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Encoding", "gzip")

	v, err := d.Inspect(ctx, req)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if !v.Malicious {
		t.Errorf("Expected gzipped SQLi payload to be flagged as malicious, got score=%d", v.Score)
	}
}

func TestCoraza_PaddingEvasion(t *testing.T) {
	d := newTestDetector(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Prepend > 32KB padding payload
	padding := strings.Repeat("A", 33000)
	payload := `{"data":"` + padding + `","exploit":"' OR '1'='1' --"}`

	req := httptest.NewRequest("POST", "/api/data", strings.NewReader(payload))
	req.Host = "localhost"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	v, err := d.Inspect(ctx, req)
	t.Logf("Inspect completed in %v, err=%v", time.Since(start), err)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if !v.OversizedBody {
		t.Errorf("Expected OversizedBody = true for >32KB payload")
	}
	if !v.BodyTruncated {
		t.Errorf("Expected BodyTruncated = true for >32KB payload")
	}
}

func TestCoraza_WAFTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = 1 * time.Nanosecond // Force immediate timeout
	d, err := NewCorazaDetector(cfg)
	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	req := makeCleanRequest("GET", "/test", "")
	v, err := d.Inspect(context.Background(), req)
	if err == nil {
		t.Fatalf("Expected timeout error, got nil")
	}

	if v.Category != "WAF_Timeout" {
		t.Errorf("Expected Category WAF_Timeout, got %q", v.Category)
	}
}

func TestCoraza_ConcurrentRace(t *testing.T) {
	d := newTestDetector(t)
	var wg sync.WaitGroup
	workers := 10
	requestsPerWorker := 5

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < requestsPerWorker; j++ {
				req := httptest.NewRequest("GET", "/search?q=benign_query", nil)
				req.Host = "localhost"
				req.Header.Set("User-Agent", "Mozilla/5.0")

				v, err := d.Inspect(context.Background(), req)
				if err != nil {
					t.Errorf("Worker %d request %d failed: %v", workerID, j, err)
				}
				if v.Malicious {
					t.Errorf("Worker %d request %d falsely flagged clean request (score=%d, rules=%v)", workerID, j, v.Score, v.RuleIDs)
				}
			}
		}(i)
	}

	wg.Wait()
}
