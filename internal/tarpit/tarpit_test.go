package tarpit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// flushRecorder wraps httptest.ResponseRecorder and signals on every Flush call.
// The standard recorder implements http.Flusher but does nothing; we need to
// observe that the tarpit actually flushes.
type flushRecorder struct {
	*httptest.ResponseRecorder
	flushed chan struct{}
}

func newFlushRecorder() *flushRecorder {
	return &flushRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		flushed:          make(chan struct{}, 1),
	}
}

func (r *flushRecorder) Flush() {
	r.ResponseRecorder.Flush()
	select {
	case r.flushed <- struct{}{}:
	default:
	}
}

// --------------------------------------------------------------------------
// Delay model
// --------------------------------------------------------------------------

func TestComputeDelay_StaysInBounds(t *testing.T) {
	cfg := DefaultConfig()
	tp := &AdaptiveTarpit{cfg: cfg}

	// Test across a range of RTTs including extremes.
	for _, rttMs := range []int{0, 1, 5, 20, 50, 100, 200, 500} {
		rtt := time.Duration(rttMs) * time.Millisecond
		for i := 0; i < 200; i++ { // many samples to exercise jitter
			d := tp.computeDelay(rtt)
			if d < cfg.MinDelay {
				t.Errorf("rtt=%v: delay %v < MinDelay %v", rtt, d, cfg.MinDelay)
			}
			if d > cfg.MaxDelay {
				t.Errorf("rtt=%v: delay %v > MaxDelay %v", rtt, d, cfg.MaxDelay)
			}
		}
	}
}

func TestComputeDelay_HigherRTTMeansHigherDelay(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Jitter = 0 // zero jitter to make this deterministic
	tp := &AdaptiveTarpit{cfg: cfg}

	low := tp.computeDelay(5 * time.Millisecond)
	high := tp.computeDelay(200 * time.Millisecond)
	if high <= low {
		t.Errorf("expected higher RTT to produce longer delay: low=%v high=%v", low, high)
	}
}

// --------------------------------------------------------------------------
// Chunk streaming
// --------------------------------------------------------------------------

func TestHandle_WritesChunksAndFlushes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BaseDelay = time.Millisecond
	cfg.MinDelay = time.Millisecond
	cfg.MaxDelay = 5 * time.Millisecond
	cfg.Duration = 50 * time.Millisecond // short for the test
	tp, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/search?q=inject", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	w := newFlushRecorder()

	done := make(chan error, 1)
	go func() { done <- tp.Handle(w, req) }()

	// We must receive at least one flush within a generous timeout.
	select {
	case <-w.flushed:
		// good — data is being streamed
	case <-time.After(2 * time.Second):
		t.Fatal("tarpit never flushed a chunk")
	}

	// Wait for Handle to return naturally (Duration elapsed).
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Handle returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Handle did not return after Duration elapsed")
	}

	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(body, `"processing"`) {
		t.Errorf("expected JSON preamble in body, got: %q", body)
	}
}

func TestThrottlePreservesCapturedResponse(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BaseDelay = time.Millisecond
	cfg.MinDelay = time.Millisecond
	cfg.MaxDelay = time.Millisecond
	cfg.Duration = 5 * time.Millisecond
	tarpit, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	captured := NewResponseCapture()
	captured.Header().Set("Content-Type", "text/plain")
	captured.Header().Set("X-Backend-Server", "mirage-demo-backend")
	captured.WriteHeader(http.StatusAccepted)
	_, _ = captured.Write([]byte("captured fake response"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.8:8080"
	w := newFlushRecorder()
	if err := tarpit.Throttle(w, req, captured); err != nil {
		t.Fatal(err)
	}

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "text/plain" {
		t.Fatalf("content type = %q, want text/plain", got)
	}
	if got := w.Body.String(); got != "captured fake response" {
		t.Fatalf("body = %q, want captured response", got)
	}
}

// --------------------------------------------------------------------------
// Client disconnect
// --------------------------------------------------------------------------

func TestHandle_ExitsCleanlyOnContextCancel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BaseDelay = time.Millisecond
	cfg.MinDelay = time.Millisecond
	cfg.MaxDelay = 5 * time.Millisecond
	cfg.Duration = 30 * time.Second // long — we cancel before it expires
	tp, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.2:6666"
	w := newFlushRecorder()

	done := make(chan error, 1)
	go func() { done <- tp.Handle(w, req) }()

	// Wait for the first flush, then cancel — simulates client disconnect.
	select {
	case <-w.flushed:
	case <-time.After(2 * time.Second):
		t.Fatal("tarpit did not send initial data")
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("unexpected error on cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Handle did not exit after context cancel")
	}
}

// --------------------------------------------------------------------------
// Concurrency caps
// --------------------------------------------------------------------------

func TestHandle_GlobalCapReturns503(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BaseDelay = 5 * time.Millisecond
	cfg.MinDelay = 5 * time.Millisecond
	cfg.MaxDelay = 10 * time.Millisecond
	cfg.Duration = 10 * time.Second
	cfg.MaxConcurrent = 1 // only one slot
	cfg.MaxPerSource = 99
	tp, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Hold the one global slot with a long-running request.
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	r1 := httptest.NewRequestWithContext(ctx1, http.MethodGet, "/", nil)
	r1.RemoteAddr = "10.0.0.3:1111"
	w1 := newFlushRecorder()
	go tp.Handle(w1, r1) //nolint:errcheck

	// Wait until the first request is actively tarpitting.
	select {
	case <-w1.flushed:
	case <-time.After(2 * time.Second):
		t.Fatal("slot holder never started")
	}

	// Second request — global cap is full.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.RemoteAddr = "10.0.0.4:2222"
	w2 := httptest.NewRecorder()
	if err := tp.Handle(w2, r2); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if w2.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when global cap full, got %d", w2.Code)
	}
}

func TestHandle_PerSourceCapReturns503(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BaseDelay = 5 * time.Millisecond
	cfg.MinDelay = 5 * time.Millisecond
	cfg.MaxDelay = 10 * time.Millisecond
	cfg.Duration = 10 * time.Second
	cfg.MaxConcurrent = 99
	cfg.MaxPerSource = 1 // one tarpit per IP
	tp, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	const sameIP = "10.0.0.5"

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	r1 := httptest.NewRequestWithContext(ctx1, http.MethodGet, "/", nil)
	r1.RemoteAddr = sameIP + ":1000"
	w1 := newFlushRecorder()
	go tp.Handle(w1, r1) //nolint:errcheck

	select {
	case <-w1.flushed:
	case <-time.After(2 * time.Second):
		t.Fatal("first request never flushed")
	}

	// Second request from the same IP — per-source cap exceeded.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.RemoteAddr = sameIP + ":2000"
	w2 := httptest.NewRecorder()
	_ = tp.Handle(w2, r2)
	if w2.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for per-source cap, got %d", w2.Code)
	}
}

// --------------------------------------------------------------------------
// Race detector
// --------------------------------------------------------------------------

func TestHandle_ConcurrentRaceSafe(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BaseDelay = time.Millisecond
	cfg.MinDelay = time.Millisecond
	cfg.MaxDelay = 5 * time.Millisecond
	cfg.Duration = 30 * time.Millisecond
	cfg.MaxConcurrent = 50
	cfg.MaxPerSource = 50
	tp, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 40
	done := make(chan struct{}, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "10.99.0.1:10000"
			w := httptest.NewRecorder()
			_ = tp.Handle(w, req)
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// --------------------------------------------------------------------------
// ConnStore
// --------------------------------------------------------------------------

func TestConnStore_SetAndGet(t *testing.T) {
	cs := NewConnStore()
	// We can't easily create a real net.Conn in a unit test, so we verify the
	// StateHook signature compiles and the store map initialises correctly.
	hook := cs.StateHook()
	if hook == nil {
		t.Error("StateHook returned nil")
	}
	if len(cs.conns) != 0 {
		t.Error("new ConnStore should be empty")
	}
}
