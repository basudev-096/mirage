// Package tarpit implements the adaptive RTT-aware response throttler.
//
// When the proxy detects an attack and the deception sandbox (Phase 3) has
// generated a fake response, the tarpit takes ownership of writing that response
// to the wire. Instead of a single Write call, it emits the body in small chunks
// separated by delays derived from the attacker's own TCP round-trip time.
//
// A client probing with sqlmap will block for over two minutes waiting for data
// that dribbles out at ~32 bytes per 600–800 ms — all while receiving a response
// that looks like a real, slightly slow application server.
package tarpit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"time"
)

// Tarpit is the interface implemented by AdaptiveTarpit.
// The proxy depends on this interface so the implementation can be swapped in tests.
type Tarpit interface {
	// Handle writes an adaptive throttled response to w for the given request.
	Handle(w http.ResponseWriter, r *http.Request) error

	// ConnStore returns the internal connection store for use as http.Server.ConnState.
	ConnStore() *ConnStore
}

var ErrCapacity = errors.New("tarpit capacity exhausted")

// ResponseCapture stores a Deceiver response until the tarpit can release it
// in controlled chunks. It is intentionally an http.ResponseWriter so the
// deception package does not need to know whether throttling is enabled.
type ResponseCapture struct {
	header http.Header
	status int
	body   bytes.Buffer
}

// NewResponseCapture returns an empty response buffer.
func NewResponseCapture() *ResponseCapture {
	return &ResponseCapture{header: make(http.Header)}
}

func (c *ResponseCapture) Header() http.Header { return c.header }

func (c *ResponseCapture) WriteHeader(status int) {
	if c.status == 0 {
		c.status = status
	}
}

func (c *ResponseCapture) Write(body []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	return c.body.Write(body)
}

func (c *ResponseCapture) Status() int {
	if c.status == 0 {
		return http.StatusOK
	}
	return c.status
}

func (c *ResponseCapture) Body() []byte { return c.body.Bytes() }

// Throttle writes a captured deception response using the adaptive pacing
// policy. It is separate from Handle so custom Tarpit implementations can
// continue to implement the smaller interface.
func (t *AdaptiveTarpit) Throttle(w http.ResponseWriter, r *http.Request, cap *ResponseCapture) error {
	if cap == nil {
		return nil
	}
	return t.throttle(w, r, cap)
}

// --------------------------------------------------------------------------
// Context-based connection storage
// --------------------------------------------------------------------------

type connKeyType struct{}

var connKey = connKeyType{}

// WithConnection embeds the accepted net.Conn into the context. Use this as
// http.Server.ConnContext so every request handler can retrieve it via
// connFromContext without needing the ConnStore StateHook.
func WithConnection(ctx context.Context, conn net.Conn) context.Context {
	return context.WithValue(ctx, connKey, conn)
}

// connFromContext retrieves the net.Conn stored by WithConnection.
func connFromContext(ctx context.Context) (net.Conn, bool) {
	c, ok := ctx.Value(connKey).(net.Conn)
	return c, ok
}

// Config controls every tunable in the tarpit. Build it with DefaultConfig()
// and tweak only the fields you care about.
type Config struct {
	// ChunkSize is how many bytes are written per flush cycle.
	ChunkSize int

	// BaseDelay is added to every inter-chunk delay regardless of RTT.
	BaseDelay time.Duration

	// RTTMultiplier scales the measured RTT before adding it to BaseDelay.
	// A value of 2.0 means we wait roughly twice the observed RTT per chunk.
	RTTMultiplier float64

	// Jitter is the half-width of the uniform random noise added to each delay.
	// This prevents the inter-chunk timing from being a fixed fingerprint.
	Jitter time.Duration

	// MinDelay and MaxDelay clamp the final computed delay.
	MinDelay time.Duration
	MaxDelay time.Duration

	// FallbackRTT is used when the kernel RTT cannot be read (non-Linux or new
	// connection with no RTT sample yet).
	FallbackRTT time.Duration

	// Duration is the minimum time the tarpit will hold a connection open
	// regardless of how fast it finishes writing the buffered content.
	// When the content is exhausted before Duration elapses, the tarpit
	// continues emitting small keepalive chunks until the deadline.
	Duration time.Duration

	// MaxConcurrent caps the total number of goroutines simultaneously in the
	// slow chunk loop. Requests that arrive when the cap is full receive
	// http.StatusServiceUnavailable immediately (still no 403 or RST).
	MaxConcurrent int

	// MaxPerSource caps concurrent tarpits from a single source IP.
	MaxPerSource int
}

// DefaultConfig returns a Config calibrated to achieve >120 s dwell time at
// RTTs typical of internet attackers (≥20 ms) while staying under common
// scanner read timeouts (sqlmap: 30 s, nikto: 10 s).
func DefaultConfig() Config {
	return Config{
		ChunkSize:     32,
		BaseDelay:     600 * time.Millisecond,
		RTTMultiplier: 2.0,
		Jitter:        150 * time.Millisecond,
		MinDelay:      400 * time.Millisecond,
		MaxDelay:      4 * time.Second,
		FallbackRTT:   50 * time.Millisecond,
		Duration:      130 * time.Second,
		MaxConcurrent: 400,
		MaxPerSource:  3,
	}
}

// AdaptiveTarpit is the concrete tarpit implementation.
// Construct it with New; it is safe for concurrent use after construction.
type AdaptiveTarpit struct {
	cfg Config
	cs  *ConnStore

	// global semaphore: buffered channel of size MaxConcurrent.
	globalSlots chan struct{}

	// per-source tracking.
	sourceMu     sync.Mutex
	sourceCounts map[string]int
}

// ConnStore maps remote addresses to net.Conn so the tarpit can read
// TCP metadata (RTT via TCP_INFO) without hijacking the ResponseWriter.
type ConnStore struct {
	mu    sync.RWMutex
	conns map[string]net.Conn
}

// NewConnStore returns an empty ConnStore.
func NewConnStore() *ConnStore {
	return &ConnStore{conns: make(map[string]net.Conn)}
}

// StateHook returns a function suitable for http.Server.ConnState.
func (cs *ConnStore) StateHook() func(net.Conn, http.ConnState) {
	return func(c net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			cs.mu.Lock()
			cs.conns[c.RemoteAddr().String()] = c
			cs.mu.Unlock()
		case http.StateClosed, http.StateHijacked:
			cs.mu.Lock()
			delete(cs.conns, c.RemoteAddr().String())
			cs.mu.Unlock()
		}
	}
}

// get returns the stored connection for remoteAddr, if any.
func (cs *ConnStore) get(remoteAddr string) (net.Conn, bool) {
	cs.mu.RLock()
	c, ok := cs.conns[remoteAddr]
	cs.mu.RUnlock()
	return c, ok
}

// New constructs a ready-to-use AdaptiveTarpit.
func New(cfg Config) (*AdaptiveTarpit, error) {
	defaults := DefaultConfig()
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = defaults.ChunkSize
	}
	if cfg.BaseDelay <= 0 {
		cfg.BaseDelay = defaults.BaseDelay
	}
	if cfg.RTTMultiplier < 0 {
		return nil, fmt.Errorf("RTT multiplier must not be negative")
	}
	if cfg.MinDelay <= 0 {
		cfg.MinDelay = defaults.MinDelay
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = defaults.MaxDelay
	}
	if cfg.FallbackRTT <= 0 {
		cfg.FallbackRTT = defaults.FallbackRTT
	}
	if cfg.Duration <= 0 {
		cfg.Duration = defaults.Duration
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = defaults.MaxConcurrent
	}
	if cfg.MaxPerSource <= 0 {
		cfg.MaxPerSource = defaults.MaxPerSource
	}
	if cfg.MaxDelay < cfg.MinDelay {
		return nil, fmt.Errorf("max delay must be greater than or equal to min delay")
	}
	return &AdaptiveTarpit{
		cfg:          cfg,
		cs:           NewConnStore(),
		globalSlots:  make(chan struct{}, cfg.MaxConcurrent),
		sourceCounts: make(map[string]int),
	}, nil
}

// ConnStore returns the internal ConnStore for registration with http.Server.
func (t *AdaptiveTarpit) ConnStore() *ConnStore { return t.cs }

// Duration exposes the configured hold time to the HTTP server timeout setup.
func (t *AdaptiveTarpit) Duration() time.Duration { return t.cfg.Duration }

// Handle is the main entry point called by the proxy. It writes a
// semantically complete HTTP response (headers + body) to w, dripping the
// body in cfg.ChunkSize slices with adaptive inter-chunk delays.
//
// It first tries to retrieve the net.Conn from the request context (via
// WithConnection / http.Server.ConnContext), then falls back to the ConnStore.
// This dual lookup handles both the TLS and plain-HTTP serving paths.
func (t *AdaptiveTarpit) Handle(w http.ResponseWriter, r *http.Request) error {
	cap := NewResponseCapture()
	cap.Header().Set("Content-Type", "application/json")
	cap.Header().Set("X-Backend-Server", "mirage-demo-backend")
	cap.WriteHeader(http.StatusOK)
	_, _ = cap.Write([]byte(`{"status":"processing","data":[]`))
	for i := 0; i < 100; i++ {
		if i > 0 {
			_, _ = cap.Write([]byte(","))
		}
		_, _ = cap.Write(makeJSONChunk())
	}
	_, _ = cap.Write([]byte(`]}` + "\n"))
	err := t.throttle(w, r, cap)
	if errors.Is(err, ErrCapacity) {
		http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
		return nil
	}
	return err
}

func (t *AdaptiveTarpit) throttle(w http.ResponseWriter, r *http.Request, cap *ResponseCapture) error {
	sourceIP := sourceIP(r.RemoteAddr)

	// --- Concurrency gate (global) ---
	select {
	case t.globalSlots <- struct{}{}:
		defer func() { <-t.globalSlots }()
	default:
		return ErrCapacity
	}

	// --- Concurrency gate (per source IP) ---
	if !t.tryAcquireSource(sourceIP) {
		<-t.globalSlots
		return ErrCapacity
	}
	defer t.releaseSource(sourceIP)

	// --- Measure RTT (context conn first, then ConnStore fallback) ---
	rtt := t.cfg.FallbackRTT
	var conn net.Conn
	if c, ok := connFromContext(r.Context()); ok {
		conn = c
	} else if c, ok := t.cs.get(r.RemoteAddr); ok {
		conn = c
	}
	if conn != nil {
		if measured, ok := tcpRTT(conn); ok {
			rtt = measured
		}
	}
	delay := t.computeDelay(rtt)

	// --- Set up chunked streaming ---
	flusher, canFlush := w.(http.Flusher)
	for key, values := range cap.Header() {
		w.Header()[key] = append([]string(nil), values...)
	}
	w.Header().Del("Content-Length")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(cap.Status())

	deadline := time.Now().Add(t.cfg.Duration)
	ctx := r.Context()
	body := cap.Body()
	for offset := 0; offset < len(body); {
		if offset > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
		end := offset + t.cfg.ChunkSize
		if end > len(body) {
			end = len(body)
		}
		if _, err := w.Write(body[offset:end]); err != nil {
			return nil
		}
		if canFlush {
			flusher.Flush()
		}
		offset = end
	}

	for time.Now().Before(deadline) {
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
			return nil
		}
	}
	return nil
}

// --------------------------------------------------------------------------
// Delay computation
// --------------------------------------------------------------------------

// computeDelay applies the delay formula:
//
//	delay = clamp(base + α×rtt + Uniform(−jitter, +jitter), min, max)
func (t *AdaptiveTarpit) computeDelay(rtt time.Duration) time.Duration {
	cfg := t.cfg
	jitterRange := float64(cfg.Jitter)
	// rand.Float64() in [0, 1) → shift to [−jitter, +jitter)
	jitter := time.Duration((rand.Float64()*2 - 1) * jitterRange)

	d := cfg.BaseDelay + time.Duration(float64(rtt)*cfg.RTTMultiplier) + jitter
	if d < cfg.MinDelay {
		d = cfg.MinDelay
	}
	if d > cfg.MaxDelay {
		d = cfg.MaxDelay
	}
	return d
}

// --------------------------------------------------------------------------
// Per-source concurrency accounting
// --------------------------------------------------------------------------

func (t *AdaptiveTarpit) tryAcquireSource(ip string) bool {
	t.sourceMu.Lock()
	defer t.sourceMu.Unlock()
	if t.sourceCounts[ip] >= t.cfg.MaxPerSource {
		return false
	}
	t.sourceCounts[ip]++
	return true
}

func (t *AdaptiveTarpit) releaseSource(ip string) {
	t.sourceMu.Lock()
	t.sourceCounts[ip]--
	if t.sourceCounts[ip] <= 0 {
		delete(t.sourceCounts, ip)
	}
	t.sourceMu.Unlock()
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// makeJSONChunk returns a small but realistic-looking JSON object fragment
// that can be dripped as part of a streaming result array.
func makeJSONChunk() []byte {
	// 32-byte chunks — each looks like a partial DB row update.
	// We cycle through a small set of realistic fragments.
	fragments := [][]byte{
		[]byte(`{"id":` + randomIntStr() + `,"status":"ok"}`),
		[]byte(`{"row":` + randomIntStr() + `,"ts":"2024-01-01"}`),
		[]byte(`{"seq":` + randomIntStr() + `,"flag":true}`),
	}
	return fragments[rand.IntN(len(fragments))]
}

var intStrs = []string{
	"1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
	"11", "12", "42", "99", "100", "256", "512", "1024",
}

func randomIntStr() string {
	return intStrs[rand.IntN(len(intStrs))]
}

// sourceIP extracts the host part from a "host:port" remote address.
func sourceIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
