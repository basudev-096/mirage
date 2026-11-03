package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mirage-proxy/mirage/internal/deceive"
	"github.com/mirage-proxy/mirage/internal/detect"
	"github.com/mirage-proxy/mirage/internal/fingerprint"
	"github.com/mirage-proxy/mirage/internal/tarpit"
	"github.com/mirage-proxy/mirage/internal/telemetry"
)

// Config defines the operational parameters for the edge reverse proxy.
type Config struct {
	TargetURL     string
	ListenAddr    string
	TLSCertFile   string
	TLSKeyFile    string
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	IdleTimeout   time.Duration
	FlushInterval time.Duration
	Detector      detect.Detector
	Tarpit        tarpit.Tarpit
	// Deceiver, when non-nil, handles all flagged requests by synthesising a
	// fake response instead of forwarding to the real backend. This is the
	// normal production mode. EvalBlock takes precedence when both are set.
	Deceiver  deceive.Deceiver
	EvalBlock bool
	Telemetry *telemetry.Publisher
}

// DefaultConfig returns sane default parameters for high-throughput production proxying.
func DefaultConfig() Config {
	return Config{
		TargetURL:     "http://127.0.0.1:8080",
		ListenAddr:    ":8443",
		ReadTimeout:   30 * time.Second,
		WriteTimeout:  30 * time.Second,
		IdleTimeout:   120 * time.Second,
		FlushInterval: 100 * time.Millisecond,
		EvalBlock:     false,
	}
}

// Proxy encapsulates the transparent HTTP/HTTPS reverse proxy handler.
type Proxy struct {
	cfg          Config
	targetURL    *url.URL
	reverseProxy *httputil.ReverseProxy
	transport    *http.Transport
	detector     detect.Detector
	deceiver     deceive.Deceiver
	tarpit       tarpit.Tarpit
}

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32768)
		return &b
	},
}

type trackedBody struct {
	mu       sync.Mutex
	once     sync.Once
	origBody io.ReadCloser
	poolBuf  *[]byte
	buf      []byte
	off      int
	closed   bool
}

type responseMetricsWriter struct {
	http.ResponseWriter
	bytes       int64
	status      int
	wroteHeader bool
}

func (w *responseMetricsWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseMetricsWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(body)
	w.bytes += int64(n)
	return n, err
}

func (w *responseMetricsWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *responseMetricsWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

func (w *responseMetricsWriter) Push(target string, options *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, options)
}

func (w *responseMetricsWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func newTrackedBody(orig io.ReadCloser) (*trackedBody, error) {
	if orig == nil || orig == http.NoBody {
		return nil, nil
	}
	poolBuf := bufPool.Get().(*[]byte)
	n, err := io.ReadFull(orig, *poolBuf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		bufPool.Put(poolBuf)
		return nil, err
	}
	return &trackedBody{
		origBody: orig,
		poolBuf:  poolBuf,
		buf:      (*poolBuf)[:n],
	}, nil
}

func (tb *trackedBody) Read(p []byte) (int, error) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if tb.closed {
		return 0, io.ErrClosedPipe
	}

	if tb.off < len(tb.buf) {
		n := copy(p, tb.buf[tb.off:])
		tb.off += n
		return n, nil
	}

	return tb.origBody.Read(p)
}

func (tb *trackedBody) Reset() {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.off = 0
}

func (tb *trackedBody) Close() error {
	var err error
	tb.once.Do(func() {
		tb.mu.Lock()
		tb.closed = true
		if tb.origBody != nil {
			err = tb.origBody.Close()
		}
		if tb.poolBuf != nil {
			bufPool.Put(tb.poolBuf)
			tb.poolBuf = nil
			tb.buf = nil
		}
		tb.mu.Unlock()
	})
	return err
}

// NewProxy constructs a transparent ReverseProxy targeting targetURL.
func NewProxy(cfg Config) (*Proxy, error) {
	parsedURL, err := url.Parse(cfg.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL %q: %w", cfg.TargetURL, err)
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   200,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	p := &Proxy{
		cfg:       cfg,
		targetURL: parsedURL,
		transport: transport,
		detector:  cfg.Detector,
		deceiver:  cfg.Deceiver,
		tarpit:    cfg.Tarpit,
	}

	rp := &httputil.ReverseProxy{
		Director:      p.director,
		Transport:     transport,
		FlushInterval: cfg.FlushInterval,
		ErrorHandler:  p.errorHandler,
	}

	p.reverseProxy = rp
	return p, nil
}

// director mutates incoming client HTTP requests before forwarding them to the upstream target backend.
func (p *Proxy) director(req *http.Request) {
	req.URL.Scheme = p.targetURL.Scheme
	req.URL.Host = p.targetURL.Host

	// Set X-Forwarded-* headers
	clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil {
		if prior, ok := req.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	if req.TLS != nil {
		req.Header.Set("X-Forwarded-Proto", "https")
	} else {
		req.Header.Set("X-Forwarded-Proto", "http")
	}

	if req.Host != "" {
		req.Header.Set("X-Forwarded-Host", req.Host)
	}

	// Host header preservation option (transparent mode)
	req.Host = p.targetURL.Host
}

// errorHandler handles upstream proxy connection or response failures.
func (p *Proxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("[Proxy Error] Upstream connection failure to %s: %v", p.targetURL.String(), err)
	w.WriteHeader(http.StatusBadGateway)
	_, _ = w.Write([]byte(`{"error":"bad_gateway","message":"Upstream server failed to respond"}`))
}

// ServeHTTP delegates request processing to the internal ReverseProxy.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	metrics := &responseMetricsWriter{ResponseWriter: w}
	w = fingerprint.NewWriter(metrics)
	if p.detector == nil {
		p.reverseProxy.ServeHTTP(w, r)
		return
	}

	var tb *trackedBody
	if r.Body != nil && r.Body != http.NoBody {
		var err error
		tb, err = newTrackedBody(r.Body)
		if err != nil {
			log.Printf("[Proxy Error] Failed to buffer request body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		r.Body = tb
	}

	verdict, err := p.detector.Inspect(r.Context(), r)
	if err != nil {
		log.Printf("[Detector Warning] Inspection error: %v", err)
	}
	log.Printf("[Detector] %s %s category=%s score=%d rules=%v duration=%s", r.Method, r.URL.RequestURI(), verdict.Category, verdict.Score, verdict.RuleIDs, verdict.InspectionTime)

	if tb != nil {
		tb.Reset()
	}

	verdictHeader := "Clean"
	if verdict.Malicious {
		verdictHeader = "Malicious"
	}
	r.Header.Set("X-Mirage-Verdict", verdictHeader)
	useTarpit := verdict.Malicious && p.tarpit != nil && shouldTarpit(r)
	event := telemetry.Event{
		Timestamp:      time.Now().UTC(),
		SourceIP:       sourceIP(r.RemoteAddr),
		Method:         r.Method,
		Path:           r.URL.Path,
		RequestSummary: requestSummary(r),
		UserAgent:      r.UserAgent(),
		Verdict:        verdictHeader,
		Category:       verdict.Category,
		PayloadClass:   verdict.Category,
		Score:          verdict.Score,
		InspectionTime: verdict.InspectionTime.Microseconds(),
		Action:         "passthrough",
	}
	ruleIDs := make([]string, len(verdict.RuleIDs))
	for i, ruleID := range verdict.RuleIDs {
		ruleIDs[i] = string(ruleID)
	}
	event.RuleIDs = ruleIDs
	started := time.Now()
	if p.cfg.Telemetry != nil {
		if verdict.Malicious {
			event.Action = "honeypot"
			if useTarpit {
				event.Action = "tarpit"
			}
		}
		if verdict.Malicious {
			event.Phase = "started"
			p.cfg.Telemetry.Publish(event)
		}
		defer func() {
			event.Phase = "completed"
			event.TarpitDuration = time.Since(started).Milliseconds()
			event.BytesServed = metrics.bytes
			p.cfg.Telemetry.Publish(event)
		}()
	}

	if verdict.Malicious {
		if tb != nil {
			tb.Close()
		}

		// EvalBlock mode: return 403 for gotestwaf scoring runs.
		if p.cfg.EvalBlock {
			w.Header().Set("X-Mirage-Verdict", verdictHeader)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden","message":"Request blocked by security policy"}`))
			return
		}

		// Deception mode: synthesise a fake response — the TLS session is
		// never reset and the backend is never contacted.
		if useTarpit {
			if p.deceiver != nil {
				if throttler, ok := p.tarpit.(interface {
					Throttle(http.ResponseWriter, *http.Request, *tarpit.ResponseCapture) error
				}); ok {
					captured := tarpit.NewResponseCapture()
					if err := p.deceiver.Handle(captured, r, deceive.Category(verdict.Category)); err != nil {
						log.Printf("[Deceiver Error] %v", err)
						return
					}
					event.ResponseType = "adaptive_fake_response"
					event.ResponsePreview = previewResponse(captured.Body())
					if err := throttler.Throttle(w, r, captured); err != nil {
						if errors.Is(err, tarpit.ErrCapacity) && p.deceiver != nil {
							_ = p.deceiver.Handle(w, r, deceive.Category(verdict.Category))
							return
						}
						log.Printf("[Tarpit Error] %v", err)
					}
					return
				}
			}
			if err := p.tarpit.Handle(w, r); err != nil {
				log.Printf("[Tarpit Error] %v", err)
			}
			return
		}
		if p.deceiver != nil {
			category := deceive.Category(verdict.Category)
			captured := tarpit.NewResponseCapture()
			if err := p.deceiver.Handle(captured, r, category); err != nil {
				log.Printf("[Deceiver Error] %v", err)
				return
			}
			event.ResponseType = "fake_honeypot_response"
			event.ResponsePreview = previewResponse(captured.Body())
			copyCapturedResponse(w, captured)
			return
		}
	}

	p.reverseProxy.ServeHTTP(w, r)
}

// shouldTarpit selects slow deception for scanner-like traffic. Exploit
// requests from ordinary clients still receive an immediate honeypot response,
// which lets the same running proxy demonstrate both actions automatically.
func shouldTarpit(r *http.Request) bool {
	ua := strings.ToLower(r.UserAgent())
	for _, marker := range []string{"sqlmap", "nikto", "masscan", "nmap", "python-requests", "zgrab", "gobuster", "dirbuster"} {
		if strings.Contains(ua, marker) {
			return true
		}
	}
	path := strings.ToLower(r.URL.Path)
	for _, probe := range []string{"/.env", "/.git", "/wp-admin", "/actuator", "/server-status", "/phpmyadmin"} {
		if strings.HasPrefix(path, probe) {
			return true
		}
	}
	return false
}

func requestSummary(r *http.Request) string {
	query := r.URL.Query()
	for key, values := range query {
		if len(values) > 0 {
			return r.Method + " " + r.URL.Path + "?" + key + "=" + truncateActivity(values[0])
		}
	}
	return r.Method + " " + r.URL.Path
}

func previewResponse(body []byte) string {
	const maxPreview = 512
	return string(body[:minInt(len(body), maxPreview)])
}

func truncateActivity(value string) string {
	const maxValue = 160
	if len(value) <= maxValue {
		return value
	}
	return value[:maxValue] + "..."
}

func copyCapturedResponse(w http.ResponseWriter, captured *tarpit.ResponseCapture) {
	for key, values := range captured.Header() {
		w.Header()[key] = append([]string(nil), values...)
	}
	w.WriteHeader(captured.Status())
	_, _ = w.Write(captured.Body())
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

// Server returns an *http.Server configured with sane timeouts and optional TLS settings.
func (p *Proxy) Server(tlsConfig *tls.Config) *http.Server {
	writeTimeout := p.cfg.WriteTimeout
	if durationProvider, ok := p.tarpit.(interface{ Duration() time.Duration }); ok {
		if tarpitTimeout := durationProvider.Duration() + 10*time.Second; tarpitTimeout > writeTimeout {
			writeTimeout = tarpitTimeout
		}
	}
	server := &http.Server{
		Addr:         p.cfg.ListenAddr,
		Handler:      p,
		ReadTimeout:  p.cfg.ReadTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  p.cfg.IdleTimeout,
		TLSConfig:    tlsConfig,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			return tarpit.WithConnection(ctx, conn)
		},
	}
	if p.tarpit != nil {
		server.ConnState = p.tarpit.ConnStore().StateHook()
	}
	return server
}

func sourceIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

// DefaultTLSConfig returns a recommended TLS 1.2/1.3 configuration with strong cipher suites.
func DefaultTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate pair (%s, %s): %w", certFile, keyFile, err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}, nil
}
