package proxy

import (
	"crypto/tls"
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

	"github.com/mirage-proxy/mirage/internal/detect"
)

// Config defines the operational parameters for the Mirage edge reverse proxy.
type Config struct {
	TargetURL      string
	ListenAddr     string
	TLSCertFile    string
	TLSKeyFile     string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	FlushInterval  time.Duration
	Detector       detect.Detector
	EvalBlock      bool
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

	if tb != nil {
		tb.Reset()
	}

	verdictHeader := "Clean"
	if verdict.Malicious {
		verdictHeader = "Malicious"
	}
	r.Header.Set("X-Mirage-Verdict", verdictHeader)

	if verdict.Malicious && p.cfg.EvalBlock {
		if tb != nil {
			tb.Close()
		}
		w.Header().Set("X-Mirage-Verdict", verdictHeader)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden","message":"Request blocked by security policy"}`))
		return
	}

	p.reverseProxy.ServeHTTP(w, r)
}

// Server returns an *http.Server configured with sane timeouts and optional TLS settings.
func (p *Proxy) Server(tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:         p.cfg.ListenAddr,
		Handler:      p,
		ReadTimeout:  p.cfg.ReadTimeout,
		WriteTimeout: p.cfg.WriteTimeout,
		IdleTimeout:  p.cfg.IdleTimeout,
		TLSConfig:    tlsConfig,
	}
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
