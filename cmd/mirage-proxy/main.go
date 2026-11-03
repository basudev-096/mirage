package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/mirage-proxy/mirage/internal/deceive"
	"github.com/mirage-proxy/mirage/internal/detect"
	"github.com/mirage-proxy/mirage/internal/proxy"
	"github.com/mirage-proxy/mirage/internal/tarpit"
	"github.com/mirage-proxy/mirage/internal/telemetry"
	"github.com/redis/go-redis/v9"
)

func main() {
	targetURL := flag.String("target", getEnv("TARGET_URL", "http://127.0.0.1:8080"), "Target upstream backend URL")
	listenAddr := flag.String("listen", getEnv("LISTEN_ADDR", ":8443"), "HTTPS proxy listen address")
	certFile := flag.String("cert", getEnv("TLS_CERT", "deploy/certs/server.crt"), "TLS certificate file path")
	keyFile := flag.String("key", getEnv("TLS_KEY", "deploy/certs/server.key"), "TLS key file path")
	evalBlock := flag.Bool("eval-block", getEnvBool("MIRAGE_EVAL_BLOCK", false), "Enable 403 evaluation blocking for flagged requests")
	tarpitEnabled := flag.Bool("tarpit", getEnvBool("MIRAGE_TARPIT", false), "Enable adaptive tarpit for flagged requests")
	wafTimeout := flag.Duration("waf-timeout", getEnvDuration("MIRAGE_WAF_TIMEOUT", 50*time.Millisecond), "Maximum time allowed for each WAF inspection")
	redisAddr := flag.String("redis-addr", getEnv("REDIS_ADDR", "127.0.0.1:6380"), "Redis address for telemetry")
	redisStream := flag.String("redis-stream", getEnv("REDIS_STREAM", "mirage:events"), "Redis telemetry stream")
	telemetryQueue := flag.Int("telemetry-queue", getEnvInt("MIRAGE_TELEMETRY_QUEUE", 4096), "Bounded telemetry queue size")
	flag.Parse()

	log.Println("==========================================================")
	log.Println(" Starting Project Mirage Edge Proxy (Phase 2+3)")
	log.Printf(" Target Upstream: %s", *targetURL)
	log.Printf(" HTTPS Listening: %s", *listenAddr)
	log.Printf(" Eval Block Mode: %t", *evalBlock)
	log.Printf(" Adaptive Tarpit: %t", *tarpitEnabled)
	log.Printf(" WAF Inspection Timeout: %s", *wafTimeout)
	if !*evalBlock {
		log.Println(" Deception Mode: ACTIVE (fake responses for flagged requests)")
	}
	log.Println("==========================================================")

	detCfg := detect.DefaultConfig()
	detCfg.Timeout = *wafTimeout
	detCfg.EvalBlock = *evalBlock
	detector, err := detect.NewCorazaDetector(detCfg)
	if err != nil {
		log.Fatalf("Failed to initialize Coraza WAF detector: %v", err)
	}
	redisClient := redis.NewClient(&redis.Options{Addr: *redisAddr})
	redisSink, err := telemetry.NewRedisSink(redisClient, *redisStream, 100000)
	if err != nil {
		log.Fatalf("Failed to initialize telemetry sink: %v", err)
	}
	telemetryPublisher := telemetry.NewPublisher(context.Background(), *telemetryQueue, redisSink)
	defer func() {
		telemetryPublisher.Close()
		_ = redisClient.Close()
	}()

	cfg := proxy.DefaultConfig()
	cfg.TargetURL = *targetURL
	cfg.ListenAddr = *listenAddr
	cfg.Detector = detector
	cfg.EvalBlock = *evalBlock
	cfg.Telemetry = telemetryPublisher
	// Wire the deception sandbox for production divert mode.
	// EvalBlock (gotestwaf scoring) takes precedence over deception when set.
	if !*evalBlock {
		cfg.Deceiver = deceive.NewSandboxDeceiver()
	}
	if *tarpitEnabled && !*evalBlock {
		adaptiveTarpit, err := tarpit.New(tarpit.DefaultConfig())
		if err != nil {
			log.Fatalf("Failed to initialize adaptive tarpit: %v", err)
		}
		cfg.Tarpit = adaptiveTarpit
	}

	p, err := proxy.NewProxy(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize Mirage proxy: %v", err)
	}

	var server *http.Server

	// Check if TLS certificates are present
	if fileExists(*certFile) && fileExists(*keyFile) {
		tlsConfig, err := proxy.DefaultTLSConfig(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("TLS initialization failed: %v", err)
		}
		server = p.Server(tlsConfig)
		go func() {
			log.Printf("Proxy HTTPS server listening on https://%s", *listenAddr)
			if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS server error: %v", err)
			}
		}()
	} else {
		log.Printf("[WARNING] TLS certificates (%s, %s) not found. Falling back to HTTP mode on %s", *certFile, *keyFile, *listenAddr)
		server = p.Server(nil)
		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP server error: %v", err)
			}
		}()
	}

	// Graceful shutdown handling
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	log.Println("\nShutting down Mirage Edge Proxy gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced shutdown error: %v", err)
	}

	log.Println("Mirage Edge Proxy stopped cleanly.")
}

func getEnv(key, defaultValue string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		b, err := strconv.ParseBool(val)
		if err == nil {
			return b
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		duration, err := time.ParseDuration(val)
		if err == nil && duration > 0 {
			return duration
		}
		log.Printf("[WARNING] Invalid duration for %s=%q; using %s", key, val, defaultValue)
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if val := os.Getenv(key); val != "" {
		parsed, err := strconv.Atoi(val)
		if err == nil && parsed > 0 {
			return parsed
		}
		log.Printf("[WARNING] Invalid integer for %s=%q; using %d", key, val, defaultValue)
	}
	return defaultValue
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
