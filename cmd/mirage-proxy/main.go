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

	"github.com/mirage-proxy/mirage/internal/detect"
	"github.com/mirage-proxy/mirage/internal/proxy"
)

func main() {
	targetURL := flag.String("target", getEnv("TARGET_URL", "http://127.0.0.1:8080"), "Target upstream backend URL")
	listenAddr := flag.String("listen", getEnv("LISTEN_ADDR", ":8443"), "HTTPS proxy listen address")
	certFile := flag.String("cert", getEnv("TLS_CERT", "deploy/certs/server.crt"), "TLS certificate file path")
	keyFile := flag.String("key", getEnv("TLS_KEY", "deploy/certs/server.key"), "TLS key file path")
	evalBlock := flag.Bool("eval-block", getEnvBool("MIRAGE_EVAL_BLOCK", false), "Enable 403 evaluation blocking for flagged requests")
	flag.Parse()

	log.Println("==========================================================")
	log.Println(" Starting Project Mirage Edge Proxy (Phase 2 Detection)")
	log.Printf(" Target Upstream: %s", *targetURL)
	log.Printf(" HTTPS Listening: %s", *listenAddr)
	log.Printf(" Eval Block Mode: %t", *evalBlock)
	log.Println("==========================================================")

	detCfg := detect.DefaultConfig()
	detCfg.EvalBlock = *evalBlock
	detector, err := detect.NewCorazaDetector(detCfg)
	if err != nil {
		log.Fatalf("Failed to initialize Coraza WAF detector: %v", err)
	}

	cfg := proxy.DefaultConfig()
	cfg.TargetURL = *targetURL
	cfg.ListenAddr = *listenAddr
	cfg.Detector = detector
	cfg.EvalBlock = *evalBlock

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

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
