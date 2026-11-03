package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/mirage-proxy/mirage/internal/telemetry"
	"github.com/redis/go-redis/v9"
)

func main() {
	listenAddr := getEnv("INGEST_LISTEN_ADDR", ":8090")
	redisAddr := getEnv("REDIS_ADDR", "127.0.0.1:6380")
	redisStream := getEnv("REDIS_STREAM", "mirage:events")
	redisGroup := getEnv("REDIS_GROUP", "mirage-ingest")
	redisConsumer := getEnv("REDIS_CONSUMER", hostname())
	databaseURL := getEnv("DATABASE_URL", "postgres://mirage:mirage_password@127.0.0.1:5433/mirage_telemetry")

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

	hub := telemetry.NewHub()
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
			switch r.URL.Path {
			case "/healthz":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok\n"))
			case "/ws":
				hub.ServeHTTP(w, r)
			default:
				http.NotFound(w, r)
			}
		}),
	}

	go func() {
		log.Printf("Mirage ingest listening on %s", listenAddr)
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
