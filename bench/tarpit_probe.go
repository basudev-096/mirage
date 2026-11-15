package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/mirage-proxy/mirage/internal/tarpit"
)

type sample struct {
	name    string
	chunks  int
	bytes   int64
	elapsed time.Duration
}

func main() {
	runs := flag.Int("runs", 5, "number of samples per mode")
	cutoff := flag.Duration("cutoff", 1200*time.Millisecond, "client read cutoff")
	flag.Parse()
	if *runs < 1 || *cutoff <= 0 {
		panic("runs and cutoff must be positive")
	}

	for _, mode := range []string{"flat-1b-s", "adaptive"} {
		var samples []sample
		for i := 0; i < *runs; i++ {
			result, err := run(mode, *cutoff)
			if err != nil {
				panic(err)
			}
			samples = append(samples, result)
		}
		var totalChunks, totalBytes int
		var totalElapsed time.Duration
		for _, result := range samples {
			totalChunks += result.chunks
			totalBytes += int(result.bytes)
			totalElapsed += result.elapsed
		}
		fmt.Printf("mode=%s runs=%d mean_elapsed=%s mean_chunks=%.1f mean_bytes=%.1f\n",
			mode, *runs, totalElapsed/time.Duration(*runs), float64(totalChunks)/float64(*runs), float64(totalBytes)/float64(*runs))
	}
}

func run(mode string, cutoff time.Duration) (sample, error) {
	handler, err := handlerFor(mode)
	if err != nil {
		return sample{}, err
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), cutoff)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		return sample{}, err
	}
	started := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return sample{}, err
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil && ctx.Err() == nil {
		return sample{}, readErr
	}
	chunkSize := 1
	if mode == "adaptive" {
		chunkSize = len([]byte(" {\"status\":\"processing\"}\n"))
	}
	return sample{
		name:    mode,
		chunks:  (len(body) + chunkSize - 1) / chunkSize,
		bytes:   int64(len(body)),
		elapsed: time.Since(started),
	}, nil
}

func handlerFor(mode string) (http.Handler, error) {
	if mode == "flat-1b-s" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			flusher, ok := w.(http.Flusher)
			if !ok {
				return
			}
			_, _ = w.Write([]byte("1"))
			flusher.Flush()
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-r.Context().Done():
					return
				case <-ticker.C:
					_, _ = w.Write([]byte("1"))
					flusher.Flush()
				}
			}
		}), nil
	}
	if mode != "adaptive" {
		return nil, fmt.Errorf("unknown mode %q", mode)
	}
	cfg := tarpit.DefaultConfig()
	cfg.BaseDelay = 10 * time.Millisecond
	cfg.MinDelay = 5 * time.Millisecond
	cfg.MaxDelay = 20 * time.Millisecond
	cfg.Duration = time.Hour
	t, err := tarpit.New(cfg)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = t.Handle(w, r)
	}), nil
}
