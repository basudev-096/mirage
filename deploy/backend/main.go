package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type Response struct {
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	Query     string    `json:"query,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Backend-Server", "mirage-demo-backend")
		json.NewEncoder(w).Encode(Response{
			Status:    "success",
			Message:   "Welcome to the production demo target backend server",
			Timestamp: time.Now().UTC(),
		})
	})

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Backend-Server", "mirage-demo-backend")
		json.NewEncoder(w).Encode(Response{
			Status:    "success",
			Message:   fmt.Sprintf("Found 3 results for query: %s", query),
			Query:     query,
			Timestamp: time.Now().UTC(),
		})
	})

	log.Printf("Demo Backend listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Backend server failed: %v", err)
	}
}
