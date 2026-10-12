package detect

import (
	"context"
	"net/http"
	"time"
)

// RuleID uniquely identifies a triggered security rule.
type RuleID string

// Verdict represents the outcome of inspecting an HTTP request.
type Verdict struct {
	Malicious      bool          `json:"malicious"`        // True if anomaly score >= threshold or rule matched
	Category       string        `json:"category"`         // e.g., "SQLi", "XSS", "RCE", "PathTraversal", "WAF_Timeout", "DecompressionError"
	RuleIDs        []RuleID      `json:"rule_ids"`         // Triggered OWASP CRS or custom rule IDs
	Score          int           `json:"score"`            // Cumulative Coraza inbound anomaly score
	OversizedBody  bool          `json:"oversized_body"`   // True if Content-Length or actual body exceeded N=32KB
	BodyTruncated  bool          `json:"body_truncated"`   // True if WAF inspection was performed on a partial body slice
	InspectionTime time.Duration `json:"inspection_time"` // Time taken for WAF inspection
	Error          error         `json:"error,omitempty"`  // Inspection error or timeout if encountered
}

// Config specifies detection engine operational parameters.
type Config struct {
	ParanoiaLevel            int           `json:"paranoia_level"`             // Default 1
	AnomalyThreshold         int           `json:"anomaly_threshold"`          // Default 5
	MaxBodyInspectSize       int           `json:"max_body_inspect_size"`      // Default 32768 (32KB)
	Timeout                  time.Duration `json:"timeout"`                    // Default 5ms
	MaxConcurrentInspections int           `json:"max_concurrent_inspections"` // Default 500
	FailClosed               bool          `json:"fail_closed"`                // Default false (fail-open)
	EvalBlock                bool          `json:"eval_block"`                 // Returns 403 when malicious (for evaluation)
}

// DefaultConfig returns sane production default settings for Phase 2.
func DefaultConfig() Config {
	return Config{
		ParanoiaLevel:            1,
		AnomalyThreshold:         5,
		MaxBodyInspectSize:       32768, // 32KB
		Timeout:                  5 * time.Millisecond,
		MaxConcurrentInspections: 500,
		FailClosed:               false,
		EvalBlock:                false,
	}
}

// Detector defines the contract for request inspection engines.
type Detector interface {
	// Inspect evaluates an HTTP request and returns a Verdict.
	Inspect(ctx context.Context, req *http.Request) (Verdict, error)
}
