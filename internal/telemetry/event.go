// Package telemetry defines the event contract shared by the proxy and the
// downstream ingest pipeline.
package telemetry

import "time"

// Event is the durable summary of one inspected request. It intentionally
// contains request metadata, not request bodies or generated secret values.
type Event struct {
	Timestamp       time.Time `json:"timestamp"`
	SourceIP        string    `json:"source_ip"`
	Method          string    `json:"method"`
	Path            string    `json:"path"`
	RequestSummary  string    `json:"request_summary,omitempty"`
	UserAgent       string    `json:"user_agent,omitempty"`
	JA3             string    `json:"ja3,omitempty"`
	JA4             string    `json:"ja4,omitempty"`
	Verdict         string    `json:"verdict"`
	Category        string    `json:"category,omitempty"`
	PayloadClass    string    `json:"payload_class,omitempty"`
	RuleIDs         []string  `json:"rule_ids,omitempty"`
	Score           int       `json:"score,omitempty"`
	InspectionTime  int64     `json:"inspection_time_us"`
	Action          string    `json:"action"`
	Phase           string    `json:"phase"`
	ResponseType    string    `json:"response_type,omitempty"`
	ResponsePreview string    `json:"response_preview,omitempty"`
	TarpitDuration  int64     `json:"tarpit_duration_ms,omitempty"`
	BytesServed     int64     `json:"bytes_served,omitempty"`
}
