// Package telemetry defines the event contract shared by the proxy and the
// downstream ingest pipeline.
package telemetry

import "time"

// Event is the durable summary of one inspected request. It intentionally
// contains request metadata, not request bodies or generated secret values.
type Event struct {
	RequestID        string    `json:"request_id,omitempty"`
	SessionID        string    `json:"session_id,omitempty"`
	SessionRequests  int       `json:"session_requests,omitempty"`
	Timestamp        time.Time `json:"timestamp"`
	SourceIP         string    `json:"source_ip"`
	Principal        string    `json:"principal,omitempty"`
	Authorization    string    `json:"authorization,omitempty"`
	Method           string    `json:"method"`
	Path             string    `json:"path"`
	RequestSummary   string    `json:"request_summary,omitempty"`
	RequestPreview   string    `json:"request_preview,omitempty"`
	BodyPreview      string    `json:"body_preview,omitempty"`
	ContentType      string    `json:"content_type,omitempty"`
	UserAgent        string    `json:"user_agent,omitempty"`
	JA3              string    `json:"ja3,omitempty"`
	JA4              string    `json:"ja4,omitempty"`
	Verdict          string    `json:"verdict"`
	Category         string    `json:"category,omitempty"`
	PayloadClass     string    `json:"payload_class,omitempty"`
	RuleIDs          []string  `json:"rule_ids,omitempty"`
	Score            int       `json:"score,omitempty"`
	InspectionTime   int64     `json:"inspection_time_us"`
	Action           string    `json:"action"`
	Phase            string    `json:"phase"`
	ResponseType     string    `json:"response_type,omitempty"`
	DeceptionType    string    `json:"deception_type,omitempty"`
	TargetDatabase   string    `json:"target_database,omitempty"`
	TargetSchema     string    `json:"target_schema,omitempty"`
	TargetTable      string    `json:"target_table,omitempty"`
	TargetColumns    []string  `json:"target_columns,omitempty"`
	Operation        string    `json:"operation,omitempty"`
	ResponseMetadata string    `json:"response_metadata,omitempty"`
	ResponseStatus   int       `json:"response_status,omitempty"`
	DurationMS       int64     `json:"duration_ms,omitempty"`
	TarpitDuration   int64     `json:"tarpit_duration_ms,omitempty"`
	BytesServed      int64     `json:"bytes_served,omitempty"`
}
