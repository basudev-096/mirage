package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EventStore is the persistence boundary used by the Redis consumer.
type EventStore interface {
	InsertBatch(context.Context, []Event) error
}

type SessionSummary struct {
	SessionID       string    `json:"session_id"`
	SourceIP        string    `json:"source_ip"`
	Principal       string    `json:"principal"`
	Authorization   string    `json:"authorization"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	Requests        int       `json:"requests"`
	Flagged         int       `json:"flagged"`
	SawUnauthorized bool      `json:"saw_unauthorized"`
	Diverted        int       `json:"diverted"`
	Tarpitted       int       `json:"tarpitted"`
	BytesServed     int64     `json:"bytes_served"`
	Categories      []string  `json:"categories"`
}

// Latest returns the newest persisted events for dashboard history.
func (s *PostgresStore) Latest(ctx context.Context, limit int) ([]Event, error) {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `SELECT request_id, session_id, session_requests, timestamp, source_ip, principal, auth_state,
	method, path, request_summary, request_preview, body_preview, content_type, user_agent,
	ja3, ja4, verdict, category, payload_class, rule_ids, score, inspection_time_us, action,
	phase, response_type, response_preview, response_status, duration_ms, tarpit_duration_ms, bytes_served
	FROM telemetry_events ORDER BY timestamp DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]Event, 0, limit)
	for rows.Next() {
		var event Event
		var ruleIDs []byte
		if err := rows.Scan(&event.RequestID, &event.SessionID, &event.SessionRequests, &event.Timestamp, &event.SourceIP,
			&event.Principal, &event.Authorization, &event.Method, &event.Path, &event.RequestSummary,
			&event.RequestPreview, &event.BodyPreview, &event.ContentType, &event.UserAgent,
			&event.JA3, &event.JA4, &event.Verdict, &event.Category, &event.PayloadClass,
			&ruleIDs, &event.Score, &event.InspectionTime, &event.Action, &event.Phase, &event.ResponseType,
			&event.ResponsePreview, &event.ResponseStatus, &event.DurationMS, &event.TarpitDuration, &event.BytesServed); err != nil {
			return nil, err
		}
		if len(ruleIDs) > 0 {
			_ = json.Unmarshal(ruleIDs, &event.RuleIDs)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

// Sessions returns durable per-client activity summaries for the command center.
func (s *PostgresStore) Sessions(ctx context.Context, limit int) ([]SessionSummary, error) {
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT session_id, source_ip,
	CASE WHEN COUNT(DISTINCT principal) > 1 THEN 'mixed' ELSE MAX(principal) END,
	CASE WHEN COUNT(DISTINCT auth_state) > 1 THEN 'mixed' ELSE MAX(auth_state) END,
	MIN(timestamp), MAX(timestamp),
	COUNT(*) FILTER (WHERE phase = 'completed'),
	COUNT(*) FILTER (WHERE phase = 'completed' AND verdict <> 'Clean'),
	BOOL_OR(auth_state = 'unauthorized'),
	COUNT(*) FILTER (WHERE phase = 'completed' AND action = 'honeypot'),
	COUNT(*) FILTER (WHERE phase = 'completed' AND action = 'tarpit'),
	COALESCE(SUM(bytes_served) FILTER (WHERE phase = 'completed'), 0),
	COALESCE(array_agg(DISTINCT category) FILTER (WHERE category <> ''), ARRAY[]::text[])
	FROM telemetry_events WHERE session_id <> '' GROUP BY session_id, source_ip
	ORDER BY MAX(timestamp) DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions := make([]SessionSummary, 0, limit)
	for rows.Next() {
		var item SessionSummary
		if err := rows.Scan(&item.SessionID, &item.SourceIP, &item.Principal, &item.Authorization,
			&item.FirstSeen, &item.LastSeen, &item.Requests, &item.Flagged, &item.SawUnauthorized, &item.Diverted,
			&item.Tarpitted, &item.BytesServed, &item.Categories); err != nil {
			return nil, err
		}
		sessions = append(sessions, item)
	}
	return sessions, rows.Err()
}

// PostgresStore persists telemetry events in batches.
type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	if dsn == "" {
		return nil, fmt.Errorf("postgres DSN is required")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return &PostgresStore{pool: pool}, nil
}

func (s *PostgresStore) Close() { s.pool.Close() }

func (s *PostgresStore) EnsureSchema(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS telemetry_events (
    id BIGSERIAL PRIMARY KEY,
    request_id TEXT NOT NULL DEFAULT '',
    session_id TEXT NOT NULL DEFAULT '',
    session_requests INTEGER NOT NULL DEFAULT 0,
    timestamp TIMESTAMPTZ NOT NULL,
    source_ip TEXT NOT NULL,
    principal TEXT NOT NULL DEFAULT 'anonymous',
    auth_state TEXT NOT NULL DEFAULT 'unknown',
    method TEXT NOT NULL,
    path TEXT NOT NULL,
	request_summary TEXT NOT NULL DEFAULT '',
	request_preview TEXT NOT NULL DEFAULT '',
	body_preview TEXT NOT NULL DEFAULT '',
	content_type TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    ja3 TEXT NOT NULL DEFAULT '',
    ja4 TEXT NOT NULL DEFAULT '',
    verdict TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    payload_class TEXT NOT NULL DEFAULT '',
    rule_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    score INTEGER NOT NULL DEFAULT 0,
    inspection_time_us BIGINT NOT NULL DEFAULT 0,
    action TEXT NOT NULL,
	phase TEXT NOT NULL DEFAULT '',
	response_type TEXT NOT NULL DEFAULT '',
	response_preview TEXT NOT NULL DEFAULT '',
	response_status INTEGER NOT NULL DEFAULT 0,
	duration_ms BIGINT NOT NULL DEFAULT 0,
    tarpit_duration_ms BIGINT NOT NULL DEFAULT 0,
    bytes_served BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS phase TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS request_summary TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS request_id TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS session_id TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS session_requests INTEGER NOT NULL DEFAULT 0;
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS principal TEXT NOT NULL DEFAULT 'anonymous';
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS auth_state TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS request_preview TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS body_preview TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS content_type TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS response_type TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS response_preview TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS response_status INTEGER NOT NULL DEFAULT 0;
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS duration_ms BIGINT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS telemetry_events_timestamp_idx ON telemetry_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS telemetry_events_source_idx ON telemetry_events (source_ip);
CREATE INDEX IF NOT EXISTS telemetry_events_session_idx ON telemetry_events (session_id, timestamp DESC);
`)
	return err
}

func (s *PostgresStore) InsertBatch(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, event := range events {
		_, err = tx.Exec(ctx, `
INSERT INTO telemetry_events
	 (request_id, session_id, session_requests, timestamp, source_ip, principal, auth_state,
	  method, path, request_summary, request_preview, body_preview, content_type, user_agent, ja3, ja4,
	  verdict, category, payload_class, rule_ids, score, inspection_time_us, action, phase, response_type,
	  response_preview, response_status, duration_ms, tarpit_duration_ms, bytes_served)
	 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20::jsonb,
	 $21,$22,$23,$24,$25,$26,$27,$28,$29,$30)`,
			event.RequestID, event.SessionID, event.SessionRequests, normalizeTimestamp(event.Timestamp), event.SourceIP,
			event.Principal, event.Authorization, event.Method, event.Path, event.RequestSummary,
			event.RequestPreview, event.BodyPreview, event.ContentType, event.UserAgent, event.JA3, event.JA4,
			event.Verdict, event.Category, event.PayloadClass, marshalRuleIDs(event.RuleIDs), event.Score,
			event.InspectionTime, event.Action, event.Phase, event.ResponseType, event.ResponsePreview,
			event.ResponseStatus, event.DurationMS, event.TarpitDuration, event.BytesServed)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func normalizeTimestamp(timestamp time.Time) time.Time {
	if timestamp.IsZero() {
		return time.Now().UTC()
	}
	return timestamp
}

func marshalRuleIDs(ruleIDs []string) string {
	encoded, err := json.Marshal(ruleIDs)
	if err != nil {
		return "[]"
	}
	return string(encoded)
}
