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

type EventHistory interface {
	Recent(context.Context, int) ([]Event, error)
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
    timestamp TIMESTAMPTZ NOT NULL,
    source_ip TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
	request_summary TEXT NOT NULL DEFAULT '',
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
    tarpit_duration_ms BIGINT NOT NULL DEFAULT 0,
    bytes_served BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS phase TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS request_summary TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS response_type TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS response_preview TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS telemetry_events_timestamp_idx ON telemetry_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS telemetry_events_source_idx ON telemetry_events (source_ip);
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
	 (timestamp, source_ip, method, path, request_summary, user_agent, ja3, ja4, verdict, category,
  payload_class, rule_ids, score, inspection_time_us, action, phase, response_type, response_preview, tarpit_duration_ms, bytes_served)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15,$16,$17,$18,$19,$20)`,
			normalizeTimestamp(event.Timestamp), event.SourceIP, event.Method, event.Path, event.RequestSummary,
			event.UserAgent, event.JA3, event.JA4, event.Verdict, event.Category,
			event.PayloadClass, marshalRuleIDs(event.RuleIDs), event.Score,
			event.InspectionTime, event.Action, event.Phase, event.ResponseType, event.ResponsePreview, event.TarpitDuration, event.BytesServed)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) Recent(ctx context.Context, limit int) ([]Event, error) {
	if limit < 1 {
		return []Event{}, nil
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.pool.Query(ctx, `
SELECT timestamp, source_ip, method, path, request_summary, user_agent, ja3, ja4, verdict,
       category, payload_class, rule_ids, score, inspection_time_us, action, phase,
       response_type, response_preview, tarpit_duration_ms, bytes_served
FROM telemetry_events
WHERE LOWER(phase) <> 'started'
ORDER BY timestamp DESC, id DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]Event, 0, limit)
	for rows.Next() {
		var event Event
		var ruleIDs []byte
		if err := rows.Scan(
			&event.Timestamp, &event.SourceIP, &event.Method, &event.Path, &event.RequestSummary,
			&event.UserAgent, &event.JA3, &event.JA4, &event.Verdict, &event.Category,
			&event.PayloadClass, &ruleIDs, &event.Score, &event.InspectionTime,
			&event.Action, &event.Phase, &event.ResponseType, &event.ResponsePreview,
			&event.TarpitDuration, &event.BytesServed,
		); err != nil {
			return nil, err
		}
		if len(ruleIDs) > 0 {
			if err := json.Unmarshal(ruleIDs, &event.RuleIDs); err != nil {
				return nil, fmt.Errorf("decode persisted rule IDs: %w", err)
			}
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
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
