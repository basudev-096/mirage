package telemetry

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// streamWriter is the small Redis surface needed by RedisSink. Keeping it
// narrow makes serialization testable without running Redis in unit tests.
type streamWriter interface {
	XAdd(context.Context, *redis.XAddArgs) *redis.StringCmd
}

// RedisSink writes one serialized event to a Redis Stream.
type RedisSink struct {
	client streamWriter
	stream string
	maxLen int64
}

// NewRedisSink creates a Redis Streams sink. maxLen <= 0 disables approximate
// trimming and leaves retention to the Redis deployment policy.
func NewRedisSink(client *redis.Client, stream string, maxLen int64) (*RedisSink, error) {
	if client == nil {
		return nil, fmt.Errorf("redis client is required")
	}
	if stream == "" {
		return nil, fmt.Errorf("redis stream name is required")
	}
	return &RedisSink{client: client, stream: stream, maxLen: maxLen}, nil
}

func (s *RedisSink) Write(ctx context.Context, event Event) error {
	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal telemetry event: %w", err)
	}
	args := &redis.XAddArgs{
		Stream: s.stream,
		Values: map[string]any{"event": string(encoded)},
	}
	if s.maxLen > 0 {
		args.MaxLen = s.maxLen
		args.Approx = true
	}
	return s.client.XAdd(ctx, args).Err()
}
