package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type Consumer struct {
	redis  *redis.Client
	store  EventStore
	hub    *Hub
	stream string
	group  string
	name   string
	batch  int
}

func NewConsumer(client *redis.Client, store EventStore, hub *Hub, stream, group, name string, batch int) (*Consumer, error) {
	if client == nil || store == nil || hub == nil {
		return nil, fmt.Errorf("redis, store, and hub are required")
	}
	if stream == "" || group == "" || name == "" {
		return nil, fmt.Errorf("stream, group, and consumer names are required")
	}
	if batch < 1 {
		batch = 100
	}
	return &Consumer{redis: client, store: store, hub: hub, stream: stream, group: group, name: name, batch: batch}, nil
}

func (c *Consumer) Run(ctx context.Context) error {
	backoff := 500 * time.Millisecond
	for {
		if err := c.ensureGroup(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if err := waitForRetry(ctx, backoff); err != nil {
				return nil
			}
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}
		streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group: c.group, Consumer: c.name, Streams: []string{c.stream, ">"}, Count: int64(c.batch), Block: time.Second,
		}).Result()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if err == redis.Nil {
				continue
			}
			if err := waitForRetry(ctx, backoff); err != nil {
				return nil
			}
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 500 * time.Millisecond
		for _, stream := range streams {
			if err := c.process(ctx, stream.Messages); err != nil {
				return err
			}
		}
	}
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Consumer) ensureGroup(ctx context.Context) error {
	err := c.redis.XGroupCreateMkStream(ctx, c.stream, c.group, "0").Err()
	if err != nil && !containsBusyGroup(err.Error()) {
		return err
	}
	return nil
}

func (c *Consumer) process(ctx context.Context, messages []redis.XMessage) error {
	events := make([]Event, 0, len(messages))
	ids := make([]string, 0, len(messages))
	for _, message := range messages {
		encoded, ok := message.Values["event"].(string)
		if !ok {
			return fmt.Errorf("stream message %s has no event field", message.ID)
		}
		var event Event
		if err := json.Unmarshal([]byte(encoded), &event); err != nil {
			return fmt.Errorf("decode stream message %s: %w", message.ID, err)
		}
		events = append(events, event)
		ids = append(ids, message.ID)
	}
	if err := c.store.InsertBatch(ctx, events); err != nil {
		return err
	}
	for _, event := range events {
		c.hub.Broadcast(event)
	}
	return c.redis.XAck(ctx, c.stream, c.group, ids...).Err()
}

func containsBusyGroup(message string) bool {
	return strings.HasPrefix(message, "BUSYGROUP")
}
