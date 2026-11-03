package telemetry

import (
	"context"
	"sync"
	"testing"
	"time"
)

type blockingSink struct {
	mu     sync.Mutex
	events []Event
}

func (s *blockingSink) Write(context.Context, Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, Event{})
	return nil
}

func TestPublisherDropsWhenQueueIsFull(t *testing.T) {
	publisher := NewPublisher(context.Background(), 1, &blockingSink{})
	defer publisher.Close()

	// The worker may consume the first event, so fill the queue until a drop is
	// observed rather than relying on a scheduler-specific ordering.
	for i := 0; i < 1000 && publisher.Dropped() == 0; i++ {
		publisher.Publish(Event{Path: "/search"})
	}
	if publisher.Dropped() == 0 {
		t.Fatal("publisher never recorded a dropped event")
	}
}

func TestPublisherDeliversQueuedEvents(t *testing.T) {
	sink := &blockingSink{}
	publisher := NewPublisher(context.Background(), 4, sink)
	publisher.Publish(Event{Path: "/search", Verdict: "Malicious"})
	publisher.Close()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		sink.mu.Lock()
		count := len(sink.events)
		sink.mu.Unlock()
		if count == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("queued event was not delivered")
}
