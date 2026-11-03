package telemetry

import (
	"context"
	"sync"
	"sync/atomic"
)

// Sink receives events outside the proxy request path. Implementations may
// write to Redis, a test buffer, or another durable transport.
type Sink interface {
	Write(context.Context, Event) error
}

// Publisher is safe for concurrent use. Publish never waits for the sink.
type Publisher struct {
	queue    chan Event
	sink     Sink
	cancel   context.CancelFunc
	done     chan struct{}
	closeMu  sync.Once
	accepted atomic.Uint64
	dropped  atomic.Uint64
}

// NewPublisher starts one delivery worker with a bounded queue.
func NewPublisher(parent context.Context, queueSize int, sink Sink) *Publisher {
	if queueSize < 1 {
		queueSize = 1
	}
	ctx, cancel := context.WithCancel(parent)
	p := &Publisher{
		queue:  make(chan Event, queueSize),
		sink:   sink,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go p.run(ctx)
	return p
}

// Publish queues an event or drops it immediately when the bounded queue is full.
func (p *Publisher) Publish(event Event) bool {
	select {
	case p.queue <- event:
		p.accepted.Add(1)
		return true
	default:
		p.dropped.Add(1)
		return false
	}
}

// Accepted returns the number of events accepted by the queue.
func (p *Publisher) Accepted() uint64 { return p.accepted.Load() }

// Dropped returns the number of events discarded because the queue was full.
func (p *Publisher) Dropped() uint64 { return p.dropped.Load() }

// Close stops the worker after attempting to deliver events already queued.
func (p *Publisher) Close() {
	p.closeMu.Do(func() {
		p.cancel()
		<-p.done
	})
}

func (p *Publisher) run(ctx context.Context) {
	defer close(p.done)
	for {
		select {
		case event := <-p.queue:
			if p.sink != nil {
				_ = p.sink.Write(ctx, event)
			}
		case <-ctx.Done():
			for {
				select {
				case event := <-p.queue:
					if p.sink != nil {
						_ = p.sink.Write(context.Background(), event)
					}
				default:
					return
				}
			}
		}
	}
}
