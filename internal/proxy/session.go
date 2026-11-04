package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const sessionIdleWindow = 30 * time.Minute

type clientSession struct {
	id       string
	last     time.Time
	requests int
	diverted bool
}

// sessionTracker groups activity from the same source and user agent while
// keeping the original IP and user agent in the event for analyst review.
type sessionTracker struct {
	mu      sync.Mutex
	clients map[string]clientSession
	seen    uint64
}

func newSessionTracker() *sessionTracker {
	return &sessionTracker{clients: make(map[string]clientSession)}
}

func (t *sessionTracker) observe(clientKey string, now time.Time, flagged bool) (string, int, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	client, ok := t.clients[clientKey]
	if !ok || now.Sub(client.last) > sessionIdleWindow {
		if len(t.clients) >= 10000 {
			return newTraceID("ses"), 1, flagged
		}
		client = clientSession{id: newTraceID("ses"), last: now}
	}
	client.last = now
	client.requests++
	client.diverted = client.diverted || flagged
	t.clients[clientKey] = client
	if atomic.AddUint64(&t.seen, 1)%128 == 0 {
		for key, item := range t.clients {
			if now.Sub(item.last) > sessionIdleWindow {
				delete(t.clients, key)
			}
		}
	}
	return client.id, client.requests, client.diverted
}

var fallbackTraceCounter atomic.Uint64

func newTraceID(prefix string) string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err == nil {
		return prefix + "-" + hex.EncodeToString(value[:])
	}
	return fmt.Sprintf("%s-%x-%x", prefix, time.Now().UnixNano(), fallbackTraceCounter.Add(1))
}
