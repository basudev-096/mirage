package telemetry

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

type Hub struct {
	mu       sync.RWMutex
	clients  map[*hubClient]struct{}
	history  EventHistory
	upgrader websocket.Upgrader
}

type hubClient struct {
	conn *websocket.Conn
	send chan []byte
}

func NewHub(history EventHistory) *Hub {
	return &Hub{
		clients: make(map[*hubClient]struct{}),
		history: history,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 4096,
			CheckOrigin:     func(*http.Request) bool { return true },
		},
	}
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	client := &hubClient{conn: conn, send: make(chan []byte, 32)}
	h.mu.Lock()
	h.clients[client] = struct{}{}
	h.mu.Unlock()
	go h.writeLoop(client)
	if h.history != nil {
		events, err := h.history.Recent(r.Context(), 100)
		if err != nil {
			log.Printf("load telemetry history for WebSocket client: %v", err)
		} else {
			for index := len(events) - 1; index >= 0; index-- {
				payload, marshalErr := json.Marshal(events[index])
				if marshalErr != nil {
					log.Printf("encode telemetry history for WebSocket client: %v", marshalErr)
					continue
				}
				select {
				case client.send <- payload:
				default:
					log.Printf("drop telemetry history for slow WebSocket client")
					break
				}
			}
		}
	}
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			h.remove(client)
			return
		}
	}
}

func (h *Hub) Broadcast(event Event) {
	payload, err := json.Marshal(event)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for client := range h.clients {
		select {
		case client.send <- payload:
		default:
			delete(h.clients, client)
			close(client.send)
			_ = client.conn.Close()
		}
	}
}

func (h *Hub) writeLoop(client *hubClient) {
	for payload := range client.send {
		if err := client.conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			h.remove(client)
			return
		}
	}
}

func (h *Hub) remove(client *hubClient) {
	h.mu.Lock()
	if _, ok := h.clients[client]; ok {
		delete(h.clients, client)
		close(client.send)
		_ = client.conn.Close()
	}
	h.mu.Unlock()
}
