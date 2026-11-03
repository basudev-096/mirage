package telemetry

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

type Hub struct {
	mu       sync.RWMutex
	clients  map[*hubClient]struct{}
	upgrader websocket.Upgrader
}

type hubClient struct {
	conn *websocket.Conn
	send chan []byte
}

func NewHub() *Hub {
	return &Hub{
		clients: make(map[*hubClient]struct{}),
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
