package deceive

import (
	"net"
	"net/http"
)

// SandboxDeceiver is the concrete Deceiver implementation.
// It dispatches to category-specific handlers and writes a fake response
// that matches the real backend's header profile (Content-Type, X-Backend-Server).
type SandboxDeceiver struct {
	sqli      *sqliHandler
	xss       *xssHandler
	traversal *traversalHandler
	rce       *rceHandler
}

// NewSandboxDeceiver constructs a ready-to-use SandboxDeceiver.
func NewSandboxDeceiver() *SandboxDeceiver {
	return &SandboxDeceiver{
		sqli:      &sqliHandler{},
		xss:       &xssHandler{},
		traversal: &traversalHandler{},
		rce:       &rceHandler{},
	}
}

// Handle dispatches the flagged request to the appropriate fake-response handler.
// It satisfies the Deceiver interface.
func (d *SandboxDeceiver) Handle(w http.ResponseWriter, r *http.Request, category Category) error {
	sessionIP := extractIP(r.RemoteAddr)

	switch category {
	case CategorySQLi:
		return d.sqli.handle(w, r, sessionIP)
	case CategoryXSS:
		return d.xss.handle(w, r)
	case CategoryPathTraversal:
		return d.traversal.handle(w, r, sessionIP)
	case CategoryRCE:
		return d.rce.handle(w, r, sessionIP)
	default:
		// Unknown category: return an innocuous empty-result response.
		backendHeaders(w)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"status":"success","message":"No results found","data":[]}`))
		return err
	}
}

// extractIP returns the host part of a remoteAddr "host:port" string.
func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
