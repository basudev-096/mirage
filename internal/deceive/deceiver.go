// Package deceive implements the deception sandbox that synthesises plausible
// fake HTTP responses for flagged malicious requests. The real backend is never
// contacted; all data is generated synthetically. The TLS session is preserved —
// the routing decision is a pure in-process branch in the proxy hot path.
package deceive

import "net/http"

// Category is the attack class determined by the detection layer.
// It mirrors detect.Verdict.Category and drives handler dispatch.
type Category string

const (
	CategorySQLi          Category = "SQLi"
	CategoryXSS           Category = "XSS"
	CategoryPathTraversal Category = "PathTraversal"
	CategoryRCE           Category = "RCE"
	CategoryUnknown       Category = "Unknown"
)

// Deceiver generates and writes a fake HTTP response for a malicious request.
// Implementations must:
//   - Never contact the real backend.
//   - Never include real system data (files, env vars, users).
//   - Preserve response header parity with the legitimate backend.
//   - Return the first non-nil write error, or nil on success.
type Deceiver interface {
	Handle(w http.ResponseWriter, r *http.Request, category Category) error
}
