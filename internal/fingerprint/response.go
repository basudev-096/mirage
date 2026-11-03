// Package fingerprint contains response-shaping helpers shared by the clean
// and deceptive paths. It removes implementation details that would otherwise
// make the two routes easy to distinguish.
package fingerprint

import (
	"bufio"
	"net"
	"net/http"
)

var privateHeaders = [...]string{
	"Server",
	"X-Powered-By",
	"X-AspNet-Version",
	"X-AspNetMvc-Version",
}

// SanitizeHeaders removes framework and runtime identifiers from a response.
// It deliberately leaves application headers such as X-Backend-Server intact.
func SanitizeHeaders(header http.Header) {
	for _, name := range privateHeaders {
		header.Del(name)
	}
}

// Writer sanitizes response headers while forwarding optional net/http
// capabilities used by ReverseProxy and streaming handlers.
type Writer struct {
	http.ResponseWriter
	wroteHeader bool
}

// NewWriter wraps w with the shared response policy.
func NewWriter(w http.ResponseWriter) *Writer {
	return &Writer{ResponseWriter: w}
}

func (w *Writer) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	SanitizeHeaders(w.Header())
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *Writer) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *Writer) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *Writer) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

func (w *Writer) Push(target string, options *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, options)
}

func (w *Writer) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
