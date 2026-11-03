package fingerprint

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriterSanitizesRuntimeHeaders(t *testing.T) {
	recorder := httptest.NewRecorder()
	recorder.Header().Set("Server", "Go-http-server")
	recorder.Header().Set("X-Powered-By", "Express")
	recorder.Header().Set("X-Backend-Server", "mirage-demo-backend")

	writer := NewWriter(recorder)
	writer.WriteHeader(http.StatusOK)

	if got := recorder.Header().Get("Server"); got != "" {
		t.Fatalf("Server header = %q, want it removed", got)
	}
	if got := recorder.Header().Get("X-Powered-By"); got != "" {
		t.Fatalf("X-Powered-By header = %q, want it removed", got)
	}
	if got := recorder.Header().Get("X-Backend-Server"); got != "mirage-demo-backend" {
		t.Fatalf("application header = %q, want it preserved", got)
	}
}

func TestWriterForwardsFlush(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := NewWriter(recorder)

	writer.Flush()

	if !recorder.Flushed {
		t.Fatal("Flush was not forwarded")
	}
}
