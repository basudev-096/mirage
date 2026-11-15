package deception

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnalyzeRequestExtractsSelectTarget(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet,
		"/search?q="+urlQueryEscape("UNION SELECT username, password FROM users --"),
		nil)

	result := New().AnalyzeRequest(req, nil)
	if !result.Recognized {
		t.Fatal("expected SQL payload to be recognized")
	}
	if result.Target.Operation != "SELECT" {
		t.Fatalf("operation = %q, want SELECT", result.Target.Operation)
	}
	if result.Target.Table != "users" {
		t.Fatalf("table = %q, want users", result.Target.Table)
	}
	if !contains(result.Target.Columns, "username") || !contains(result.Target.Columns, "password") {
		t.Fatalf("columns = %v, want username and password", result.Target.Columns)
	}
	if result.ResponseType != "synthetic_database_result" {
		t.Fatalf("response type = %q, want synthetic_database_result", result.ResponseType)
	}
	if !strings.Contains(string(result.Body), `"target_table":"users"`) {
		t.Fatalf("response does not identify target table: %s", result.Body)
	}
}

func TestAnalyzeRequestFallsBackForBooleanInjection(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet,
		"/login?q="+urlQueryEscape("' OR '1'='1' --"),
		nil)

	result := New().AnalyzeRequest(req, nil)
	if !result.Recognized {
		t.Fatal("expected boolean SQL injection to use deception fallback")
	}
	if result.PayloadClass != "sql_injection_fallback" {
		t.Fatalf("payload class = %q, want sql_injection_fallback", result.PayloadClass)
	}
	if result.Target.Operation != "SELECT" {
		t.Fatalf("operation = %q, want SELECT", result.Target.Operation)
	}
}

func urlQueryEscape(value string) string {
	return strings.NewReplacer(" ", "%20", "'", "%27", ",", "%2C").Replace(value)
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}
