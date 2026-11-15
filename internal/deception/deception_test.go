package deception

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
)

func TestAnalyzeRequestExtractsSelectTarget(t *testing.T) {
	result := analyze(t, New(), "", "users", "username,password")
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
	if strings.Contains(string(result.Body), "target_table") || strings.Contains(string(result.Body), "mirage-sql-honeypot") {
		t.Fatalf("response exposed internal deception metadata: %s", result.Body)
	}
	if !strings.Contains(result.ResponseMetadata, `"target_table":"users"`) {
		t.Fatalf("metadata does not identify target table: %s", result.ResponseMetadata)
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

func TestSyntheticDataIsStableForSessionAndTarget(t *testing.T) {
	first := analyze(t, NewWithSeed("test-secret"), "ses-1", "users", "username,email")
	second := analyze(t, NewWithSeed("test-secret"), "ses-1", "users", "username,email")
	if !reflect.DeepEqual(first.Body, second.Body) {
		t.Fatalf("same seed and target produced different responses:\n%s\n%s", first.Body, second.Body)
	}
}

func TestSyntheticDataChangesForSeedAndTable(t *testing.T) {
	base := analyze(t, NewWithSeed("test-secret"), "ses-1", "users", "username,email")
	otherSeed := analyze(t, NewWithSeed("other-secret"), "ses-1", "users", "username,email")
	otherTable := analyze(t, NewWithSeed("test-secret"), "ses-1", "accounts", "username,email")
	if reflect.DeepEqual(base.Body, otherSeed.Body) {
		t.Fatal("different seed produced identical synthetic response")
	}
	if reflect.DeepEqual(base.Body, otherTable.Body) {
		t.Fatal("different table produced identical synthetic response")
	}
}

func TestSyntheticIdentityIsConsistentAcrossColumnSelections(t *testing.T) {
	usernames := analyzeRows(t, analyze(t, NewWithSeed("test-secret"), "ses-1", "users", "username"))
	projection := analyzeRows(t, analyze(t, NewWithSeed("test-secret"), "ses-1", "users", "username,email"))
	for index, row := range usernames {
		if row["username"] != projection[index]["username"] {
			t.Fatalf("row %d username changed between projections", index)
		}
	}
}

func TestSyntheticColumnsAndUnknownValues(t *testing.T) {
	result := analyze(t, NewWithSeed("test-secret"), "ses-1", "users",
		"id,username,name,first_name,last_name,email,phone,password,token,address,city,country,company,age,created_at,status,role,custom_field")
	rows := analyzeRows(t, result)
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	if !regexp.MustCompile(`^[^@]+@example\.invalid$`).MatchString(rows[0]["email"].(string)) {
		t.Fatalf("email = %q, want reserved domain", rows[0]["email"])
	}
	if !regexp.MustCompile(`^\+1-202-555-\d{4}$`).MatchString(rows[0]["phone"].(string)) {
		t.Fatalf("phone = %q, want fictional 555 number", rows[0]["phone"])
	}
	if _, ok := rows[0]["age"].(float64); !ok {
		t.Fatalf("age has type %T, want JSON number", rows[0]["age"])
	}
	if rows[0]["custom_field"] == "" {
		t.Fatal("unknown column should receive a synthetic value")
	}
	if strings.Contains(string(result.Body), "target_table") || strings.Contains(string(result.Body), "records_generated") {
		t.Fatalf("response exposed internal metadata: %s", result.Body)
	}
}

func TestSyntheticGenerationIsConcurrentSafe(t *testing.T) {
	engine := NewWithSeed("test-secret")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := analyze(t, engine, "ses-1", "users", "username,email")
			if !result.Recognized {
				t.Error("concurrent request was not recognized")
			}
		}()
	}
	wg.Wait()
}

func analyze(t *testing.T, engine *Engine, session, table, columns string) Result {
	t.Helper()
	query := "UNION SELECT " + columns + " FROM " + table + " --"
	req := httptest.NewRequest(http.MethodGet, "/search?q="+urlQueryEscape(query), nil)
	req.Header.Set("X-Mirage-Session-ID", session)
	result := engine.AnalyzeRequest(req, nil)
	if !result.Recognized {
		t.Fatalf("payload was not recognized: %s", query)
	}
	return result
}

func analyzeRows(t *testing.T, result Result) []map[string]any {
	t.Helper()
	var response struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(result.Body, &response); err != nil {
		t.Fatalf("decode synthetic response: %v", err)
	}
	return response.Data
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
