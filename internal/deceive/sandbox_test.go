package deceive

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func makeRequest(rawURL string) *http.Request {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return &http.Request{
		Method:     "GET",
		URL:        u,
		RemoteAddr: "10.0.0.99:54321",
		Header:     make(http.Header),
	}
}

func makeRequestBody(rawURL, body, contentType string) *http.Request {
	r := makeRequest(rawURL)
	r.Method = "POST"
	r.Body = http.NoBody
	_ = body
	_ = contentType
	return r
}

// --------------------------------------------------------------------------
// SQLi — error-based
// --------------------------------------------------------------------------

func TestDeceiver_SQLi_ErrorBased(t *testing.T) {
	d := NewSandboxDeceiver()
	r := makeRequest(`http://localhost/search?q=' OR '1'='1' --`)
	w := httptest.NewRecorder()

	if err := d.Handle(w, r, CategorySQLi); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody: %s", err, w.Body.String())
	}
	// Should have an "error" key with a MySQL-style error message.
	errMsg, ok := resp["error"].(string)
	if !ok || errMsg == "" {
		t.Errorf("expected non-empty 'error' field, got %v", resp)
	}
	if !strings.Contains(errMsg, "syntax") {
		t.Errorf("expected syntax error message, got: %s", errMsg)
	}
}

// --------------------------------------------------------------------------
// SQLi — UNION SELECT
// --------------------------------------------------------------------------

func TestDeceiver_SQLi_UnionSelect(t *testing.T) {
	d := NewSandboxDeceiver()
	// 3-column UNION probe targeting users table.
	r := makeRequest(`http://localhost/search?q=1 UNION SELECT NULL,NULL,NULL FROM users--`)
	w := httptest.NewRecorder()

	if err := d.Handle(w, r, CategorySQLi); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody: %s", err, w.Body.String())
	}
	rows, ok := resp["data"].([]interface{})
	if !ok || len(rows) == 0 {
		t.Errorf("expected non-empty 'data' array, got %v", resp)
	}
	// Verify that each row has at most 3 keys (matching UNION column count).
	for i, rawRow := range rows {
		row, ok := rawRow.(map[string]interface{})
		if !ok {
			t.Errorf("row %d is not a JSON object", i)
			continue
		}
		if len(row) > 3 {
			t.Errorf("row %d has %d columns, expected ≤3", i, len(row))
		}
	}
}

// --------------------------------------------------------------------------
// SQLi — information_schema.tables
// --------------------------------------------------------------------------

func TestDeceiver_SQLi_InfoSchemaTables(t *testing.T) {
	d := NewSandboxDeceiver()
	r := makeRequest(`http://localhost/search?q=' UNION SELECT table_name FROM information_schema.tables--`)
	w := httptest.NewRecorder()

	if err := d.Handle(w, r, CategorySQLi); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("not valid JSON: %v\nbody: %s", err, w.Body.String())
	}
	data, ok := resp["data"].([]interface{})
	if !ok || len(data) == 0 {
		t.Fatalf("expected non-empty data array, got %v", resp)
	}
	// Verify well-known table names are present.
	tableNames := make(map[string]bool)
	for _, rawRow := range data {
		row, ok := rawRow.(map[string]interface{})
		if !ok {
			continue
		}
		if name, ok := row["TABLE_NAME"].(string); ok {
			tableNames[name] = true
		}
	}
	for _, expected := range []string{"users", "orders", "products"} {
		if !tableNames[expected] {
			t.Errorf("expected fake table %q in info_schema response, got: %v", expected, tableNames)
		}
	}
}

// --------------------------------------------------------------------------
// SQLi — information_schema.columns
// --------------------------------------------------------------------------

func TestDeceiver_SQLi_InfoSchemaColumns(t *testing.T) {
	d := NewSandboxDeceiver()
	r := makeRequest(`http://localhost/search?q=' UNION SELECT column_name FROM information_schema.columns WHERE TABLE_NAME='users'--`)
	w := httptest.NewRecorder()

	if err := d.Handle(w, r, CategorySQLi); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("not valid JSON: %v\nbody: %s", err, w.Body.String())
	}
	data, ok := resp["data"].([]interface{})
	if !ok || len(data) == 0 {
		t.Fatalf("expected column data, got %v", resp)
	}
	// Verify "users" column names appear.
	colNames := make(map[string]bool)
	for _, rawRow := range data {
		row, ok := rawRow.(map[string]interface{})
		if !ok {
			continue
		}
		if col, ok := row["COLUMN_NAME"].(string); ok {
			colNames[col] = true
		}
	}
	for _, expected := range []string{"id", "username", "email", "password"} {
		if !colNames[expected] {
			t.Errorf("expected column %q in column list, got: %v", expected, colNames)
		}
	}
}

// --------------------------------------------------------------------------
// SQLi — session consistency (same IP + table → same first row)
// --------------------------------------------------------------------------

func TestDeceiver_SQLi_SessionConsistency(t *testing.T) {
	d := NewSandboxDeceiver()
	q := url.QueryEscape("1 UNION SELECT NULL,NULL,NULL FROM users--")
	rawURL := "http://localhost/search?q=" + q

	w1 := httptest.NewRecorder()
	r1 := makeRequest(rawURL)
	r1.RemoteAddr = "10.0.1.11:11111"
	_ = d.Handle(w1, r1, CategorySQLi)

	w2 := httptest.NewRecorder()
	r2 := makeRequest(rawURL)
	r2.RemoteAddr = "10.0.1.11:22222" // same IP, different port
	_ = d.Handle(w2, r2, CategorySQLi)

	// Both calls from same IP must return the same first row.
	if w1.Body.String() != w2.Body.String() {
		t.Errorf("same-IP queries returned different rows\nfirst:  %s\nsecond: %s",
			w1.Body.String(), w2.Body.String())
	}
}

// --------------------------------------------------------------------------
// SQLi — PostgreSQL engine detection
// --------------------------------------------------------------------------

func TestDeceiver_SQLi_PostgresEngine(t *testing.T) {
	d := NewSandboxDeceiver()
	r := makeRequest(`http://localhost/search?q=' AND pg_sleep(5)--`)
	w := httptest.NewRecorder()

	if err := d.Handle(w, r, CategorySQLi); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	body := w.Body.String()
	if !strings.Contains(body, "PostgreSQL") && !strings.Contains(body, "syntax error") {
		t.Errorf("expected postgres-style response, got: %s", body)
	}
}

// --------------------------------------------------------------------------
// XSS — payload is entity-encoded, not raw
// --------------------------------------------------------------------------

func TestDeceiver_XSS_PayloadEncoded(t *testing.T) {
	d := NewSandboxDeceiver()
	r := makeRequest(`http://localhost/search?q=<script>alert(1)</script>`)
	w := httptest.NewRecorder()

	if err := d.Handle(w, r, CategoryXSS); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	body := w.Body.String()
	// The raw <script> tag must NOT appear in the response body.
	if strings.Contains(body, "<script>") {
		t.Errorf("response contains raw <script> tag — payload is not entity-encoded")
	}
	// The entity-encoded form MUST appear (reflects the probe).
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("expected entity-encoded payload in response, got: %s", body)
	}
}

func TestDeceiver_XSS_ResponseIs200HTML(t *testing.T) {
	d := NewSandboxDeceiver()
	r := makeRequest(`http://localhost/search?q=<img src=x onerror=alert(1)>`)
	w := httptest.NewRecorder()

	_ = d.Handle(w, r, CategoryXSS)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("expected text/html Content-Type, got %q", ct)
	}
}

// --------------------------------------------------------------------------
// Path Traversal — /etc/passwd
// --------------------------------------------------------------------------

func TestDeceiver_PathTraversal_Passwd(t *testing.T) {
	d := NewSandboxDeceiver()
	r := makeRequest(`http://localhost/read?file=../../../../etc/passwd`)
	w := httptest.NewRecorder()

	if err := d.Handle(w, r, CategoryPathTraversal); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	body := w.Body.String()
	// Must contain typical /etc/passwd structure.
	if !strings.Contains(body, "root:x:0:0") {
		t.Errorf("expected fake passwd root entry, got: %s", body)
	}
	if !strings.Contains(body, "www-data") {
		t.Errorf("expected www-data entry in fake passwd, got: %s", body)
	}
	// Must NOT contain real system usernames (we check for a few unlikely ones).
	for _, realUser := range []string{"anurag", "ubuntu"} {
		if strings.Contains(body, realUser+":") {
			t.Errorf("fake passwd must not contain real username %q", realUser)
		}
	}
}

func TestDeceiver_PathTraversal_Shadow_Denied(t *testing.T) {
	d := NewSandboxDeceiver()
	r := makeRequest(`http://localhost/read?file=../../../../etc/shadow`)
	w := httptest.NewRecorder()
	_ = d.Handle(w, r, CategoryPathTraversal)

	if !strings.Contains(w.Body.String(), "Permission denied") {
		t.Errorf("expected permission denied for /etc/shadow, got: %s", w.Body.String())
	}
}

func TestDeceiver_PathTraversal_EnvFile(t *testing.T) {
	d := NewSandboxDeceiver()
	r := makeRequest(`http://localhost/read?file=../../../../var/www/html/.env`)
	w := httptest.NewRecorder()
	_ = d.Handle(w, r, CategoryPathTraversal)

	body := w.Body.String()
	if !strings.Contains(body, "DB_PASSWORD") {
		t.Errorf("expected fake .env with DB_PASSWORD, got: %s", body)
	}
}

// --------------------------------------------------------------------------
// RCE — command output
// --------------------------------------------------------------------------

func TestDeceiver_RCE_ID(t *testing.T) {
	d := NewSandboxDeceiver()
	r := makeRequest(`http://localhost/ping?host=127.0.0.1; id`)
	w := httptest.NewRecorder()

	if err := d.Handle(w, r, CategoryRCE); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("not valid JSON: %v\nbody: %s", err, w.Body.String())
	}
	output, _ := resp["output"].(string)
	if !strings.Contains(output, "www-data") {
		t.Errorf("expected www-data in id output, got: %q", output)
	}
}

func TestDeceiver_RCE_Whoami(t *testing.T) {
	d := NewSandboxDeceiver()
	r := makeRequest("http://localhost/ping?host=127.0.0.1%3B+whoami")
	w := httptest.NewRecorder()
	_ = d.Handle(w, r, CategoryRCE)

	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	output, _ := resp["output"].(string)
	if output != "www-data" {
		t.Errorf("expected 'www-data', got %q", output)
	}
}

func TestDeceiver_RCE_UnknownCommand(t *testing.T) {
	d := NewSandboxDeceiver()
	r := makeRequest("http://localhost/ping?host=127.0.0.1%3B+xyzzy")
	w := httptest.NewRecorder()
	_ = d.Handle(w, r, CategoryRCE)

	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	output, _ := resp["output"].(string)
	if !strings.Contains(output, "not found") {
		t.Errorf("expected 'not found' for unknown command, got %q", output)
	}
}

// --------------------------------------------------------------------------
// Unknown category — fallback
// --------------------------------------------------------------------------

func TestDeceiver_Unknown_FallbackOK(t *testing.T) {
	d := NewSandboxDeceiver()
	r := makeRequest("http://localhost/search?q=test")
	w := httptest.NewRecorder()

	if err := d.Handle(w, r, CategoryUnknown); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// --------------------------------------------------------------------------
// Backend header parity — no honeypot fingerprints
// --------------------------------------------------------------------------

func TestDeceiver_HeaderParity(t *testing.T) {
	d := NewSandboxDeceiver()
	categories := []Category{CategorySQLi, CategoryXSS, CategoryPathTraversal, CategoryRCE, CategoryUnknown}
	queries := []string{
		`?q=' OR '1'='1'--`,
		`?q=<script>alert(1)</script>`,
		`?q=../../../../etc/passwd`,
		`?host=127.0.0.1; id`,
		`?q=normal`,
	}

	for i, cat := range categories {
		r := makeRequest("http://localhost/search" + queries[i])
		w := httptest.NewRecorder()
		_ = d.Handle(w, r, cat)

		if got := w.Header().Get("X-Backend-Server"); got != "mirage-demo-backend" {
			t.Errorf("[%s] expected X-Backend-Server=mirage-demo-backend, got %q", cat, got)
		}
		// Must NOT reveal honeypot identity.
		for _, hdr := range []string{"X-Honeypot", "X-Mirage-Internal", "X-Deception"} {
			if v := w.Header().Get(hdr); v != "" {
				t.Errorf("[%s] response must not contain header %q", cat, hdr)
			}
		}
	}
}

// --------------------------------------------------------------------------
// Concurrency / race detector
// --------------------------------------------------------------------------

func TestDeceiver_ConcurrentRace(t *testing.T) {
	d := NewSandboxDeceiver()
	const goroutines = 50
	done := make(chan struct{}, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			r := makeRequest(`http://localhost/search?q=' UNION SELECT NULL,NULL FROM users--`)
			r.RemoteAddr = "10.99.0.1:10000"
			w := httptest.NewRecorder()
			_ = d.Handle(w, r, CategorySQLi)
		}(i)
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// --------------------------------------------------------------------------
// Backend never contacted when Deceiver is active — verified externally
// in proxy_test.go; here we just ensure Handle never panics.
// --------------------------------------------------------------------------

func TestDeceiver_NoPanic_AllCategories(t *testing.T) {
	d := NewSandboxDeceiver()
	cases := []struct {
		cat Category
		url string
	}{
		{CategorySQLi, "http://localhost/search?q=' OR 1=1--"},
		{CategoryXSS, "http://localhost/search?q=<script>x</script>"},
		{CategoryPathTraversal, "http://localhost/read?file=../../etc/passwd"},
		{CategoryRCE, "http://localhost/ping?host=x; cat /etc/passwd"},
		{CategoryUnknown, "http://localhost/search?q=hello"},
	}
	for _, tc := range cases {
		t.Run(string(tc.cat), func(t *testing.T) {
			r := makeRequest(tc.url)
			w := httptest.NewRecorder()
			if err := d.Handle(w, r, tc.cat); err != nil {
				t.Errorf("Handle(%s) returned unexpected error: %v", tc.cat, err)
			}
		})
	}
}
