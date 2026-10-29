package deceive

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"
)

// SQL fragment extraction patterns.
// These are intentionally lenient: injection payloads are often syntactically
// broken, so regex extraction is more robust than a full parser for our use case.
var (
	reFromTable   = regexp.MustCompile(`(?i)(?:from|join|into|update)\s+` + "`?" + `([a-z_][a-z0-9_]*)` + "`?")
	reUnionSelect = regexp.MustCompile(`(?i)union\s+(?:all\s+)?select`)
	reInfoSchema  = regexp.MustCompile(`(?i)information_schema`)
	reInfoTables  = regexp.MustCompile(`(?i)tables`)
	reInfoColumns = regexp.MustCompile(`(?i)columns`)
	reTargetTable = regexp.MustCompile(`(?i)TABLE_NAME\s*=\s*'([^']+)'`)

	// DB engine fingerprinting hints present in common sqlmap payloads.
	reMySQLHint    = regexp.MustCompile(`(?i)(@@version|@@datadir|information_schema|user\(\)|database\(\)|concat\()`)
	rePostgresHint = regexp.MustCompile(`(?i)(pg_sleep|pg_catalog|version\(\)|current_database|pg_user)`)
	reSQLiteHint   = regexp.MustCompile(`(?i)(sqlite_master|sqlite_sequence|tbl_name)`)
)

type dbEngine int

const (
	engineMySQL    dbEngine = iota
	enginePostgres dbEngine = iota
	engineSQLite   dbEngine = iota
)

// sqliHandler handles all SQL injection deception variants.
type sqliHandler struct{}

// handle is the top-level dispatcher: routes to info_schema, union, or error-based handler.
func (h *sqliHandler) handle(w http.ResponseWriter, r *http.Request, sessionIP string) error {
	fragment := extractSQLFragment(r)
	engine := detectEngine(fragment)

	switch {
	case reInfoSchema.MatchString(fragment):
		return h.handleInfoSchema(w, fragment, sessionIP, engine)
	case reUnionSelect.MatchString(fragment):
		return h.handleUnion(w, fragment, sessionIP, engine)
	default:
		return h.handleErrorBased(w, fragment, engine)
	}
}

// --------------------------------------------------------------------------
// Error-based injection response
// --------------------------------------------------------------------------

func (h *sqliHandler) handleErrorBased(w http.ResponseWriter, fragment string, engine dbEngine) error {
	snip := truncate(fragment, 80)
	var errMsg string
	switch engine {
	case enginePostgres:
		errMsg = fmt.Sprintf(
			"ERROR:  syntax error at or near \"OR\"\nLINE 1: SELECT * FROM users WHERE id=%s\n        ^", snip)
	case engineSQLite:
		errMsg = fmt.Sprintf("near \"%s\": syntax error", snip)
	default: // MySQL
		errMsg = fmt.Sprintf(
			"You have an error in your SQL syntax; check the manual that corresponds to your "+
				"MySQL server version for the right syntax to use near '%s' at line 1", snip)
	}

	backendHeaders(w)
	w.WriteHeader(http.StatusOK)
	return jsonEncode(w, map[string]interface{}{
		"status": "error",
		"error":  errMsg,
		"query":  html.EscapeString(fragment),
	})
}

// --------------------------------------------------------------------------
// UNION SELECT response — returns fake rows matching column count
// --------------------------------------------------------------------------

func (h *sqliHandler) handleUnion(w http.ResponseWriter, fragment, sessionIP string, engine dbEngine) error {
	tableName := extractTable(fragment)
	_, cols := resolveTable(tableName)

	numCols := countUnionColumns(fragment)
	if numCols < 1 {
		numCols = 1
	}
	if numCols > len(cols) {
		numCols = len(cols)
	}
	selectedCols := cols[:numCols]

	rows := generateRows(sessionIP, tableName, selectedCols, 3)

	backendHeaders(w)
	w.WriteHeader(http.StatusOK)
	return jsonEncode(w, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Found %d results", len(rows)),
		"data":    rows,
	})
}

// --------------------------------------------------------------------------
// information_schema probe responses
// --------------------------------------------------------------------------

func (h *sqliHandler) handleInfoSchema(w http.ResponseWriter, fragment, sessionIP string, engine dbEngine) error {
	switch {
	case reInfoColumns.MatchString(fragment):
		return h.handleInfoSchemaColumns(w, fragment)
	case reInfoTables.MatchString(fragment):
		return h.handleInfoSchemaTables(w)
	default:
		return h.handleVersionProbe(w, engine)
	}
}

func (h *sqliHandler) handleInfoSchemaTables(w http.ResponseWriter) error {
	tables := allTableNames()
	rows := make([]map[string]string, len(tables))
	for i, t := range tables {
		rows[i] = map[string]string{
			"TABLE_CATALOG": "def",
			"TABLE_SCHEMA":  "app_db",
			"TABLE_NAME":    t,
			"TABLE_TYPE":    "BASE TABLE",
			"ENGINE":        "InnoDB",
			"ROW_FORMAT":    "Dynamic",
		}
	}
	backendHeaders(w)
	w.WriteHeader(http.StatusOK)
	return jsonEncode(w, map[string]interface{}{
		"status": "success",
		"data":   rows,
	})
}

func (h *sqliHandler) handleInfoSchemaColumns(w http.ResponseWriter, fragment string) error {
	tableName := "users"
	if m := reTargetTable.FindStringSubmatch(fragment); len(m) > 1 {
		tableName = strings.ToLower(m[1])
	}
	_, cols := resolveTable(tableName)

	rows := make([]map[string]string, len(cols))
	for i, col := range cols {
		rows[i] = map[string]string{
			"TABLE_SCHEMA":    "app_db",
			"TABLE_NAME":      tableName,
			"COLUMN_NAME":     col.Name,
			"ORDINAL_POSITION": fmt.Sprintf("%d", i+1),
			"COLUMN_TYPE":     col.SQLType,
			"IS_NULLABLE":     "YES",
			"COLUMN_KEY":      func() string {
				if i == 0 { return "PRI" }
				return ""
			}(),
		}
	}
	backendHeaders(w)
	w.WriteHeader(http.StatusOK)
	return jsonEncode(w, map[string]interface{}{
		"status": "success",
		"data":   rows,
	})
}

func (h *sqliHandler) handleVersionProbe(w http.ResponseWriter, engine dbEngine) error {
	var version string
	switch engine {
	case enginePostgres:
		version = "PostgreSQL 14.5 on x86_64-pc-linux-gnu, compiled by gcc 11.4.0, 64-bit"
	case engineSQLite:
		version = "3.39.2"
	default:
		version = "8.0.31-MySQL Community Server - GPL"
	}
	backendHeaders(w)
	w.WriteHeader(http.StatusOK)
	return jsonEncode(w, map[string]interface{}{
		"status": "success",
		"data":   []map[string]string{{"version()": version}},
	})
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// extractSQLFragment scans URL query parameters and returns the first value
// that looks like an SQL injection fragment.
func extractSQLFragment(r *http.Request) string {
	sqlKeywords := []string{
		"select", "union", "insert", "update", "delete", "drop",
		"exec", "declare", "or '", "and '", "1=1", "'='", "--", "/*",
	}
	for _, vals := range r.URL.Query() {
		for _, v := range vals {
			vl := strings.ToLower(v)
			for _, kw := range sqlKeywords {
				if strings.Contains(vl, kw) {
					return v
				}
			}
		}
	}
	return r.URL.RawQuery
}

// detectEngine guesses the target DB engine from SQL patterns.
func detectEngine(fragment string) dbEngine {
	switch {
	case rePostgresHint.MatchString(fragment):
		return enginePostgres
	case reSQLiteHint.MatchString(fragment):
		return engineSQLite
	default:
		return engineMySQL
	}
}

// extractTable returns the first table name referenced in the SQL fragment.
func extractTable(fragment string) string {
	skipWords := map[string]bool{
		"select": true, "where": true, "null": true,
		"and": true, "or": true, "not": true, "set": true,
	}
	matches := reFromTable.FindAllStringSubmatch(fragment, -1)
	for _, m := range matches {
		if len(m) > 1 {
			tbl := strings.ToLower(strings.Trim(m[1], "`"))
			if !skipWords[tbl] {
				return tbl
			}
		}
	}
	return "users"
}

// countUnionColumns counts the number of columns in a UNION SELECT
// by counting comma-separated NULL (or other) placeholders after SELECT.
func countUnionColumns(fragment string) int {
	upper := strings.ToUpper(fragment)
	uIdx := strings.Index(upper, "UNION")
	if uIdx < 0 {
		return 3
	}
	after := upper[uIdx:]
	sIdx := strings.Index(after, "SELECT")
	if sIdx < 0 {
		return 3
	}
	colPart := after[sIdx+6:]
	// Trim from WHERE / -- / LIMIT onwards
	for _, stop := range []string{"WHERE", " FROM ", "--", "/*", "LIMIT"} {
		if i := strings.Index(colPart, stop); i >= 0 {
			colPart = colPart[:i]
		}
	}
	return strings.Count(colPart, ",") + 1
}

// backendHeaders writes headers that match the real backend's response profile.
func backendHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Backend-Server", "mirage-demo-backend")
}

// jsonEncode writes v as JSON to w.
func jsonEncode(w http.ResponseWriter, v interface{}) error {
	return json.NewEncoder(w).Encode(v)
}

// truncate shortens s to at most n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
