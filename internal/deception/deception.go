// Package deception analyzes SQL injection payloads and produces safe,
// deterministic database-shaped responses for the deception path.
package deception

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/xwb1989/sqlparser"
)

type Target struct {
	Database  string
	Schema    string
	Table     string
	Columns   []string
	Operation string
}

type Result struct {
	Recognized       bool
	Target           Target
	PayloadClass     string
	ResponseType     string
	ResponseMetadata string
	Body             []byte
}

type Engine struct {
	rows int
}

func New() *Engine {
	return &Engine{rows: 3}
}

func (e *Engine) AnalyzeRequest(r *http.Request, body []byte) Result {
	payload := extractPayload(r, body)
	if payload == "" {
		return Result{}
	}
	statement := statementCandidate(payload)
	if statement == "" {
		if looksLikeSQLInjection(payload) {
			return e.fallback(payload)
		}
		return Result{}
	}
	parsed, err := sqlparser.Parse(statement)
	if err != nil {
		if !looksLikeSQLInjection(payload) {
			return Result{}
		}
		return e.fallback(payload)
	}

	target := targetFromStatement(parsed)
	if target.Operation == "" {
		return Result{}
	}
	if target.Table == "" {
		target.Table = "virtual_records"
	}
	if len(target.Columns) == 0 {
		target.Columns = []string{"id", "status", "created_at"}
	}
	return e.result(target, "sql_ast_projection")
}

func (e *Engine) result(target Target, class string) Result {
	if target.Database == "" {
		target.Database = "mirage_honeypot"
	}
	if target.Schema == "" {
		target.Schema = "public"
	}
	if target.Operation == "" {
		target.Operation = "SELECT"
	}
	body := map[string]any{
		"status": "success",
		"data":   fakeRows(target.Columns, target.Table, e.rows),
		"deception": map[string]any{
			"engine":            "mirage-sql-honeypot",
			"target_database":   target.Database,
			"target_schema":     target.Schema,
			"target_table":      target.Table,
			"target_columns":    target.Columns,
			"operation":         target.Operation,
			"records_generated": e.rows,
		},
	}
	encoded, _ := json.Marshal(body)
	metadata, _ := json.Marshal(map[string]any{
		"target_database":   target.Database,
		"target_schema":     target.Schema,
		"target_table":      target.Table,
		"target_columns":    target.Columns,
		"operation":         target.Operation,
		"records_generated": e.rows,
	})
	return Result{
		Recognized:       true,
		Target:           target,
		PayloadClass:     class,
		ResponseType:     "synthetic_database_result",
		ResponseMetadata: string(metadata),
		Body:             encoded,
	}
}

func (e *Engine) fallback(payload string) Result {
	operation := "SELECT"
	if strings.Contains(strings.ToLower(payload), "drop ") {
		operation = "DROP"
	} else if strings.Contains(strings.ToLower(payload), "update ") {
		operation = "UPDATE"
	} else if strings.Contains(strings.ToLower(payload), "delete ") {
		operation = "DELETE"
	} else if strings.Contains(strings.ToLower(payload), "insert ") {
		operation = "INSERT"
	}
	return e.result(Target{
		Table:     inferTable(payload),
		Columns:   []string{"id", "status", "created_at"},
		Operation: operation,
	}, "sql_injection_fallback")
}

func targetFromStatement(statement sqlparser.Statement) Target {
	target := Target{}
	_ = sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
		switch item := node.(type) {
		case *sqlparser.Select:
			if target.Operation == "" {
				target.Operation = "SELECT"
			}
		case *sqlparser.Insert:
			target.Operation = "INSERT"
			target.Table = item.Table.Name.String()
			if !item.Table.Qualifier.IsEmpty() {
				target.Database = item.Table.Qualifier.String()
			}
			for _, column := range item.Columns {
				target.Columns = append(target.Columns, column.String())
			}
		case *sqlparser.Update:
			target.Operation = "UPDATE"
		case *sqlparser.Delete:
			target.Operation = "DELETE"
		case sqlparser.TableName:
			if target.Table == "" {
				target.Table = item.Name.String()
				target.Database = item.Qualifier.String()
			}
		case *sqlparser.ColName:
			name := item.Name.String()
			if name != "" && name != "*" {
				target.Columns = append(target.Columns, name)
			}
		}
		return true, nil
	}, statement)
	target.Columns = uniqueStrings(target.Columns)
	return target
}

func fakeRows(columns []string, table string, count int) []map[string]any {
	rows := make([]map[string]any, 0, count)
	for row := 1; row <= count; row++ {
		item := make(map[string]any, len(columns))
		for _, column := range columns {
			switch strings.ToLower(column) {
			case "id", "user_id", "account_id":
				item[column] = row
			case "username", "name":
				item[column] = fmt.Sprintf("guest_%s_%d", sanitizeIdentifier(table), row)
			case "email":
				item[column] = fmt.Sprintf("guest_%d@mirage.invalid", row)
			case "password", "token", "secret":
				item[column] = "redacted-honeypot-value"
			default:
				item[column] = fmt.Sprintf("synthetic_%d", row)
			}
		}
		rows = append(rows, item)
	}
	return rows
}

func extractPayload(r *http.Request, body []byte) string {
	values := make([]string, 0)
	for _, list := range r.URL.Query() {
		values = append(values, list...)
	}
	if len(body) > 0 {
		values = append(values, string(body))
	}
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func statementCandidate(payload string) string {
	lower := strings.ToLower(payload)
	for _, keyword := range []string{"select ", "insert ", "update ", "delete "} {
		if index := strings.Index(lower, keyword); index >= 0 {
			candidate := payload[index:]
			candidate = strings.Split(candidate, "--")[0]
			candidate = strings.TrimSpace(strings.TrimSuffix(candidate, ";"))
			if candidate != "" {
				return candidate
			}
		}
	}
	return ""
}

func looksLikeSQLInjection(payload string) bool {
	lower := strings.ToLower(payload)
	return strings.Contains(lower, "' or ") ||
		strings.Contains(lower, " union ") ||
		strings.Contains(lower, "drop table") ||
		strings.Contains(lower, "sleep(")
}

var identifierPattern = regexp.MustCompile(`[^a-zA-Z0-9_]+`)

func inferTable(payload string) string {
	lower := strings.ToLower(payload)
	for _, table := range []string{"users", "accounts", "orders", "logs"} {
		if strings.Contains(lower, table) {
			return table
		}
	}
	return "virtual_records"
}

func sanitizeIdentifier(value string) string {
	value = identifierPattern.ReplaceAllString(value, "_")
	if value == "" {
		return "record"
	}
	return value
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}
