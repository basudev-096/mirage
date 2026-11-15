// Package deception analyzes SQL injection payloads and produces safe,
// deterministic database-shaped responses for the deception path.
package deception

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/brianvoe/gofakeit/v7"
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
	rows   int
	secret []byte
}

const defaultSeedSecret = "mirage-development-seed"

func New() *Engine {
	secret := os.Getenv("MIRAGE_DECEPTION_SEED")
	if secret == "" {
		secret = defaultSeedSecret
	}
	return NewWithSeed(secret)
}

// NewWithSeed creates a deception engine whose synthetic identities are
// stable for the configured secret, session, and virtual target.
func NewWithSeed(secret string) *Engine {
	if secret == "" {
		secret = defaultSeedSecret
	}
	return &Engine{rows: 3, secret: []byte(secret)}
}

func (e *Engine) AnalyzeRequest(r *http.Request, body []byte) Result {
	payload := extractPayload(r, body)
	if payload == "" {
		return Result{}
	}
	statement := statementCandidate(payload)
	if statement == "" {
		if looksLikeSQLInjection(payload) {
			return e.fallback(payload, r.Header.Get("X-Mirage-Session-ID"))
		}
		return Result{}
	}
	parsed, err := sqlparser.Parse(statement)
	if err != nil {
		if !looksLikeSQLInjection(payload) {
			return Result{}
		}
		return e.fallback(payload, r.Header.Get("X-Mirage-Session-ID"))
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
	return e.result(target, "sql_ast_projection", r.Header.Get("X-Mirage-Session-ID"))
}

func (e *Engine) result(target Target, class, sessionID string) Result {
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
		"data":   e.fakeRows(sessionID, target, e.rows),
	}
	encoded, _ := json.Marshal(body)
	metadata, _ := json.Marshal(map[string]any{
		"engine":            "mirage-sql-honeypot",
		"strategy":          class,
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

func (e *Engine) fallback(payload, sessionID string) Result {
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
	}, "sql_injection_fallback", sessionID)
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

func (e *Engine) fakeRows(sessionID string, target Target, count int) []map[string]any {
	rows := make([]map[string]any, 0, count)
	for row := 1; row <= count; row++ {
		item := make(map[string]any, len(target.Columns))
		for _, column := range target.Columns {
			item[column] = e.syntheticValue(sessionID, target, row, column)
		}
		rows = append(rows, item)
	}
	return rows
}

func (e *Engine) syntheticValue(sessionID string, target Target, row int, column string) any {
	name := strings.ToLower(strings.TrimSpace(column))
	faker := gofakeit.New(e.seed(sessionID, target, row, name))
	switch name {
	case "id", "user_id", "account_id":
		return faker.IntRange(10000, 99999999)
	case "username", "user_name":
		return e.syntheticUsername(sessionID, target, row)
	case "name", "full_name":
		return faker.Name()
	case "first_name":
		return faker.FirstName()
	case "last_name":
		return faker.LastName()
	case "email":
		return e.syntheticUsername(sessionID, target, row) + "@example.invalid"
	case "phone", "phone_number":
		return fmt.Sprintf("+1-202-555-%04d", faker.IntRange(0, 9999))
	case "password", "password_hash":
		return "synthetic-hash-" + hexDigest(e.seedBytes(sessionID, target, row, name))[:24]
	case "token", "api_key", "secret":
		return "synthetic-" + hexDigest(e.seedBytes(sessionID, target, row, name))[:32]
	case "address":
		return faker.Street()
	case "city":
		return faker.City()
	case "country":
		return faker.Country()
	case "company":
		return faker.Company()
	case "age":
		return faker.IntRange(18, 85)
	case "created_at", "updated_at":
		base := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
		return faker.DateRange(base, time.Date(2025, time.December, 31, 23, 59, 59, 0, time.UTC)).Format(time.RFC3339)
	case "status":
		return []string{"active", "pending", "suspended"}[faker.IntRange(0, 2)]
	case "role":
		return []string{"user", "admin", "analyst"}[faker.IntRange(0, 2)]
	default:
		return fmt.Sprintf("synthetic_%s_%s", sanitizeIdentifier(column), sanitizeIdentifier(faker.Word()))
	}
}

func (e *Engine) syntheticUsername(sessionID string, target Target, row int) string {
	faker := gofakeit.New(e.seed(sessionID, target, row, "identity"))
	return fmt.Sprintf("%s_%d", sanitizeIdentifier(strings.ToLower(faker.Username())), row)
}

func (e *Engine) seed(sessionID string, target Target, row int, column string) uint64 {
	digest := e.seedBytes(sessionID, target, row, column)
	return binary.BigEndian.Uint64(digest[:8])
}

func (e *Engine) seedBytes(sessionID string, target Target, row int, column string) []byte {
	context := strings.Join([]string{
		"mirage-deception-v1",
		normalize(sessionID, "anonymous"),
		normalize(target.Database, "mirage_honeypot"),
		normalize(target.Schema, "public"),
		normalize(target.Table, "virtual_records"),
		fmt.Sprintf("%d", row),
		normalize(column, "value"),
	}, "\x00")
	mac := hmac.New(sha256.New, e.secret)
	_, _ = mac.Write([]byte(context))
	return mac.Sum(nil)
}

func hexDigest(value []byte) string {
	return fmt.Sprintf("%x", value)
}

func normalize(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	return value
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
