package deceive

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/brianvoe/gofakeit/v6"
)

// columnDef describes a single column in a fake table.
type columnDef struct {
	Name     string // SQL column name
	SQLType  string // SQL type string, e.g. "INT", "VARCHAR(255)"
	FakeType string // generation hint used by generateValue
}

// fakeDatabase is the static schema for the synthetic backend database.
// All tables and columns are pre-defined; no real schema is ever inspected.
var fakeDatabase = map[string][]columnDef{
	"users": {
		{Name: "id", SQLType: "INT", FakeType: "seq"},
		{Name: "username", SQLType: "VARCHAR(64)", FakeType: "username"},
		{Name: "email", SQLType: "VARCHAR(255)", FakeType: "email"},
		{Name: "password", SQLType: "VARCHAR(255)", FakeType: "password_hash"},
		{Name: "role", SQLType: "VARCHAR(32)", FakeType: "role"},
		{Name: "created_at", SQLType: "TIMESTAMP", FakeType: "timestamp"},
		{Name: "last_login", SQLType: "TIMESTAMP", FakeType: "timestamp"},
	},
	"orders": {
		{Name: "id", SQLType: "INT", FakeType: "seq"},
		{Name: "user_id", SQLType: "INT", FakeType: "int"},
		{Name: "product_id", SQLType: "INT", FakeType: "int"},
		{Name: "amount", SQLType: "FLOAT", FakeType: "price"},
		{Name: "status", SQLType: "VARCHAR(32)", FakeType: "order_status"},
		{Name: "created_at", SQLType: "TIMESTAMP", FakeType: "timestamp"},
	},
	"products": {
		{Name: "id", SQLType: "INT", FakeType: "seq"},
		{Name: "name", SQLType: "VARCHAR(255)", FakeType: "product_name"},
		{Name: "description", SQLType: "TEXT", FakeType: "sentence"},
		{Name: "price", SQLType: "FLOAT", FakeType: "price"},
		{Name: "stock", SQLType: "INT", FakeType: "stock"},
		{Name: "category", SQLType: "VARCHAR(64)", FakeType: "category"},
	},
	"sessions": {
		{Name: "id", SQLType: "VARCHAR(64)", FakeType: "uuid"},
		{Name: "user_id", SQLType: "INT", FakeType: "int"},
		{Name: "token", SQLType: "VARCHAR(255)", FakeType: "token"},
		{Name: "ip_address", SQLType: "VARCHAR(45)", FakeType: "ipv4"},
		{Name: "created_at", SQLType: "TIMESTAMP", FakeType: "timestamp"},
		{Name: "expires_at", SQLType: "TIMESTAMP", FakeType: "timestamp"},
	},
	"audit_log": {
		{Name: "id", SQLType: "INT", FakeType: "seq"},
		{Name: "user_id", SQLType: "INT", FakeType: "int"},
		{Name: "action", SQLType: "VARCHAR(64)", FakeType: "action"},
		{Name: "resource", SQLType: "VARCHAR(255)", FakeType: "resource_path"},
		{Name: "ip_address", SQLType: "VARCHAR(45)", FakeType: "ipv4"},
		{Name: "ts", SQLType: "TIMESTAMP", FakeType: "timestamp"},
	},
	"employees": {
		{Name: "id", SQLType: "INT", FakeType: "seq"},
		{Name: "name", SQLType: "VARCHAR(255)", FakeType: "name"},
		{Name: "department", SQLType: "VARCHAR(64)", FakeType: "department"},
		{Name: "salary", SQLType: "FLOAT", FakeType: "salary"},
		{Name: "hire_date", SQLType: "TIMESTAMP", FakeType: "timestamp"},
		{Name: "email", SQLType: "VARCHAR(255)", FakeType: "email"},
	},
	"customers": {
		{Name: "id", SQLType: "INT", FakeType: "seq"},
		{Name: "name", SQLType: "VARCHAR(255)", FakeType: "name"},
		{Name: "email", SQLType: "VARCHAR(255)", FakeType: "email"},
		{Name: "phone", SQLType: "VARCHAR(32)", FakeType: "phone"},
		{Name: "address", SQLType: "TEXT", FakeType: "address"},
		{Name: "created_at", SQLType: "TIMESTAMP", FakeType: "timestamp"},
	},
}

// allTableNames returns sorted list of table names in the fake database.
func allTableNames() []string {
	names := make([]string, 0, len(fakeDatabase))
	for k := range fakeDatabase {
		names = append(names, k)
	}
	return names
}

// resolveTable returns the columns for tableName.
// Falls back to "users" schema if the table name is unrecognised.
func resolveTable(tableName string) (string, []columnDef) {
	if cols, ok := fakeDatabase[tableName]; ok {
		return tableName, cols
	}
	return tableName, fakeDatabase["users"]
}

// --------------------------------------------------------------------------
// Deterministic per-session seed management
// --------------------------------------------------------------------------

// sessionSchemaMgr assigns and caches a deterministic seed per (IP, table) pair
// so repeated probes from the same source get structurally consistent fake rows.
type sessionSchemaMgr struct {
	mu       sync.RWMutex
	sessions map[string]map[string]int64 // sessionIP → tableName → seed
}

var globalSessions = &sessionSchemaMgr{
	sessions: make(map[string]map[string]int64),
}

// seedFor computes a deterministic int64 seed from a (sessionIP, tableName) pair.
func seedFor(sessionIP, tableName string) int64 {
	h := sha256.Sum256([]byte(sessionIP + "\x00" + tableName))
	return int64(binary.LittleEndian.Uint64(h[:8]))
}

// fakerFor returns a *gofakeit.Faker seeded deterministically for (sessionIP, tableName).
// The same pair always returns the same seed, so the first-row output is identical
// across multiple calls — providing session-level schema consistency.
func fakerFor(sessionIP, tableName string) *gofakeit.Faker {
	globalSessions.mu.RLock()
	if s, ok := globalSessions.sessions[sessionIP]; ok {
		if seed, ok2 := s[tableName]; ok2 {
			globalSessions.mu.RUnlock()
			return gofakeit.New(seed)
		}
	}
	globalSessions.mu.RUnlock()

	seed := seedFor(sessionIP, tableName)

	globalSessions.mu.Lock()
	if _, ok := globalSessions.sessions[sessionIP]; !ok {
		globalSessions.sessions[sessionIP] = make(map[string]int64)
	}
	globalSessions.sessions[sessionIP][tableName] = seed
	globalSessions.mu.Unlock()

	return gofakeit.New(seed)
}

// --------------------------------------------------------------------------
// Fake value generation
// --------------------------------------------------------------------------

// generateValue returns a fake value for a single column using the given Faker.
// The seq fakeType is handled externally (caller provides the row index).
func generateValue(f *gofakeit.Faker, fakeType string, rowIdx int) interface{} {
	switch fakeType {
	case "seq":
		return rowIdx + 1
	case "int":
		return f.Number(1, 999999)
	case "username":
		return f.Username()
	case "email":
		return f.Email()
	case "password_hash":
		return "$2b$12$" + f.LetterN(53)
	case "role":
		roles := []string{"admin", "user", "moderator", "viewer", "editor"}
		return roles[f.Number(0, len(roles)-1)]
	case "timestamp":
		base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		end := time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC)
		return f.DateRange(base, end).Format("2006-01-02 15:04:05")
	case "price":
		return fmt.Sprintf("%.2f", f.Price(1.0, 999.99))
	case "salary":
		return fmt.Sprintf("%.2f", f.Price(30000, 150000))
	case "order_status":
		statuses := []string{"pending", "processing", "shipped", "delivered", "cancelled"}
		return statuses[f.Number(0, len(statuses)-1)]
	case "product_name":
		adjectives := []string{"Premium", "Advanced", "Pro", "Smart", "Ultra", "Essential"}
		nouns := []string{"Widget", "Device", "Tool", "Kit", "Pack", "Unit", "System"}
		return adjectives[f.Number(0, len(adjectives)-1)] + " " + nouns[f.Number(0, len(nouns)-1)]
	case "sentence":
		return f.Sentence(f.Number(5, 12))
	case "stock":
		return f.Number(0, 10000)
	case "category":
		cats := []string{"electronics", "clothing", "food", "books", "home", "sports", "tools"}
		return cats[f.Number(0, len(cats)-1)]
	case "uuid":
		return f.UUID()
	case "token":
		return f.LetterN(64)
	case "ipv4":
		return f.IPv4Address()
	case "action":
		actions := []string{"login", "logout", "view", "update", "delete", "create", "export"}
		return actions[f.Number(0, len(actions)-1)]
	case "resource_path":
		return "/api/" + f.LoremIpsumWord()
	case "name":
		return f.Name()
	case "department":
		depts := []string{"Engineering", "Sales", "Marketing", "HR", "Finance", "Operations", "Legal"}
		return depts[f.Number(0, len(depts)-1)]
	case "phone":
		return f.Phone()
	case "address":
		a := f.Address()
		return a.Street + ", " + a.City + ", " + a.State
	default:
		return f.Word()
	}
}

// generateRows produces n fake rows for tableName using deterministic seeding for sessionIP.
func generateRows(sessionIP, tableName string, cols []columnDef, n int) []map[string]interface{} {
	f := fakerFor(sessionIP, tableName)
	rows := make([]map[string]interface{}, n)
	for i := 0; i < n; i++ {
		row := make(map[string]interface{}, len(cols))
		for _, col := range cols {
			row[col.Name] = generateValue(f, col.FakeType, i)
		}
		rows[i] = row
	}
	return rows
}
