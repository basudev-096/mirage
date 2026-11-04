package proxy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const maxRecordedBody = 1024

func requestSummary(r *http.Request) string {
	query := r.URL.Query()
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		values := query[key]
		if sensitiveField(key) {
			values = []string{"[REDACTED]"}
		}
		for _, value := range values {
			parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(truncateActivity(value)))
		}
	}
	summary := r.Method + " " + r.URL.Path
	if len(parts) > 0 {
		summary += "?" + strings.Join(parts, "&")
	}
	return summary
}

func requestBodyPreview(r *http.Request, body []byte) string {
	if len(body) == 0 {
		return ""
	}
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	var safe []byte
	switch {
	case strings.Contains(contentType, "application/json") || strings.Contains(contentType, "+json"):
		var value any
		if json.Unmarshal(body, &value) != nil {
			return "[JSON request body omitted: unable to parse safely]"
		}
		redactJSON(value)
		safe, _ = json.Marshal(value)
	case strings.Contains(contentType, "application/x-www-form-urlencoded"):
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return "[form request body omitted: unable to parse safely]"
		}
		for key := range form {
			if sensitiveField(key) {
				form[key] = []string{"[REDACTED]"}
			}
		}
		safe = []byte(form.Encode())
	default:
		return "[request body omitted for content type " + truncateActivity(contentType) + "]"
	}
	if len(safe) > maxRecordedBody {
		return string(safe[:maxRecordedBody]) + "…[truncated]"
	}
	return string(safe)
}

func redactJSON(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if sensitiveField(key) {
				typed[key] = "[REDACTED]"
			} else {
				redactJSON(child)
			}
		}
	case []any:
		for _, child := range typed {
			redactJSON(child)
		}
	}
}

func sensitiveField(name string) bool {
	name = strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(name))
	for _, marker := range []string{"password", "passwd", "secret", "token", "authorization", "apikey", "session", "cookie", "email", "phone", "ssn", "creditcard"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func truncateActivity(value string) string {
	const maxValue = 160
	if len(value) <= maxValue {
		return value
	}
	return value[:maxValue] + "..."
}
