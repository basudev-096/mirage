package deceive

import (
	"fmt"
	"html"
	"net/http"
)

// xssHandler returns a fake HTML page that reflects the attacker's payload
// as HTML-entity-encoded text. The script tag never executes, but scanning
// tools that look for raw reflection will see it and continue probing.
type xssHandler struct{}

func (h *xssHandler) handle(w http.ResponseWriter, r *http.Request) error {
	// Collect the first query-param value (usually the injected payload).
	payload := ""
	for _, vals := range r.URL.Query() {
		if len(vals) > 0 {
			payload = vals[0]
			break
		}
	}

	// HTML-entity-encode the payload so it is visible in the page but never
	// interpreted as executable code by the browser.
	escaped := html.EscapeString(payload)

	body := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Search Results</title>
</head>
<body>
  <div id="header">
    <h1>Search Results</h1>
    <p>Showing results for: <span id="query">%s</span></p>
  </div>
  <div id="results">
    <ul>
      <li>Result #1 &mdash; example item one</li>
      <li>Result #2 &mdash; example item two</li>
      <li>Result #3 &mdash; example item three</li>
    </ul>
  </div>
  <div id="footer">
    <small>Powered by WebApp v2.3.1 | &copy; 2024</small>
  </div>
</body>
</html>`, escaped)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Backend-Server", "mirage-demo-backend")
	w.WriteHeader(http.StatusOK)
	_, err := fmt.Fprint(w, body)
	return err
}
