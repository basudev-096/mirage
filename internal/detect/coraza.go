package detect

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3/types"
)

var (
	ErrWAFTimeout = errors.New("waf inspection deadline exceeded")
	ErrWAFBusy    = errors.New("waf concurrency limit reached")
	ErrDecompress = errors.New("gzip decompression failure")
)

// CorazaDetector adapts Coraza WAF v3 and OWASP CRS v4 for request inspection.
type CorazaDetector struct {
	waf coraza.WAF
	cfg Config
	sem chan struct{}
}

// NewCorazaDetector initializes an in-memory Coraza WAF instance with OWASP CRS v4.9.0 rules.
func NewCorazaDetector(cfg Config) (*CorazaDetector, error) {
	directives := fmt.Sprintf(`
		SecRuleEngine DetectionOnly
		SecRequestBodyAccess On
		SecRequestBodyLimit %d
		SecRequestBodyInMemoryLimit %d
		SecRequestBodyLimitAction ProcessPartial
		SecResponseBodyAccess Off
		SecComponentSignature "Mirage-WAF/v1.0"
		Include @crs-setup.conf.example
		Include @owasp_crs/*.conf
	`, cfg.MaxBodyInspectSize, cfg.MaxBodyInspectSize)

	wafConfig := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(directives)

	waf, err := coraza.NewWAF(wafConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to compile Coraza WAF with CRS directives: %w", err)
	}

	maxSem := cfg.MaxConcurrentInspections
	if maxSem <= 0 {
		maxSem = 500
	}

	return &CorazaDetector{
		waf: waf,
		cfg: cfg,
		sem: make(chan struct{}, maxSem),
	}, nil
}

// Inspect evaluates an HTTP request against OWASP CRS and returns a Verdict.
func (d *CorazaDetector) Inspect(ctx context.Context, req *http.Request) (Verdict, error) {
	start := time.Now()

	// 1. Acquire Concurrency Semaphore
	select {
	case d.sem <- struct{}{}:
		defer func() { <-d.sem }()
	default:
		verdict := Verdict{
			Category:       "WAF_Timeout",
			InspectionTime: time.Since(start),
			Error:          ErrWAFBusy,
		}
		if d.cfg.FailClosed {
			verdict.Malicious = true
		}
		return verdict, ErrWAFBusy
	}

	// 2. Set per-request context deadline
	inspectCtx, cancel := context.WithTimeout(ctx, d.cfg.Timeout)
	defer cancel()

	type result struct {
		verdict Verdict
		err     error
	}
	resChan := make(chan result, 1)

	go func() {
		v, err := d.doInspect(req, start)
		resChan <- result{verdict: v, err: err}
	}()

	select {
	case res := <-resChan:
		return res.verdict, res.err
	case <-inspectCtx.Done():
		verdict := Verdict{
			Category:       "WAF_Timeout",
			InspectionTime: time.Since(start),
			Error:          ErrWAFTimeout,
		}
		if d.cfg.FailClosed {
			verdict.Malicious = true
		}
		return verdict, ErrWAFTimeout
	}
}

// doInspect executes the two-phase Coraza WAF inspection.
func (d *CorazaDetector) doInspect(req *http.Request, start time.Time) (Verdict, error) {
	tx := d.waf.NewTransaction()
	defer tx.Close()

	// Phase 1: Process Connection, URI, Method, and Headers
	clientHost := req.RemoteAddr
	clientPort := 0
	tx.ProcessConnection(clientHost, clientPort, "", 0)

	uri := req.URL.RequestURI()
	if uri == "" {
		uri = req.URL.Path
	}
	tx.ProcessURI(uri, req.Method, req.Proto)

	for k, vv := range req.Header {
		for _, v := range vv {
			tx.AddRequestHeader(k, v)
		}
	}
	if req.Host != "" {
		tx.AddRequestHeader("Host", req.Host)
	}

	interruption := tx.ProcessRequestHeaders()

	// Phase 2: Process Request Body if present
	var oversized, truncated bool
	var category string

	if req.Body != nil && req.Body != http.NoBody && req.Method != http.MethodGet && req.Method != http.MethodHead {
		bodyBuf, isOversized, decompressErr := d.readInspectBody(req)
		if isOversized {
			oversized = true
			truncated = true
		}
		if decompressErr != nil {
			category = "DecompressionError"
		}

		if len(bodyBuf) > 0 {
			it, _, _ := tx.WriteRequestBody(bodyBuf)
			if it != nil {
				interruption = it
			} else {
				if it2, err := tx.ProcessRequestBody(); err == nil && it2 != nil {
					interruption = it2
				}
			}
		} else {
			if it, err := tx.ProcessRequestBody(); err == nil && it != nil {
				interruption = it
			}
		}
	} else {
		if it, err := tx.ProcessRequestBody(); err == nil && it != nil {
			interruption = it
		}
	}

	// 3. Derive Verdict from Coraza matched rules and calculated anomaly score
	matchedRules := tx.MatchedRules()
	ruleIDs := make([]RuleID, 0, len(matchedRules))
	score := 0
	hasAttackRule := false

	for _, mr := range matchedRules {
		ruleID := mr.Rule().ID()
		if isSetupOrSummaryRule(ruleID) {
			continue
		}

		ruleIDs = append(ruleIDs, RuleID(fmt.Sprintf("%d", ruleID)))
		score += 5
		hasAttackRule = true

		if category == "" {
			category = categorizeRule(mr)
		}
	}

	isMalicious := score >= d.cfg.AnomalyThreshold || interruption != nil || hasAttackRule

	if isMalicious && category == "" {
		category = "MaliciousRequest"
	} else if !isMalicious && category == "" {
		category = "Clean"
	}

	return Verdict{
		Malicious:      isMalicious,
		Category:       category,
		RuleIDs:        ruleIDs,
		Score:          score,
		OversizedBody:  oversized,
		BodyTruncated:  truncated,
		InspectionTime: time.Since(start),
	}, nil
}

// isSetupOrSummaryRule returns true for CRS setup, metadata, or correlation summary rules.
func isSetupOrSummaryRule(id int) bool {
	if id >= 900000 && id < 910000 {
		return true
	}
	if id >= 949000 && id < 950000 {
		return true
	}
	if id >= 980000 && id < 990000 {
		return true
	}
	mod := id % 1000
	if mod == 10 || mod == 13 || mod == 14 || mod == 52 || mod == 59 || mod == 60 || mod == 152 || mod == 159 || mod == 160 {
		return true
	}
	return false
}

// readInspectBody reads up to MaxBodyInspectSize bytes from request body, handling gzip if present.
func (d *CorazaDetector) readInspectBody(req *http.Request) ([]byte, bool, error) {
	maxInspect := d.cfg.MaxBodyInspectSize
	if maxInspect <= 0 {
		maxInspect = 32768
	}

	// Read up to maxInspect + 1 bytes to detect truncation
	buf := make([]byte, maxInspect+1)
	n, err := io.ReadFull(req.Body, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, false, err
	}

	isOversized := n > maxInspect
	if isOversized {
		n = maxInspect
	}
	bodySlice := buf[:n]

	// Handle Gzip Content-Encoding
	if strings.EqualFold(req.Header.Get("Content-Encoding"), "gzip") {
		gzReader, gzErr := gzip.NewReader(bytes.NewReader(bodySlice))
		if gzErr != nil {
			return bodySlice, isOversized, ErrDecompress
		}
		defer gzReader.Close()

		decompBuf := make([]byte, maxInspect+1)
		dn, _ := io.ReadFull(gzReader, decompBuf)
		if dn > maxInspect {
			isOversized = true
			dn = maxInspect
		}
		return decompBuf[:dn], isOversized, nil
	}

	return bodySlice, isOversized, nil
}

// categorizeRule maps matched CRS rule IDs and tags to standard attack categories.
func categorizeRule(mr types.MatchedRule) string {
	ruleID := mr.Rule().ID()
	tags := mr.Rule().Tags()

	for _, tag := range tags {
		tagLower := strings.ToLower(tag)
		if strings.Contains(tagLower, "sqli") || strings.Contains(tagLower, "sql_injection") {
			return "SQLi"
		}
		if strings.Contains(tagLower, "xss") {
			return "XSS"
		}
		if strings.Contains(tagLower, "lfi") || strings.Contains(tagLower, "rfi") || strings.Contains(tagLower, "path-traversal") {
			return "PathTraversal"
		}
		if strings.Contains(tagLower, "rce") || strings.Contains(tagLower, "command-injection") {
			return "RCE"
		}
	}

	// Fallback check by CRS rule ID ranges
	if ruleID >= 942000 && ruleID < 943000 {
		return "SQLi"
	}
	if ruleID >= 941000 && ruleID < 942000 {
		return "XSS"
	}
	if ruleID >= 930000 && ruleID < 931000 {
		return "PathTraversal"
	}
	if ruleID >= 932000 && ruleID < 933000 {
		return "RCE"
	}

	return "Attack"
}
