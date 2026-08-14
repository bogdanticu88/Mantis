package attacks

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/bogdanticu88/Mantis/internal/findings"
	"github.com/bogdanticu88/Mantis/internal/httpclient"
)

// Form mirrors dast.Form's shape without importing the dast package (attacks
// is a peer of dast, not a dependent of it - dast calls into attacks, not
// the other way round).
type Form struct {
	Action string
	Method string
	Inputs map[string]string
}

// Options controls what gets fuzzed and how hard.
type Options struct {
	Environment string
	Classes     []string // empty = AllClasses()
	MaxParams   int      // distinct parameters to fuzz, query+form combined; 0 = default (25)
	MaxRequests int      // hard cap on fuzz requests for this run; 0 = default (300)
	Destructive bool     // permit fuzzing form fields on non-GET forms and JSON body POST fuzzing

	// Timing-based detection thresholds. Zero values use the defaults listed.
	TimingMinDeltaMS    int // minimum response-time increase over baseline to flag; default 3500
	TimingBaselineN     int // baseline request count per URL; default 3
	TimingMinAbsoluteMS int // minimum absolute response time required to flag; default 3000
}

func (o Options) maxParams() int {
	if o.MaxParams > 0 {
		return o.MaxParams
	}
	return 25
}

func (o Options) maxRequests() int {
	if o.MaxRequests > 0 {
		return o.MaxRequests
	}
	return 300
}

func (o Options) timingMinDeltaMS() int {
	if o.TimingMinDeltaMS > 0 {
		return o.TimingMinDeltaMS
	}
	return 3500
}

func (o Options) timingBaselineN() int {
	if o.TimingBaselineN > 0 {
		return o.TimingBaselineN
	}
	return 3
}

func (o Options) timingMinAbsoluteMS() int {
	if o.TimingMinAbsoluteMS > 0 {
		return o.TimingMinAbsoluteMS
	}
	return 3000
}

// budget is a simple shared request counter so FuzzQueryParams and
// FuzzForms can be called back to back against the same overall cap.
type budget struct {
	remaining int
}

func (b *budget) take() bool {
	if b.remaining <= 0 {
		return false
	}
	b.remaining--
	return true
}

// FuzzQueryParams fuzzes every distinct query parameter found across urls.
// Always safe to run under an active-testing policy - it only ever sends
// GET requests, each independently retryable, nothing state-changing.
func FuzzQueryParams(ctx context.Context, client *httpclient.Client, redactor *httpclient.Redactor, urls []string, opts Options) []findings.Finding {
	b := &budget{remaining: opts.maxRequests()}
	targets := queryTargets(urls, opts.maxParams())

	var out []findings.Finding
	for _, tgt := range targets {
		for _, class := range sortedClasses(opts.Classes) {
			for _, p := range payloadsByClass[class] {
				if !b.take() {
					return out
				}
				fuzzed := setQueryParam(tgt.rawURL, tgt.param, p.Value)
				resp, err := client.Do(ctx, httpclient.Request{Method: "GET", URL: fuzzed})
				if err != nil {
					continue
				}
				if ok, on := matched(p, string(resp.Body)); ok {
					out = append(out, mkFinding(class, tgt.param, resp.Request.Method, tgt.rawURL, opts.Environment, p, on, resp, redactor))
				}
			}
		}
	}
	return out
}

// FuzzForms fuzzes discovered form fields. GET forms are always safe to
// fuzz (same reasoning as query params); forms using any other method only
// get fuzzed when Destructive is set, mirroring the same safe-methods
// gating the API checks use for method-abuse probing.
func FuzzForms(ctx context.Context, client *httpclient.Client, redactor *httpclient.Redactor, forms []Form, opts Options) []findings.Finding {
	b := &budget{remaining: opts.maxRequests()}
	targets := formTargets(forms, opts)

	var out []findings.Finding
	for _, tgt := range targets {
		for _, class := range sortedClasses(opts.Classes) {
			for _, p := range payloadsByClass[class] {
				if !b.take() {
					return out
				}
				req := buildFormRequest(tgt, p.Value)
				resp, err := client.Do(ctx, req)
				if err != nil {
					continue
				}
				if ok, on := matched(p, string(resp.Body)); ok {
					out = append(out, mkFinding(class, tgt.field, resp.Request.Method, tgt.action, opts.Environment, p, on, resp, redactor))
				}
			}
		}
	}
	return out
}

// jsonFuzzFields is the fixed set of JSON field names tried when probing
// API endpoints. These cover the most common injection entry-points (IDs,
// search/filter fields, redirect targets, and template/command values).
var jsonFuzzFields = []string{
	"id", "q", "query", "search", "username",
	"email", "url", "redirect", "input", "data", "template",
}

// timingPayloads are SQL time-delay probes for MySQL, MSSQL, and PostgreSQL.
// None of these have MatchWords or MatchRegex; detection is purely by elapsed
// time compared against a per-URL measured baseline.
var timingPayloads = []string{
	"1 AND SLEEP(5)-- -",
	"' OR SLEEP(5)-- -",
	"1; WAITFOR DELAY '0:0:5'--",
	"'; WAITFOR DELAY '0:0:5'--",
	"1; SELECT pg_sleep(5)--",
	"' OR (SELECT pg_sleep(5))--",
}

// FuzzJSONBody sends each payload class to discovered JSON API endpoints by
// POSTing a single-field JSON document for each of a fixed set of common
// field names. Requires Destructive: these are real POST submissions that
// may create or modify server-side state.
func FuzzJSONBody(ctx context.Context, client *httpclient.Client, redactor *httpclient.Redactor, endpoints []string, opts Options) []findings.Finding {
	if !opts.Destructive || len(endpoints) == 0 {
		return nil
	}
	b := &budget{remaining: opts.maxRequests()}
	sortedEndpoints := append([]string(nil), endpoints...)
	sort.Strings(sortedEndpoints)

	var out []findings.Finding
	for _, rawURL := range sortedEndpoints {
		postURL := stripQuery(rawURL)
		for _, field := range jsonFuzzFields {
			for _, class := range sortedClasses(opts.Classes) {
				for _, p := range payloadsByClass[class] {
					if !b.take() {
						return out
					}
					req := httpclient.Request{
						Method:  "POST",
						URL:     postURL,
						Headers: map[string]string{"Content-Type": "application/json"},
						Body:    []byte(jsonBody(field, p.Value)),
					}
					resp, err := client.Do(ctx, req)
					if err != nil {
						continue
					}
					if ok, on := matched(p, string(resp.Body)); ok {
						out = append(out, mkFinding(class, field, "POST", postURL, opts.Environment, p, on, resp, redactor))
					}
				}
			}
		}
	}
	return out
}

// FuzzTimingBased detects blind time-based SQL injection by measuring each
// endpoint's baseline response time and flagging when a SLEEP/WAITFOR payload
// causes a response time that exceeds the baseline by more than the configured
// delta. This statistical approach handles slow servers correctly: a server
// that already takes 4 s per request will not trigger on a SLEEP(5) that
// produces a 5 s response, only one that produces 4 s + delta.
//
// Runs GET-only against query-parameter endpoints; no destructive gate needed.
// Confidence on findings is 0.7 (timing is inherently noisier than body-match).
func FuzzTimingBased(ctx context.Context, client *httpclient.Client, redactor *httpclient.Redactor, urls []string, opts Options) []findings.Finding {
	b := &budget{remaining: opts.maxRequests()}
	targets := queryTargets(urls, opts.maxParams())
	if len(targets) == 0 {
		return nil
	}

	baselineN := opts.timingBaselineN()
	minDelta := time.Duration(opts.timingMinDeltaMS()) * time.Millisecond
	minAbsolute := time.Duration(opts.timingMinAbsoluteMS()) * time.Millisecond

	// One baseline per unique URL, shared across all params on that URL.
	baselines := map[string]time.Duration{}
	for _, tgt := range targets {
		if _, seen := baselines[tgt.rawURL]; seen {
			continue
		}
		var samples []time.Duration
		for i := 0; i < baselineN; i++ {
			if !b.take() {
				break
			}
			resp, err := client.Do(ctx, httpclient.Request{Method: "GET", URL: tgt.rawURL})
			if err != nil {
				continue
			}
			samples = append(samples, resp.Duration)
		}
		baselines[tgt.rawURL] = medianDuration(samples)
	}

	var out []findings.Finding
	for _, tgt := range targets {
		baseline := baselines[tgt.rawURL]
		for _, payload := range timingPayloads {
			if !b.take() {
				return out
			}
			fuzzed := setQueryParam(tgt.rawURL, tgt.param, payload)
			resp, err := client.Do(ctx, httpclient.Request{Method: "GET", URL: fuzzed})
			if err != nil {
				continue
			}
			delta := resp.Duration - baseline
			if delta < minDelta || resp.Duration < minAbsolute {
				continue
			}
			label := fmt.Sprintf("delta:%dms (baseline:%dms)", delta.Milliseconds(), baseline.Milliseconds())
			out = append(out, findings.Finding{
				ID:          "MANTIS-FUZZ-timing-sqli",
				Name:        fmt.Sprintf("Blind Time-Based SQL Injection (parameter: %s)", tgt.param),
				Severity:    findings.SeverityHigh,
				Confidence:  0.7,
				Environment: opts.Environment,
				Target:      tgt.rawURL,
				Endpoint:    tgt.rawURL,
				Method:      "GET",
				Description: fmt.Sprintf("Parameter %q caused a %dms response delay (baseline %dms) when injected with a time-delay SQL payload, indicating possible blind SQL injection.", tgt.param, resp.Duration.Milliseconds(), baseline.Milliseconds()),
				CWE:         "CWE-89",
				OWASP:       "A03:2021-Injection",
				Tags:        []string{"fuzz", "timing-sqli", "blind"},
				Evidence: findings.Evidence{
					Description: fmt.Sprintf("Payload sent: %s", payload),
					MatchedOn:   []string{label},
					Exchanges:   []findings.HTTPExchange{redactor.Exchange(resp)},
				},
				Timestamp: time.Now(),
			})
		}
	}
	return out
}

func medianDuration(samples []time.Duration) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

// stripQuery returns the URL with its query string removed, for use as a
// POST target when the API resource is identified by path alone.
func stripQuery(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.RawQuery = ""
	return u.String()
}

// jsonBody builds a minimal single-field JSON document for injection testing.
// Uses manual escaping so that payload characters like <, >, ', " are sent
// verbatim (encoding/json would HTML-escape them, defeating reflection tests).
func jsonBody(field, value string) string {
	return `{"` + jsonEscape(field) + `":"` + jsonEscape(value) + `"}`
}

func jsonEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
}

// fuzzableHeaders is the fixed set of request headers commonly used as
// injection vectors: IP spoofing bypasses, WAF evasion, and reflected-value
// injection through headers that get echoed back in responses or logs.
var fuzzableHeaders = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Originating-IP",
	"X-Remote-Addr",
	"X-Client-IP",
	"Referer",
}

// FuzzHeaders injects payloads into security-relevant request headers for
// each discovered URL. Runs unconditionally under an active-testing policy
// (header injection is always a GET with no side-effects on the target's
// data layer, regardless of what headers say about the caller's identity).
func FuzzHeaders(ctx context.Context, client *httpclient.Client, redactor *httpclient.Redactor, urls []string, opts Options) []findings.Finding {
	b := &budget{remaining: opts.maxRequests()}
	sortedURLs := append([]string(nil), urls...)
	sort.Strings(sortedURLs)

	seen := map[string]bool{}
	var targets []string
	for _, u := range sortedURLs {
		if !seen[u] {
			seen[u] = true
			targets = append(targets, u)
		}
	}

	var out []findings.Finding
	for _, rawURL := range targets {
		for _, hdr := range fuzzableHeaders {
			for _, class := range sortedClasses(opts.Classes) {
				for _, p := range payloadsByClass[class] {
					if !b.take() {
						return out
					}
					req := httpclient.Request{
						Method:  "GET",
						URL:     rawURL,
						Headers: map[string]string{hdr: p.Value},
					}
					resp, err := client.Do(ctx, req)
					if err != nil {
						continue
					}
					if ok, on := matched(p, string(resp.Body)); ok {
						out = append(out, mkFinding(class, hdr, "GET", rawURL, opts.Environment, p, on, resp, redactor))
					}
				}
			}
		}
	}
	return out
}

// FuzzCookies injects payloads into cookie values for each (cookie-name, url)
// pair discovered during crawling. Like header fuzzing this is always GET-safe.
func FuzzCookies(ctx context.Context, client *httpclient.Client, redactor *httpclient.Redactor, cookieNames []string, urls []string, opts Options) []findings.Finding {
	if len(cookieNames) == 0 || len(urls) == 0 {
		return nil
	}
	b := &budget{remaining: opts.maxRequests()}
	sortedURLs := append([]string(nil), urls...)
	sort.Strings(sortedURLs)
	sortedNames := append([]string(nil), cookieNames...)
	sort.Strings(sortedNames)

	var out []findings.Finding
	for _, rawURL := range sortedURLs {
		for _, name := range sortedNames {
			for _, class := range sortedClasses(opts.Classes) {
				for _, p := range payloadsByClass[class] {
					if !b.take() {
						return out
					}
					req := httpclient.Request{
						Method:  "GET",
						URL:     rawURL,
						Headers: map[string]string{"Cookie": name + "=" + p.Value},
					}
					resp, err := client.Do(ctx, req)
					if err != nil {
						continue
					}
					if ok, on := matched(p, string(resp.Body)); ok {
						out = append(out, mkFinding(class, name, "GET", rawURL, opts.Environment, p, on, resp, redactor))
					}
				}
			}
		}
	}
	return out
}

func sortedClasses(selected []string) []string {
	m := payloadsFor(selected)
	out := make([]string, 0, len(m))
	for c := range m {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

type queryTarget struct {
	rawURL string
	param  string
}

// queryTargets extracts distinct (path, param-name) pairs from urls, capped
// at max, in a deterministic order (sorted) so which subset gets tested
// under a request cap doesn't vary run to run.
func queryTargets(urls []string, max int) []queryTarget {
	seen := map[string]bool{}
	var out []queryTarget
	sortedURLs := append([]string(nil), urls...)
	sort.Strings(sortedURLs)

	for _, raw := range sortedURLs {
		u, err := url.Parse(raw)
		if err != nil || u.RawQuery == "" {
			continue
		}
		names := make([]string, 0)
		for name := range u.Query() {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			key := u.Path + "?" + name
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, queryTarget{rawURL: raw, param: name})
			if len(out) >= max {
				return out
			}
		}
	}
	return out
}

func setQueryParam(rawURL, param, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String()
}

type formTarget struct {
	action string
	method string
	field  string
	others map[string]string // other fields, filled with a benign placeholder
}

func formTargets(forms []Form, opts Options) []formTarget {
	var out []formTarget
	for _, f := range forms {
		safe := f.Method == "" || f.Method == "GET"
		if !safe && !opts.Destructive {
			continue
		}
		names := make([]string, 0, len(f.Inputs))
		for name := range f.Inputs {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, field := range names {
			others := map[string]string{}
			for _, n := range names {
				if n != field {
					others[n] = "1"
				}
			}
			out = append(out, formTarget{action: f.Action, method: f.Method, field: field, others: others})
			if len(out) >= opts.maxParams() {
				return out
			}
		}
	}
	return out
}

func buildFormRequest(tgt formTarget, payload string) httpclient.Request {
	method := tgt.method
	if method == "" {
		method = "GET"
	}
	values := url.Values{}
	for k, v := range tgt.others {
		values.Set(k, v)
	}
	values.Set(tgt.field, payload)

	if method == "GET" {
		u, err := url.Parse(tgt.action)
		if err == nil {
			u.RawQuery = values.Encode()
			return httpclient.Request{Method: "GET", URL: u.String()}
		}
	}
	return httpclient.Request{
		Method:  method,
		URL:     tgt.action,
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:    []byte(values.Encode()),
	}
}

func mkFinding(class, field, method, target, environment string, p Payload, matchedOn string, resp *httpclient.Response, redactor *httpclient.Redactor) findings.Finding {
	info := classes[class]
	return findings.Finding{
		ID:          fmt.Sprintf("MANTIS-FUZZ-%s", class),
		Name:        fmt.Sprintf("%s (parameter: %s)", info.Name, field),
		Severity:    info.Severity,
		Confidence:  1.0,
		Environment: environment,
		Target:      target,
		Endpoint:    target,
		Method:      method,
		Description: fmt.Sprintf("Parameter %q accepted a %s payload and the response matched an expected indicator (%q).", field, info.Name, matchedOn),
		CWE:         info.CWE,
		OWASP:       info.OWASP,
		Tags:        []string{"fuzz", class},
		Evidence: findings.Evidence{
			Description: fmt.Sprintf("Payload sent: %s", p.Value),
			MatchedOn:   []string{matchedOn},
			Exchanges:   []findings.HTTPExchange{redactor.Exchange(resp)},
		},
		Timestamp: time.Now(),
	}
}
