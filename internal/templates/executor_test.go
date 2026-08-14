package templates

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bogdanticu88/Mantis/internal/findings"
	"github.com/bogdanticu88/Mantis/internal/httpclient"
)

func testClient(t *testing.T) *httpclient.Client {
	t.Helper()
	c, err := httpclient.New(httpclient.Config{})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}
	return c
}

func TestRun_SimpleMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/actuator/env" {
			w.Write([]byte(`{"activeProfiles": ["prod"]}`))
		}
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "test-actuator",
		Info: Info{Name: "Test Actuator", Severity: "high"},
		Requests: []RequestSpec{{
			Method: "GET",
			Path:   "/actuator/env",
			Matchers: []Matcher{
				{Type: "word", Words: []string{"activeProfiles"}},
			},
		}},
	}

	result := Run(context.Background(), testClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if result.Error != nil {
		t.Fatalf("Run returned an error: %v", result.Error)
	}
	if !result.Matched {
		t.Fatal("expected the template to match")
	}
	if len(result.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Severity != "high" || f.Environment != "test" || f.Template != "test-actuator" {
		t.Errorf("finding = %+v, unexpected field values", f)
	}
}

func TestRun_NoMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "test-notfound",
		Info: Info{Name: "Test", Severity: "low"},
		Requests: []RequestSpec{{
			Method:   "GET",
			Path:     "/nope",
			Matchers: []Matcher{{Type: "status", Status: []int{200}}},
		}},
	}

	result := Run(context.Background(), testClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if result.Error != nil {
		t.Fatalf("Run returned an error: %v", result.Error)
	}
	if result.Matched {
		t.Error("expected no match against a 404 response")
	}
	if len(result.Findings) != 0 {
		t.Errorf("got %d findings for a non-matching template, want 0", len(result.Findings))
	}
}

// This is the chaining behavior the whole login->extract->use pattern relies
// on: a request with no matchers always "passes" and just contributes
// variables, and a later step can use what an earlier step extracted.
func TestRun_ChainExtractsAndUsesVariable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			json.NewEncoder(w).Encode(map[string]string{"token": "sess-abc123"})
		case "/whoami":
			if r.Header.Get("Authorization") == "Bearer sess-abc123" {
				w.Write([]byte("authenticated"))
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		}
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "chain-test",
		Info: Info{Name: "Chain Test", Severity: "info"},
		Requests: []RequestSpec{
			{
				Method:     "GET",
				Path:       "/login",
				Extractors: []Extractor{{Type: "json", Name: "token", Path: "$.token"}},
				// no matchers - this step exists purely to extract a token
			},
			{
				Method:   "GET",
				Path:     "/whoami",
				Headers:  map[string]string{"Authorization": "Bearer ${token}"},
				Matchers: []Matcher{{Type: "word", Words: []string{"authenticated"}}},
			},
		},
	}

	result := Run(context.Background(), testClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if result.Error != nil {
		t.Fatalf("Run returned an error: %v", result.Error)
	}
	if !result.Matched {
		t.Fatal("expected the chain to succeed once the extracted token was reused in the second request")
	}
}

func TestRun_ChainStopsOnFailedStep(t *testing.T) {
	var secondRequestMade bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/step1":
			w.WriteHeader(http.StatusForbidden)
		case "/step2":
			secondRequestMade = true
		}
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "chain-stop-test",
		Info: Info{Name: "Chain Stop Test", Severity: "info"},
		Requests: []RequestSpec{
			{Method: "GET", Path: "/step1", Matchers: []Matcher{{Type: "status", Status: []int{200}}}},
			{Method: "GET", Path: "/step2"},
		},
	}

	result := Run(context.Background(), testClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if result.Error != nil {
		t.Fatalf("Run returned an error: %v", result.Error)
	}
	if result.Matched {
		t.Error("chain should not match when the first gated step fails")
	}
	if secondRequestMade {
		t.Error("step2 should never have been requested once step1's matcher failed")
	}
}

func TestRun_RequestFailureIsReported(t *testing.T) {
	tpl := &Template{
		ID:       "unreachable-test",
		Info:     Info{Name: "Test", Severity: "info"},
		Requests: []RequestSpec{{Method: "GET", Path: "/", Matchers: []Matcher{{Type: "status", Status: []int{200}}}}},
	}
	result := Run(context.Background(), testClient(t), httpclient.NewRedactor(), tpl, "http://127.0.0.1:1", "test", nil)
	if result.Error == nil {
		t.Fatal("expected an error when the target is unreachable, got nil")
	}
}

func TestRun_MultiPathAllMatches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/backup.zip", "/backup.sql":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "backup-discovery",
		Info: Info{Name: "Backup File Discovery", Severity: "high"},
		Requests: []RequestSpec{{
			Method: "GET",
			Paths:  []string{"/backup.zip", "/backup.sql", "/backup.tar.gz"},
			Matchers: []Matcher{
				{Type: "status", Status: []int{200}},
			},
		}},
	}

	result := Run(context.Background(), testClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if !result.Matched {
		t.Fatal("expected the template to match")
	}
	if len(result.Findings) != 2 {
		t.Fatalf("got %d findings, want 2 (one per matching path)", len(result.Findings))
	}
}

func TestRun_MultiPathStopAtFirstMatch(t *testing.T) {
	var requestedPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "stop-first-test",
		Info: Info{Name: "Stop At First", Severity: "medium"},
		Requests: []RequestSpec{{
			Method:           "GET",
			Paths:            []string{"/a", "/b", "/c"},
			StopAtFirstMatch: true,
			Matchers:         []Matcher{{Type: "status", Status: []int{200}}},
		}},
	}

	result := Run(context.Background(), testClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("stop-at-first-match should produce exactly 1 finding, got %d", len(result.Findings))
	}
	if len(requestedPaths) != 1 {
		t.Errorf("stop-at-first-match should stop after the first hit, but %d paths were requested: %v", len(requestedPaths), requestedPaths)
	}
}

func TestRun_MultiPathNoneMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "no-match-multi",
		Info: Info{Name: "No Match", Severity: "low"},
		Requests: []RequestSpec{{
			Method:   "GET",
			Paths:    []string{"/a", "/b", "/c"},
			Matchers: []Matcher{{Type: "status", Status: []int{200}}},
		}},
	}

	result := Run(context.Background(), testClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if result.Matched {
		t.Error("expected no match when all paths return 404")
	}
	if len(result.Findings) != 0 {
		t.Errorf("got %d findings, want 0", len(result.Findings))
	}
}

func TestRun_MultiPathEachFindingHasCorrectEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "endpoint-check",
		Info: Info{Name: "Endpoint Check", Severity: "info"},
		Requests: []RequestSpec{{
			Method:   "GET",
			Paths:    []string{"/path-one", "/path-two"},
			Matchers: []Matcher{{Type: "status", Status: []int{200}}},
		}},
	}

	result := Run(context.Background(), testClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if len(result.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(result.Findings))
	}
	endpoints := map[string]bool{}
	for _, f := range result.Findings {
		endpoints[f.Endpoint] = true
	}
	if !endpoints["/path-one"] || !endpoints["/path-two"] {
		t.Errorf("findings don't carry per-path endpoints: %v", endpoints)
	}
}

// --- payload tests ---

func TestRun_SniperPayloads(t *testing.T) {
	var received []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 512)
		n, _ := r.Body.Read(body)
		received = append(received, string(body[:n]))
		w.Write([]byte("SQL syntax error near input"))
	}))
	defer srv.Close()

	// Payloads go into the POST body so raw characters (quotes, dashes)
	// don't require URL-encoding and reach the server unmodified.
	tpl := &Template{
		ID:   "sqli-sniper",
		Info: Info{Name: "SQLi Sniper", Severity: "high"},
		Payloads: map[string][]string{
			"injection": {"'", "'--"},
		},
		Requests: []RequestSpec{{
			Method:  "POST",
			Path:    "/search",
			Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body:    "q={{injection}}",
			Matchers: []Matcher{
				{Type: "word", Words: []string{"SQL syntax error"}},
			},
		}},
	}

	result := Run(context.Background(), testClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if !result.Matched {
		t.Fatal("expected the payload template to match")
	}
	if len(result.Findings) != 2 {
		t.Fatalf("got %d findings, want 2 (one per payload value)", len(result.Findings))
	}
	if len(received) != 2 {
		t.Errorf("server received %d requests, want 2", len(received))
	}
}

func TestRun_SniperPayloadPartialMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 512)
		n, _ := r.Body.Read(body)
		if strings.Contains(string(body[:n]), "'") {
			w.Write([]byte("database error"))
		} else {
			w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "sqli-partial",
		Info: Info{Name: "SQLi Partial", Severity: "high"},
		Payloads: map[string][]string{
			"injection": {"'", "harmless", "'--"},
		},
		Requests: []RequestSpec{{
			Method:  "POST",
			Path:    "/search",
			Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body:    "q={{injection}}",
			Matchers: []Matcher{
				{Type: "word", Words: []string{"database error"}},
			},
		}},
	}

	result := Run(context.Background(), testClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if !result.Matched {
		t.Fatal("expected a match on at least one payload")
	}
	// Two payloads contain a single quote; one doesn't.
	if len(result.Findings) != 2 {
		t.Fatalf("got %d findings, want 2 (two payloads trigger the error)", len(result.Findings))
	}
}

func TestRun_PitchforkPayloads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("user")
		p := r.URL.Query().Get("pass")
		if (u == "admin" && p == "password123") || (u == "guest" && p == "letmein") {
			w.Write([]byte(`{"token":"ok"}`))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	tpl := &Template{
		ID:     "pitchfork-creds",
		Info:   Info{Name: "Pitchfork Creds", Severity: "critical"},
		Attack: "pitchfork",
		Payloads: map[string][]string{
			"user": {"admin", "guest"},
			"pass": {"password123", "letmein"},
		},
		Requests: []RequestSpec{{
			Method: "GET",
			Path:   "/?user={{user}}&pass={{pass}}",
			Matchers: []Matcher{
				{Type: "word", Words: []string{"token"}},
			},
		}},
	}

	result := Run(context.Background(), testClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if !result.Matched {
		t.Fatal("expected pitchfork to find both valid credential pairs")
	}
	// Both lockstep combos match the server's exact credential check.
	if len(result.Findings) != 2 {
		t.Fatalf("got %d findings, want 2 (both pitchfork combos should match)", len(result.Findings))
	}
}

func TestRun_PitchforkStopsAtShortestSet(t *testing.T) {
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Write([]byte("matched"))
	}))
	defer srv.Close()

	// pass has 2 values; user has 3 - pitchfork stops at 2
	tpl := &Template{
		ID:     "pitchfork-truncate",
		Info:   Info{Name: "Pitchfork Truncate", Severity: "low"},
		Attack: "pitchfork",
		Payloads: map[string][]string{
			"user": {"a", "b", "c"},
			"pass": {"x", "y"},
		},
		Requests: []RequestSpec{{
			Method: "GET",
			Path:   "/?user={{user}}&pass={{pass}}",
			Matchers: []Matcher{
				{Type: "word", Words: []string{"matched"}},
			},
		}},
	}

	result := Run(context.Background(), testClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if len(result.Findings) != 2 {
		t.Fatalf("got %d findings, want 2 (capped at the shorter set length)", len(result.Findings))
	}
	if requestCount != 2 {
		t.Errorf("server received %d requests, want 2", requestCount)
	}
}

func TestGeneratePayloadCombinations_Sniper(t *testing.T) {
	tpl := &Template{
		Payloads: map[string][]string{
			"word": {"a", "b", "c"},
		},
	}
	combos := generatePayloadCombinations(tpl)
	if len(combos) != 3 {
		t.Fatalf("got %d combos, want 3", len(combos))
	}
	for i, want := range []string{"a", "b", "c"} {
		if combos[i]["word"] != want {
			t.Errorf("combo[%d][word] = %q, want %q", i, combos[i]["word"], want)
		}
	}
}

func TestGeneratePayloadCombinations_Pitchfork(t *testing.T) {
	tpl := &Template{
		Attack: "pitchfork",
		Payloads: map[string][]string{
			"user": {"alice", "bob", "carol"},
			"pass": {"p1", "p2"}, // shorter set - stops at 2
		},
	}
	combos := generatePayloadCombinations(tpl)
	if len(combos) != 2 {
		t.Fatalf("got %d combos, want 2 (stops at shortest set)", len(combos))
	}
	if combos[0]["user"] != "alice" || combos[0]["pass"] != "p1" {
		t.Errorf("combo[0] = %v, want {user:alice pass:p1}", combos[0])
	}
	if combos[1]["user"] != "bob" || combos[1]["pass"] != "p2" {
		t.Errorf("combo[1] = %v, want {user:bob pass:p2}", combos[1])
	}
}

func TestGeneratePayloadCombinations_NoPayloads(t *testing.T) {
	tpl := &Template{
		Requests: []RequestSpec{{Method: "GET", Path: "/"}},
	}
	if combos := generatePayloadCombinations(tpl); combos != nil {
		t.Errorf("expected nil for template with no payloads, got %v", combos)
	}
}

func TestGeneratePayloadCombinations_Clusterbomb(t *testing.T) {
	tpl := &Template{
		Attack: "clusterbomb",
		Payloads: map[string][]string{
			"user": {"alice", "bob"},
			"pass": {"x", "y", "z"},
		},
	}
	combos := generatePayloadCombinations(tpl)
	// Cartesian product: 2 users × 3 passwords = 6 combos.
	if len(combos) != 6 {
		t.Fatalf("got %d combos, want 6 (2 × 3 Cartesian product)", len(combos))
	}
	// Every combo must have both keys set.
	for i, c := range combos {
		if c["user"] == "" || c["pass"] == "" {
			t.Errorf("combo[%d] missing a key: %v", i, c)
		}
	}
	// Every (user, pass) pair must appear exactly once.
	seen := make(map[string]int)
	for _, c := range combos {
		key := c["user"] + ":" + c["pass"]
		seen[key]++
	}
	for _, u := range []string{"alice", "bob"} {
		for _, p := range []string{"x", "y", "z"} {
			if seen[u+":"+p] != 1 {
				t.Errorf("pair (%s,%s) appears %d times, want 1", u, p, seen[u+":"+p])
			}
		}
	}
}

func TestRun_ClusterbombPayloads(t *testing.T) {
	type pair struct{ user, pass string }
	var received []pair

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = append(received, pair{
			user: r.URL.Query().Get("user"),
			pass: r.URL.Query().Get("pass"),
		})
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tpl := &Template{
		ID:     "clusterbomb-test",
		Info:   Info{Name: "Clusterbomb", Severity: "low"},
		Attack: "clusterbomb",
		Payloads: map[string][]string{
			"user": {"admin", "guest"},
			"pass": {"p1", "p2"},
		},
		Requests: []RequestSpec{{
			Method:   "GET",
			Path:     "/?user={{user}}&pass={{pass}}",
			Matchers: []Matcher{{Type: "word", Words: []string{"ok"}}},
		}},
	}

	result := Run(context.Background(), testClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	// 2 users × 2 passwords = 4 combos; all return "ok" so 4 findings.
	if len(result.Findings) != 4 {
		t.Fatalf("got %d findings, want 4 (2×2 Cartesian product)", len(result.Findings))
	}
	if len(received) != 4 {
		t.Errorf("server received %d requests, want 4", len(received))
	}
}

// --- when (conditional steps) tests ---

func TestRun_WhenSkipsStep(t *testing.T) {
	var step2Called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			// Return empty token — when condition on step2 should block it.
			w.Write([]byte(`{"token":""}`))
		case "/step2":
			step2Called = true
			w.Write([]byte("reached"))
		}
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "when-skip",
		Info: Info{Name: "When Skip", Severity: "info"},
		Requests: []RequestSpec{
			{
				Method:     "GET",
				Path:       "/login",
				Extractors: []Extractor{{Type: "json", Name: "token", Path: "$.token"}},
			},
			{
				// token was extracted as empty string; when should skip this step.
				When:     `token != ""`,
				Method:   "GET",
				Path:     "/step2",
				Matchers: []Matcher{{Type: "word", Words: []string{"reached"}}},
			},
		},
	}

	result := Run(context.Background(), testClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if step2Called {
		t.Error("step2 should have been skipped by the when condition, but it ran")
	}
	if result.Matched {
		t.Error("template should not match when the final step was skipped")
	}
}

func TestRun_WhenRunsStep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			w.Write([]byte(`{"token":"abc123"}`))
		case "/admin":
			w.Write([]byte("admin panel"))
		}
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "when-run",
		Info: Info{Name: "When Run", Severity: "medium"},
		Requests: []RequestSpec{
			{
				Method:     "GET",
				Path:       "/login",
				Extractors: []Extractor{{Type: "json", Name: "token", Path: "$.token"}},
			},
			{
				When:     `token != ""`,
				Method:   "GET",
				Path:     "/admin",
				Matchers: []Matcher{{Type: "word", Words: []string{"admin panel"}}},
			},
		},
	}

	result := Run(context.Background(), testClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if !result.Matched {
		t.Error("expected template to match: token was set so the when condition should pass and step2 should run")
	}
}

// --- global matcher hook tests ---

func TestRun_PassiveFindingsFromHook(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"key":"AKIAIOSFODNN7EXAMPLE"}`))
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "hook-test",
		Info: Info{Name: "Hook Test", Severity: "info"},
		Requests: []RequestSpec{{
			Method: "GET",
			Path:   "/config",
			// no matchers — exists purely to trigger the hook
		}},
	}

	called := false
	hook := ResponseHook(func(resp *httpclient.Response, target, environment, path string) []findings.Finding {
		called = true
		if strings.Contains(string(resp.Body), "AKIA") {
			return []findings.Finding{{
				ID: "hook-finding", Name: "AWS Key", Severity: "high",
				Target: target, Endpoint: path,
			}}
		}
		return nil
	})

	result := Run(context.Background(), testClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil, hook)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if !called {
		t.Error("ResponseHook was not called")
	}
	if len(result.PassiveFindings) != 1 {
		t.Fatalf("got %d passive findings, want 1", len(result.PassiveFindings))
	}
	if result.PassiveFindings[0].ID != "hook-finding" {
		t.Errorf("unexpected passive finding ID: %q", result.PassiveFindings[0].ID)
	}
}
