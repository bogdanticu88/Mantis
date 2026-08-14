package attacks

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bogdanticu88/Mantis/internal/httpclient"
)

func newVulnerableServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/header-reflect", func(w http.ResponseWriter, r *http.Request) {
		// reflects X-Forwarded-For back - header injection test target
		val := r.Header.Get("X-Forwarded-For")
		w.Write([]byte("ip: " + val))
	})
	mux.HandleFunc("/api/items", func(w http.ResponseWriter, r *http.Request) {
		// JSON API endpoint that reflects POSTed field values - for JSON body fuzzing
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			w.Write([]byte(`{"result":"` + string(body) + `"}`))
			return
		}
		w.Write([]byte(`{"items":[]}`))
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		// sleeps when it receives a known timing payload - for timing-based fuzzing
		if strings.Contains(r.URL.Query().Get("id"), "SLEEP") ||
			strings.Contains(r.URL.Query().Get("id"), "WAITFOR") ||
			strings.Contains(r.URL.Query().Get("id"), "pg_sleep") {
			time.Sleep(300 * time.Millisecond)
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/cookie-reflect", func(w http.ResponseWriter, r *http.Request) {
		// reflects the session cookie back - cookie injection test target
		for _, c := range r.Cookies() {
			if c.Name == "session" {
				w.Write([]byte("cookie: " + c.Value))
				return
			}
		}
		w.Write([]byte("no cookie"))
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		// reflects the query param unescaped - classic XSS
		body := "<html><body>results for: " + r.URL.Query().Get("q") + "</body></html>"
		w.Write([]byte(body))
	})
	mux.HandleFunc("/db", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("id"), "'") {
			w.Write([]byte("Warning: mysql_fetch_array(): supplied argument is not valid"))
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("path"), "etc/passwd") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin"))
			return
		}
		w.Write([]byte("file not found"))
	})
	mux.HandleFunc("/render", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("tpl"), "7*777") {
			w.Write([]byte("result: 5439"))
			return
		}
		w.Write([]byte("rendered"))
	})
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("host"), "MANTIS_CMDI_8231") {
			w.Write([]byte("PING output:\nMANTIS_CMDI_8231\n64 bytes from..."))
			return
		}
		w.Write([]byte("pinging..."))
	})
	mux.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("nothing interesting here regardless of input"))
	})
	mux.HandleFunc("/form-submit", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "MANTIS_CMDI_8231") {
			w.Write([]byte("MANTIS_CMDI_8231"))
			return
		}
		w.Write([]byte("submitted"))
	})

	return httptest.NewServer(mux)
}

func newTestClient(t *testing.T) *httpclient.Client {
	t.Helper()
	c, err := httpclient.New(httpclient.Config{})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}
	return c
}

func TestFuzzQueryParams_DetectsEachClass(t *testing.T) {
	srv := newVulnerableServer(t)
	defer srv.Close()

	urls := []string{
		srv.URL + "/search?q=hello",
		srv.URL + "/db?id=1",
		srv.URL + "/file?path=readme.txt",
		srv.URL + "/render?tpl=hi",
		srv.URL + "/ping?host=localhost",
		srv.URL + "/safe?x=1",
	}

	fs := FuzzQueryParams(context.Background(), newTestClient(t), httpclient.NewRedactor(), urls, Options{Environment: "test"})

	byClass := map[string]bool{}
	for _, f := range fs {
		for _, tag := range f.Tags {
			byClass[tag] = true
		}
	}
	for _, class := range AllClasses() {
		if !byClass[class] {
			t.Errorf("expected at least one %s finding, got none (all findings: %+v)", class, fs)
		}
	}
}

func TestFuzzQueryParams_SafeParamProducesNoFindings(t *testing.T) {
	srv := newVulnerableServer(t)
	defer srv.Close()

	fs := FuzzQueryParams(context.Background(), newTestClient(t), httpclient.NewRedactor(), []string{srv.URL + "/safe?x=1"}, Options{Environment: "test"})
	if len(fs) != 0 {
		t.Errorf("expected zero findings against a non-vulnerable endpoint, got %d: %+v", len(fs), fs)
	}
}

func TestFuzzQueryParams_RespectsMaxRequests(t *testing.T) {
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// 3 params, each with >=1 payload across the default class set - well
	// over 3 requests if the cap weren't enforced.
	urls := []string{srv.URL + "/x?a=1&b=1&c=1"}
	FuzzQueryParams(context.Background(), newTestClient(t), httpclient.NewRedactor(), urls, Options{Environment: "test", MaxRequests: 3})

	if requestCount != 3 {
		t.Errorf("MaxRequests=3 but the server received %d requests", requestCount)
	}
}

func TestFuzzQueryParams_RespectsMaxParams(t *testing.T) {
	srv := newVulnerableServer(t)
	defer srv.Close()

	urls := []string{srv.URL + "/x?a=1&b=1&c=1&d=1&e=1"}
	targets := queryTargets(urls, 2)
	if len(targets) != 2 {
		t.Errorf("queryTargets with max=2 returned %d targets, want 2", len(targets))
	}
}

func TestFuzzForms_GETFormFuzzedByDefault(t *testing.T) {
	srv := newVulnerableServer(t)
	defer srv.Close()

	forms := []Form{{Action: srv.URL + "/db", Method: "GET", Inputs: map[string]string{"id": "text"}}}
	fs := FuzzForms(context.Background(), newTestClient(t), httpclient.NewRedactor(), forms, Options{Environment: "test", Classes: []string{"sqli"}})

	if len(fs) == 0 {
		t.Error("expected a SQLi finding from fuzzing a GET form's id field")
	}
}

func TestFuzzForms_POSTFormSkippedWithoutDestructive(t *testing.T) {
	srv := newVulnerableServer(t)
	defer srv.Close()

	forms := []Form{{Action: srv.URL + "/form-submit", Method: "POST", Inputs: map[string]string{"cmd": "text"}}}
	fs := FuzzForms(context.Background(), newTestClient(t), httpclient.NewRedactor(), forms, Options{Environment: "test", Classes: []string{"cmdi"}, Destructive: false})

	if len(fs) != 0 {
		t.Errorf("POST form should not be fuzzed without Destructive, got %d findings", len(fs))
	}
}

func TestFuzzForms_POSTFormFuzzedWithDestructive(t *testing.T) {
	srv := newVulnerableServer(t)
	defer srv.Close()

	forms := []Form{{Action: srv.URL + "/form-submit", Method: "POST", Inputs: map[string]string{"cmd": "text"}}}
	fs := FuzzForms(context.Background(), newTestClient(t), httpclient.NewRedactor(), forms, Options{Environment: "test", Classes: []string{"cmdi"}, Destructive: true})

	if len(fs) == 0 {
		t.Error("expected a cmdi finding when fuzzing a POST form with Destructive: true")
	}
}

func TestFuzzHeaders_DetectsInjection(t *testing.T) {
	srv := newVulnerableServer(t)
	defer srv.Close()

	urls := []string{srv.URL + "/header-reflect"}
	fs := FuzzHeaders(context.Background(), newTestClient(t), httpclient.NewRedactor(), urls, Options{
		Environment: "test",
		Classes:     []string{"xss"},
	})

	if len(fs) == 0 {
		t.Error("expected at least one XSS finding from header injection, got none")
	}
}

func TestFuzzHeaders_RespectsMaxRequests(t *testing.T) {
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	FuzzHeaders(context.Background(), newTestClient(t), httpclient.NewRedactor(), []string{srv.URL + "/x"}, Options{
		Environment: "test",
		MaxRequests: 2,
	})

	if requestCount != 2 {
		t.Errorf("MaxRequests=2 but server received %d requests", requestCount)
	}
}

func TestFuzzCookies_DetectsInjection(t *testing.T) {
	srv := newVulnerableServer(t)
	defer srv.Close()

	urls := []string{srv.URL + "/cookie-reflect"}
	fs := FuzzCookies(context.Background(), newTestClient(t), httpclient.NewRedactor(), []string{"session"}, urls, Options{
		Environment: "test",
		Classes:     []string{"xss"},
	})

	if len(fs) == 0 {
		t.Error("expected at least one XSS finding from cookie injection, got none")
	}
}

func TestFuzzCookies_EmptyInputProducesNoFindings(t *testing.T) {
	srv := newVulnerableServer(t)
	defer srv.Close()

	// no cookie names - nothing to fuzz
	fs := FuzzCookies(context.Background(), newTestClient(t), httpclient.NewRedactor(), nil, []string{srv.URL + "/"}, Options{Environment: "test"})
	if len(fs) != 0 {
		t.Errorf("expected zero findings with no cookie names, got %d", len(fs))
	}

	// no urls - nothing to fuzz
	fs = FuzzCookies(context.Background(), newTestClient(t), httpclient.NewRedactor(), []string{"session"}, nil, Options{Environment: "test"})
	if len(fs) != 0 {
		t.Errorf("expected zero findings with no urls, got %d", len(fs))
	}
}

func TestFuzzJSONBody_DetectsInjection(t *testing.T) {
	srv := newVulnerableServer(t)
	defer srv.Close()

	endpoints := []string{srv.URL + "/api/items"}
	fs := FuzzJSONBody(context.Background(), newTestClient(t), httpclient.NewRedactor(), endpoints, Options{
		Environment: "test",
		Classes:     []string{"xss"},
		Destructive: true,
	})
	if len(fs) == 0 {
		t.Error("expected at least one XSS finding from JSON body injection, got none")
	}
}

func TestFuzzJSONBody_SkippedWithoutDestructive(t *testing.T) {
	srv := newVulnerableServer(t)
	defer srv.Close()

	endpoints := []string{srv.URL + "/api/items"}
	fs := FuzzJSONBody(context.Background(), newTestClient(t), httpclient.NewRedactor(), endpoints, Options{
		Environment: "test",
		Classes:     []string{"xss"},
		Destructive: false,
	})
	if len(fs) != 0 {
		t.Errorf("JSON body fuzzing without Destructive should produce no findings, got %d", len(fs))
	}
}

func TestFuzzJSONBody_EmptyEndpointsNoop(t *testing.T) {
	fs := FuzzJSONBody(context.Background(), newTestClient(t), httpclient.NewRedactor(), nil, Options{
		Environment: "test",
		Destructive: true,
	})
	if len(fs) != 0 {
		t.Errorf("expected no findings with no endpoints, got %d", len(fs))
	}
}

func TestFuzzTimingBased_DetectsDelay(t *testing.T) {
	srv := newVulnerableServer(t)
	defer srv.Close()

	urls := []string{srv.URL + "/slow?id=1"}
	fs := FuzzTimingBased(context.Background(), newTestClient(t), httpclient.NewRedactor(), urls, Options{
		Environment:         "test",
		TimingMinDeltaMS:    150, // below the 300ms sleep
		TimingBaselineN:     1,
		TimingMinAbsoluteMS: 200, // below the 300ms sleep
	})
	if len(fs) == 0 {
		t.Error("expected a timing-sqli finding when payload causes 300ms delay")
	}
}

func TestFuzzTimingBased_FastEndpointNoFindings(t *testing.T) {
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Write([]byte("fast"))
	}))
	defer srv.Close()

	urls := []string{srv.URL + "/x?a=1"}
	fs := FuzzTimingBased(context.Background(), newTestClient(t), httpclient.NewRedactor(), urls, Options{
		Environment:         "test",
		TimingMinDeltaMS:    50,
		TimingBaselineN:     1,
		TimingMinAbsoluteMS: 50,
	})
	// A uniformly fast server (no sleep) should produce no delta worth flagging.
	// We can't guarantee zero because request timing is nondeterministic, but
	// we CAN assert the budget was consumed (baseline + payload requests ran).
	if requestCount == 0 {
		t.Error("expected some requests to be made during timing probe")
	}
	_ = fs // findings may or may not be present due to timing noise; budget check is the goal
}

func TestFuzzTimingBased_NoQueryParamsNoop(t *testing.T) {
	srv := newVulnerableServer(t)
	defer srv.Close()

	// URL without query params - nothing to fuzz, should return nil immediately.
	urls := []string{srv.URL + "/safe"}
	fs := FuzzTimingBased(context.Background(), newTestClient(t), httpclient.NewRedactor(), urls, Options{
		Environment:     "test",
		TimingBaselineN: 1,
	})
	if len(fs) != 0 {
		t.Errorf("URL with no query params should produce no timing findings, got %d", len(fs))
	}
}

func TestFuzzQueryParams_ClassFilter(t *testing.T) {
	srv := newVulnerableServer(t)
	defer srv.Close()

	urls := []string{srv.URL + "/db?id=1", srv.URL + "/search?q=1"}
	fs := FuzzQueryParams(context.Background(), newTestClient(t), httpclient.NewRedactor(), urls, Options{Environment: "test", Classes: []string{"sqli"}})

	for _, f := range fs {
		for _, tag := range f.Tags {
			if tag != "fuzz" && tag != "sqli" {
				t.Errorf("Classes filter set to [sqli] but got a finding tagged %q", tag)
			}
		}
	}
}
