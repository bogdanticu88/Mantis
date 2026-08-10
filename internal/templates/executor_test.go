package templates

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"mantis/internal/httpclient"
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
