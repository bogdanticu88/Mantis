package dast

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bogdanticu88/Mantis/internal/environments"
	"github.com/bogdanticu88/Mantis/internal/httpclient"
)

func TestRun_FuzzingSurfacesThroughActiveFindings(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/db?id=1">DB</a></body></html>`))
	})
	mux.HandleFunc("/db", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("id"), "'") {
			w.Write([]byte("Warning: mysql_fetch_array(): supplied argument is not valid"))
			return
		}
		w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	host, _ := url.Parse(srv.URL)

	client, err := httpclient.New(httpclient.Config{AllowedHosts: []string{host.Hostname()}})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}

	result, err := Run(context.Background(), client, httpclient.NewRedactor(), Options{
		Target:      srv.URL,
		Environment: "test",
		Policy:      environments.PolicyFor(string(environments.LevelAggressive)),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	found := false
	for _, f := range result.ActiveFindings {
		if f.ID == "MANTIS-FUZZ-sqli" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a fuzzing-derived SQLi finding to surface in ActiveFindings, got: %+v", result.ActiveFindings)
	}
}

func TestRun_PassivePolicySkipsFuzzingEntirely(t *testing.T) {
	var dbEndpointHit bool
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/db?id=1">DB</a></body></html>`))
	})
	mux.HandleFunc("/db", func(w http.ResponseWriter, r *http.Request) {
		dbEndpointHit = strings.Contains(r.URL.RawQuery, "%27") || strings.Contains(r.URL.RawQuery, "'")
		w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	host, _ := url.Parse(srv.URL)

	client, err := httpclient.New(httpclient.Config{AllowedHosts: []string{host.Hostname()}})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}

	result, err := Run(context.Background(), client, httpclient.NewRedactor(), Options{
		Target:      srv.URL,
		Environment: "test",
		Policy:      environments.PolicyFor(string(environments.LevelPassive)),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(result.ActiveFindings) != 0 {
		t.Errorf("passive policy should produce zero active findings, got %d", len(result.ActiveFindings))
	}
	if dbEndpointHit {
		t.Error("passive policy should never send a fuzzing payload, but /db received one")
	}
}

// This is the double-gate: an environment's security_level: aggressive
// (Policy.Destructive: true) authorizes destructive testing in principle,
// but must NOT by itself run it - Options.Destructive is the second,
// explicit gate cmd/mantis only sets when --destructive was passed on that
// specific invocation. One YAML line should never be enough, forever, to
// make every future run start submitting forms.
func newFormServer(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	var submitCount int
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><form method="POST" action="/submit"><input name="cmd"></form></body></html>`))
	})
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		submitCount++
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "MANTIS_CMDI_8231") {
			w.Write([]byte("MANTIS_CMDI_8231"))
			return
		}
		w.Write([]byte("submitted"))
	})
	return httptest.NewServer(mux), &submitCount
}

func TestRun_FormFuzzingRequiresExplicitDestructiveFlag(t *testing.T) {
	srv, submitCount := newFormServer(t)
	defer srv.Close()
	host, _ := url.Parse(srv.URL)
	client, err := httpclient.New(httpclient.Config{AllowedHosts: []string{host.Hostname()}})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}

	result, err := Run(context.Background(), client, httpclient.NewRedactor(), Options{
		Target:      srv.URL,
		Environment: "test",
		Policy:      environments.PolicyFor(string(environments.LevelAggressive)), // Policy.Destructive: true
		Destructive: false,                                                        // but --destructive was NOT passed on this run
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if *submitCount != 0 {
		t.Errorf("the POST form should never have been submitted without Options.Destructive, but /submit was hit %d time(s)", *submitCount)
	}
	for _, f := range result.ActiveFindings {
		if f.ID == "MANTIS-FUZZ-cmdi" {
			t.Error("got a cmdi finding from form fuzzing despite Options.Destructive being false")
		}
	}
}

func TestRun_FormFuzzingRunsWithBothGatesOpen(t *testing.T) {
	srv, submitCount := newFormServer(t)
	defer srv.Close()
	host, _ := url.Parse(srv.URL)
	client, err := httpclient.New(httpclient.Config{AllowedHosts: []string{host.Hostname()}})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}

	result, err := Run(context.Background(), client, httpclient.NewRedactor(), Options{
		Target:      srv.URL,
		Environment: "test",
		Policy:      environments.PolicyFor(string(environments.LevelAggressive)),
		Destructive: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if *submitCount == 0 {
		t.Error("expected the POST form to be submitted with both Policy.Destructive and Options.Destructive true")
	}
	found := false
	for _, f := range result.ActiveFindings {
		if f.ID == "MANTIS-FUZZ-cmdi" {
			found = true
		}
	}
	if !found {
		t.Error("expected a cmdi finding from form fuzzing with both gates open")
	}
}
