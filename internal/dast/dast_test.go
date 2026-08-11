package dast

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"mantis/internal/environments"
	"mantis/internal/httpclient"
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
