package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"mantis/internal/httpclient"
)

func newTestClient(t *testing.T) *httpclient.Client {
	t.Helper()
	c, err := httpclient.New(httpclient.Config{})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}
	return c
}

func TestCheckMissingAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // never enforces auth
	}))
	defer srv.Close()

	spec := &Spec{Endpoints: []Endpoint{
		{Path: "/secure", Method: "GET", RequiresAuth: true},
		{Path: "/public", Method: "GET", RequiresAuth: false},
	}}
	opts := Options{Target: srv.URL, Environment: "test"}
	fs := Run(context.Background(), newTestClient(t), httpclient.NewRedactor(), spec, opts)

	found := false
	for _, f := range fs {
		if f.ID == "MANTIS-API-MISSING-AUTH" && f.Endpoint == "/secure" {
			found = true
		}
		if f.Endpoint == "/public" && f.ID == "MANTIS-API-MISSING-AUTH" {
			t.Error("missing-auth check fired on an endpoint that never declared a security requirement")
		}
	}
	if !found {
		t.Error("expected a missing-auth finding for /secure, which declares RequiresAuth but the server never checks it")
	}
}

func TestCheckMissingAuth_EnforcedEndpointDoesNotFire(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	spec := &Spec{Endpoints: []Endpoint{{Path: "/secure", Method: "GET", RequiresAuth: true}}}
	fs := Run(context.Background(), newTestClient(t), httpclient.NewRedactor(), spec, Options{Target: srv.URL})

	for _, f := range fs {
		if f.ID == "MANTIS-API-MISSING-AUTH" {
			t.Error("missing-auth check fired on an endpoint that correctly rejects unauthenticated requests")
		}
	}
}

func TestCheckMethodAbuse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// DELETE isn't declared for this path but the server happily accepts it anyway
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	spec := &Spec{Endpoints: []Endpoint{{Path: "/resource", Method: "GET"}}}
	fs := Run(context.Background(), newTestClient(t), httpclient.NewRedactor(), spec, Options{Target: srv.URL, Destructive: true})

	found := false
	for _, f := range fs {
		if f.ID == "MANTIS-API-METHOD-ABUSE" {
			found = true
		}
	}
	if !found {
		t.Error("expected a method-abuse finding for an undeclared method the server accepts")
	}
}

func TestCheckMethodAbuse_DestructiveMethodsSkippedByDefault(t *testing.T) {
	var deleteWasCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			deleteWasCalled = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	spec := &Spec{Endpoints: []Endpoint{{Path: "/resource", Method: "GET"}}}
	Run(context.Background(), newTestClient(t), httpclient.NewRedactor(), spec, Options{Target: srv.URL, Destructive: false})

	if deleteWasCalled {
		t.Error("DELETE should not have been probed without --destructive")
	}
}

func TestCheckBOLA_TwoSuccessfulResponsesFlagACandidate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // returns 200 for any id, regardless of "ownership"
	}))
	defer srv.Close()

	spec := &Spec{Endpoints: []Endpoint{{
		Path: "/accounts/{id}", Method: "GET", RequiresAuth: true,
		Parameters: []Parameter{{Name: "id", In: "path"}},
	}}}
	opts := Options{Target: srv.URL, AuthHeaders: map[string]string{"Authorization": "Bearer sometoken"}}
	fs := Run(context.Background(), newTestClient(t), httpclient.NewRedactor(), spec, opts)

	found := false
	for _, f := range fs {
		if f.ID == "MANTIS-API-BOLA-CANDIDATE" {
			found = true
			if f.Confidence >= 1.0 {
				t.Errorf("BOLA heuristic confidence = %v, want reduced (< 1.0) since it can't prove ownership without a second identity", f.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected a BOLA candidate finding when both sample ids return 200")
	}
}

func TestCheckBOLA_SkippedWithoutAuthHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	spec := &Spec{Endpoints: []Endpoint{{
		Path: "/accounts/{id}", Method: "GET", RequiresAuth: true,
		Parameters: []Parameter{{Name: "id", In: "path"}},
	}}}
	fs := Run(context.Background(), newTestClient(t), httpclient.NewRedactor(), spec, Options{Target: srv.URL}) // no AuthHeaders

	for _, f := range fs {
		if f.ID == "MANTIS-API-BOLA-CANDIDATE" {
			t.Error("BOLA heuristic should not run at all without auth headers to test with")
		}
	}
}

func TestCheckSensitiveData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id": "u1", "password": "hunter2", "name": "irrelevant"}`))
	}))
	defer srv.Close()

	spec := &Spec{Endpoints: []Endpoint{{Path: "/me", Method: "GET"}}}
	fs := Run(context.Background(), newTestClient(t), httpclient.NewRedactor(), spec, Options{Target: srv.URL})

	found := false
	for _, f := range fs {
		if f.ID == "MANTIS-API-SENSITIVE-DATA" {
			found = true
		}
	}
	if !found {
		t.Error("expected a sensitive-data finding for a response body containing a password field")
	}
}

func TestCheckSensitiveData_CleanResponseDoesNotFire(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id": "u1", "name": "just a name"}`))
	}))
	defer srv.Close()

	spec := &Spec{Endpoints: []Endpoint{{Path: "/me", Method: "GET"}}}
	fs := Run(context.Background(), newTestClient(t), httpclient.NewRedactor(), spec, Options{Target: srv.URL})

	for _, f := range fs {
		if f.ID == "MANTIS-API-SENSITIVE-DATA" {
			t.Error("sensitive-data check fired on a response with no sensitive-looking keys")
		}
	}
}
