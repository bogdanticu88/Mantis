package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestInScope(t *testing.T) {
	c, err := New(Config{AllowedHosts: []string{"example.com", "*.internal.example.com"}, DeniedHosts: []string{"blocked.example.com"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := map[string]bool{
		"example.com":              true,
		"EXAMPLE.COM":              true, // case-insensitive
		"api.internal.example.com": true, // wildcard subdomain match
		"internal.example.com":     true, // the wildcard's own base domain
		"blocked.example.com":      false,
		"evil.com":                 false,
		"notexample.com":           false, // must not match as a suffix of a different domain
	}
	for host, want := range cases {
		if got := c.InScope(host); got != want {
			t.Errorf("InScope(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestInScope_DenyOverridesNothingButAllowIsRequiredFirst(t *testing.T) {
	// A denied host should never be reachable even if AllowedHosts is empty
	// (meaning "no allowlist restriction").
	c, err := New(Config{DeniedHosts: []string{"blocked.example.com"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.InScope("blocked.example.com") {
		t.Error("a denied host should never be in scope, even with no allowlist configured")
	}
	if !c.InScope("anything-else.com") {
		t.Error("with no allowlist, any non-denied host should be in scope")
	}
}

func TestDo_OutOfScopeRequestIsRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should never be reached"))
	}))
	defer srv.Close()

	c, err := New(Config{AllowedHosts: []string{"not-the-test-server.example.com"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = c.Do(context.Background(), Request{Method: "GET", URL: srv.URL})
	if err == nil {
		t.Fatal("request to an out-of-scope host should have been rejected")
	}
	if _, ok := err.(ErrOutOfScope); !ok {
		t.Errorf("error = %v (%T), want ErrOutOfScope", err, err)
	}
}

func TestDo_RedirectLimit(t *testing.T) {
	var hops int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer srv.Close()

	c, err := New(Config{MaxRedirects: 2})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	resp, err := c.Do(context.Background(), Request{Method: "GET", URL: srv.URL})
	// Go's http.Client treats "too many redirects" as an error rather than
	// returning the last response, so this should surface as an error.
	if err == nil {
		t.Fatalf("expected redirect-limit error, got a response with status %d", resp.StatusCode)
	}
}

func TestDo_NoRedirectsFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer srv.Close()

	c, err := New(Config{MaxRedirects: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	resp, err := c.Do(context.Background(), Request{Method: "GET", URL: srv.URL})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Errorf("StatusCode = %d, want 302 (redirect not followed)", resp.StatusCode)
	}
}

func TestDo_MaxResponseBytesTruncates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 1000))
	}))
	defer srv.Close()

	c, err := New(Config{MaxResponseBytes: 100})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resp, err := c.Do(context.Background(), Request{Method: "GET", URL: srv.URL})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(resp.Body) != 100 {
		t.Errorf("Body length = %d, want 100 (truncated)", len(resp.Body))
	}
	if !resp.Truncated {
		t.Error("Truncated flag should be true")
	}
}

func TestDo_ConcurrencyLimit(t *testing.T) {
	// Not a precise timing test - just confirms MaxConcurrency doesn't
	// deadlock or drop requests under a small burst.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c, err := New(Config{MaxConcurrency: 2, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	done := make(chan error, 5)
	for i := 0; i < 5; i++ {
		go func() {
			_, err := c.Do(context.Background(), Request{Method: "GET", URL: srv.URL})
			done <- err
		}()
	}
	for i := 0; i < 5; i++ {
		if err := <-done; err != nil {
			t.Errorf("request %d failed: %v", i, err)
		}
	}
}

func TestRedactor_Exchange(t *testing.T) {
	r := NewRedactor("super-secret-token")
	resp := &Response{
		Request: Request{
			Method:  "GET",
			URL:     "https://example.com/",
			Headers: map[string]string{"Authorization": "Bearer super-secret-token", "X-Custom": "keep-me"},
		},
		StatusCode: 200,
		Headers:    http.Header{"Set-Cookie": []string{"session=abc"}, "X-Reflects-Token": []string{"super-secret-token"}},
		Body:       []byte(`{"note": "token is super-secret-token here too"}`),
	}

	ex := r.Exchange(resp)

	if ex.RequestHeaders["Authorization"] != redactedPlaceholder {
		t.Errorf("Authorization header not redacted: %q", ex.RequestHeaders["Authorization"])
	}
	if ex.RequestHeaders["X-Custom"] != "keep-me" {
		t.Errorf("non-sensitive header should pass through unredacted, got %q", ex.RequestHeaders["X-Custom"])
	}
	if ex.ResponseHeaders["Set-Cookie"] != redactedPlaceholder {
		t.Errorf("Set-Cookie header not redacted: %q", ex.ResponseHeaders["Set-Cookie"])
	}
	if ex.ResponseHeaders["X-Reflects-Token"] != redactedPlaceholder {
		t.Errorf("a literal secret value reflected in a non-sensitive header should still be scrubbed, got %q", ex.ResponseHeaders["X-Reflects-Token"])
	}
	if got := ex.ResponseBody; got == `{"note": "token is super-secret-token here too"}` {
		t.Error("secret value should have been scrubbed from the response body")
	}
}
