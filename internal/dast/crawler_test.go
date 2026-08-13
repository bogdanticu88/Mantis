package dast

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/bogdanticu88/Mantis/internal/httpclient"
)

// pages is a tiny link graph used across the crawler tests:
//
//	/            -> /about, /contact, an out-of-scope external link
//	/about       -> /deep1
//	/deep1       -> /deep2
//	/deep2       -> /deep3
//	/contact     -> a POST form
//	/data.json   -> not HTML, has an <a href> looking string in the body
//	                that must NOT be followed as a real link
func newGraphServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>
			<a href="/about">About</a>
			<a href="/contact">Contact</a>
			<a href="http://evil.example.com/">External</a>
		</body></html>`))
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/deep1">Deep 1</a></body></html>`))
	})
	mux.HandleFunc("/deep1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/deep2">Deep 2</a></body></html>`))
	})
	mux.HandleFunc("/deep2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/deep3">Deep 3</a></body></html>`))
	})
	mux.HandleFunc("/deep3", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>bottom of the graph</body></html>`))
	})
	mux.HandleFunc("/contact", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>
			<form method="POST" action="/submit">
				<input type="text" name="name">
				<input type="email" name="email">
			</form>
		</body></html>`))
	})
	mux.HandleFunc("/data.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"note": "<a href=\"/should-not-be-followed\">not a real link</a>"}`))
	})
	return httptest.NewServer(mux)
}

func newScopedClient(t *testing.T, host string) *httpclient.Client {
	t.Helper()
	c, err := httpclient.New(httpclient.Config{AllowedHosts: []string{host}})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}
	return c
}

func containsURL(urls []string, suffix string) bool {
	for _, u := range urls {
		if len(u) >= len(suffix) && u[len(u)-len(suffix):] == suffix {
			return true
		}
	}
	return false
}

func TestCrawl_DiscoversLinkedPages(t *testing.T) {
	srv := newGraphServer(t)
	defer srv.Close()
	host, _ := url.Parse(srv.URL)

	crawler := &Crawler{Client: newScopedClient(t, host.Hostname()), MaxDepth: 3, MaxRequests: 20}
	surface, _, err := crawler.Crawl(context.Background(), srv.URL, "test", httpclient.NewRedactor())
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	for _, want := range []string{"", "/about", "/contact"} {
		if !containsURL(surface.URLs, want) {
			t.Errorf("expected %q to be discovered, got URLs: %v", want, surface.URLs)
		}
	}
}

func TestCrawl_RespectsMaxDepth(t *testing.T) {
	srv := newGraphServer(t)
	defer srv.Close()
	host, _ := url.Parse(srv.URL)

	// depth 0 = seed, depth 1 = /about, depth 2 = /deep1, depth 3 = /deep2.
	// /deep3 is depth 4 and should never be reached.
	crawler := &Crawler{Client: newScopedClient(t, host.Hostname()), MaxDepth: 2, MaxRequests: 20}
	surface, _, err := crawler.Crawl(context.Background(), srv.URL, "test", httpclient.NewRedactor())
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if containsURL(surface.URLs, "/deep3") {
		t.Errorf("/deep3 should be beyond MaxDepth=2, but was discovered: %v", surface.URLs)
	}
}

func TestCrawl_RespectsMaxRequests(t *testing.T) {
	srv := newGraphServer(t)
	defer srv.Close()
	host, _ := url.Parse(srv.URL)

	crawler := &Crawler{Client: newScopedClient(t, host.Hostname()), MaxDepth: 10, MaxRequests: 2}
	surface, _, err := crawler.Crawl(context.Background(), srv.URL, "test", httpclient.NewRedactor())
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(surface.URLs) > 2 {
		t.Errorf("MaxRequests=2 but %d URLs were fetched: %v", len(surface.URLs), surface.URLs)
	}
}

func TestCrawl_DoesNotFollowOutOfScopeLinks(t *testing.T) {
	srv := newGraphServer(t)
	defer srv.Close()
	host, _ := url.Parse(srv.URL)

	crawler := &Crawler{Client: newScopedClient(t, host.Hostname()), MaxDepth: 3, MaxRequests: 20}
	surface, _, err := crawler.Crawl(context.Background(), srv.URL, "test", httpclient.NewRedactor())
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	for _, u := range surface.URLs {
		if u == "http://evil.example.com/" {
			t.Error("out-of-scope link was followed and fetched")
		}
	}
}

func TestCrawl_ExtractsForms(t *testing.T) {
	srv := newGraphServer(t)
	defer srv.Close()
	host, _ := url.Parse(srv.URL)

	crawler := &Crawler{Client: newScopedClient(t, host.Hostname()), MaxDepth: 3, MaxRequests: 20}
	surface, _, err := crawler.Crawl(context.Background(), srv.URL, "test", httpclient.NewRedactor())
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(surface.Forms) != 1 {
		t.Fatalf("got %d forms, want 1", len(surface.Forms))
	}
	f := surface.Forms[0]
	if f.Method != "POST" {
		t.Errorf("form method = %q, want POST", f.Method)
	}
	if f.Inputs["name"] != "text" || f.Inputs["email"] != "email" {
		t.Errorf("form inputs = %+v, want name=text email=email", f.Inputs)
	}
}

func TestCrawl_NonHTMLResponsesAreNotParsedForLinks(t *testing.T) {
	srv := newGraphServer(t)
	defer srv.Close()
	host, _ := url.Parse(srv.URL)

	crawler := &Crawler{Client: newScopedClient(t, host.Hostname()), MaxDepth: 3, MaxRequests: 20}
	surface, _, err := crawler.Crawl(context.Background(), srv.URL+"/data.json", "test", httpclient.NewRedactor())
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if containsURL(surface.URLs, "/should-not-be-followed") {
		t.Error("a link-shaped string inside a JSON body was followed as if it were an HTML link")
	}
}

func TestCrawl_PassiveFindingsFireDuringCrawl(t *testing.T) {
	srv := newGraphServer(t)
	defer srv.Close()
	host, _ := url.Parse(srv.URL)

	crawler := &Crawler{Client: newScopedClient(t, host.Hostname()), MaxDepth: 0, MaxRequests: 1}
	_, findings, err := crawler.Crawl(context.Background(), srv.URL, "test", httpclient.NewRedactor())
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	// The graph server never sets any security headers, so the root page
	// should trip at least the missing-headers passive checks.
	if len(findings) == 0 {
		t.Error("expected passive checks to produce findings for a page with no security headers")
	}
}
