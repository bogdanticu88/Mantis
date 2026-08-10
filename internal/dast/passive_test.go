package dast

import (
	"net/http"
	"testing"

	"mantis/internal/httpclient"
)

func fakeResp(url string, status int, body string, headers map[string][]string) *httpclient.Response {
	h := http.Header{}
	for k, v := range headers {
		h[k] = v
	}
	return &httpclient.Response{
		Request:    httpclient.Request{Method: "GET", URL: url},
		StatusCode: status,
		Headers:    h,
		Body:       []byte(body),
	}
}

func containsID(ids []string, id string) bool {
	for _, i := range ids {
		if i == id {
			return true
		}
	}
	return false
}

func findingIDs(t *testing.T, resp *httpclient.Response) []string {
	t.Helper()
	fs := RunPassiveChecks("https://example.com", "test", resp, httpclient.NewRedactor())
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.ID)
	}
	return ids
}

func TestPassive_MissingSecurityHeaders(t *testing.T) {
	resp := fakeResp("https://example.com/", 200, "hello", nil)
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-HEADER-STRICT_TRANSPORT_SECURITY") {
		t.Error("expected a finding for missing Strict-Transport-Security")
	}
	if !containsID(ids, "MANTIS-HEADER-CONTENT_SECURITY_POLICY") {
		t.Error("expected a finding for missing Content-Security-Policy")
	}
}

func TestPassive_PresentHeadersDontFire(t *testing.T) {
	resp := fakeResp("https://example.com/", 200, "hello", map[string][]string{
		"Strict-Transport-Security": {"max-age=31536000"},
		"X-Content-Type-Options":    {"nosniff"},
		"X-Frame-Options":           {"DENY"},
		"Content-Security-Policy":   {"default-src 'self'"},
		"Referrer-Policy":           {"no-referrer"},
	})
	ids := findingIDs(t, resp)
	for _, id := range ids {
		if id == "MANTIS-HEADER-STRICT_TRANSPORT_SECURITY" || id == "MANTIS-HEADER-CONTENT_SECURITY_POLICY" {
			t.Errorf("finding %s fired even though the header was present", id)
		}
	}
}

func TestPassive_InsecureCookie(t *testing.T) {
	resp := fakeResp("https://example.com/", 200, "", map[string][]string{
		"Set-Cookie": {"session=abc123; Path=/"}, // no Secure, no HttpOnly, no SameSite
	})
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-COOKIE-SECURE") {
		t.Error("expected a finding for missing Secure attribute over HTTPS")
	}
	if !containsID(ids, "MANTIS-COOKIE-HTTPONLY") {
		t.Error("expected a finding for missing HttpOnly attribute")
	}
	if !containsID(ids, "MANTIS-COOKIE-SAMESITE") {
		t.Error("expected a finding for weak SameSite")
	}
}

func TestPassive_SecureCookieDoesNotFire(t *testing.T) {
	resp := fakeResp("https://example.com/", 200, "", map[string][]string{
		"Set-Cookie": {"session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"},
	})
	ids := findingIDs(t, resp)
	if containsID(ids, "MANTIS-COOKIE-SECURE") || containsID(ids, "MANTIS-COOKIE-HTTPONLY") || containsID(ids, "MANTIS-COOKIE-SAMESITE") {
		t.Errorf("a fully locked-down cookie should not have triggered any cookie finding, got %v", ids)
	}
}

func TestPassive_CORSWildcardWithCredentials(t *testing.T) {
	resp := fakeResp("https://example.com/", 200, "", map[string][]string{
		"Access-Control-Allow-Origin":      {"*"},
		"Access-Control-Allow-Credentials": {"true"},
	})
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-CORS-WILDCARD-CREDENTIALS") {
		t.Error("expected the wildcard-origin-with-credentials CORS finding")
	}
}

func TestPassive_CORSWildcardAloneDoesNotFire(t *testing.T) {
	// Wildcard alone (no credentials flag) isn't the same misconfiguration -
	// it's a common and often intentional public-API pattern.
	resp := fakeResp("https://example.com/", 200, "", map[string][]string{
		"Access-Control-Allow-Origin": {"*"},
	})
	ids := findingIDs(t, resp)
	if containsID(ids, "MANTIS-CORS-WILDCARD-CREDENTIALS") {
		t.Error("wildcard origin without credentials should not trigger the credentials-specific finding")
	}
}

func TestPassive_ServerVersionDisclosure(t *testing.T) {
	resp := fakeResp("https://example.com/", 200, "", map[string][]string{"Server": {"nginx/1.18.0"}})
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-INFO-SERVER") {
		t.Error("expected a version-disclosure finding for a Server header containing a version number")
	}
}

func TestPassive_GenericServerHeaderDoesNotFire(t *testing.T) {
	resp := fakeResp("https://example.com/", 200, "", map[string][]string{"Server": {"nginx"}})
	ids := findingIDs(t, resp)
	if containsID(ids, "MANTIS-INFO-SERVER") {
		t.Error("a Server header with no version digits should not fire the version-disclosure finding")
	}
}

func TestPassive_DirectoryListing(t *testing.T) {
	resp := fakeResp("https://example.com/files/", 200, "<html><body>Index of /files/</body></html>", nil)
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-DIRECTORY-LISTING") {
		t.Error("expected a directory listing finding")
	}
}
