package dast

import (
	"net/http"
	"testing"

	"github.com/bogdanticu88/Mantis/internal/httpclient"
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

func TestPassive_PermissionsPolicy(t *testing.T) {
	resp := fakeResp("https://example.com/", 200, "hello", nil)
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-HEADER-PERMISSIONS_POLICY") {
		t.Error("expected a finding for missing Permissions-Policy")
	}
}

func TestPassive_PermissionsPolicyPresent(t *testing.T) {
	resp := fakeResp("https://example.com/", 200, "hello", map[string][]string{
		"Permissions-Policy": {"camera=(), microphone=()"},
	})
	ids := findingIDs(t, resp)
	if containsID(ids, "MANTIS-HEADER-PERMISSIONS_POLICY") {
		t.Error("Permissions-Policy finding fired even though header was present")
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

func TestPassive_CookieDomainScope(t *testing.T) {
	// Cookie on api.example.com scoped to .example.com - sibling services get it too.
	resp := fakeResp("https://api.example.com/", 200, "", map[string][]string{
		"Set-Cookie": {"session=abc123; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict"},
	})
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-COOKIE-DOMAIN-SCOPE") {
		t.Error("expected a finding when cookie domain is a parent of the request host")
	}
}

func TestPassive_CookieDomainExactMatchDoesNotFire(t *testing.T) {
	resp := fakeResp("https://example.com/", 200, "", map[string][]string{
		"Set-Cookie": {"session=abc123; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict"},
	})
	ids := findingIDs(t, resp)
	if containsID(ids, "MANTIS-COOKIE-DOMAIN-SCOPE") {
		t.Error("cookie domain matching the request host exactly should not fire")
	}
}

func TestPassive_CookieNoDomainDoesNotFire(t *testing.T) {
	resp := fakeResp("https://example.com/", 200, "", map[string][]string{
		"Set-Cookie": {"session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"},
	})
	ids := findingIDs(t, resp)
	if containsID(ids, "MANTIS-COOKIE-DOMAIN-SCOPE") {
		t.Error("host-only cookie (no Domain= attribute) should not fire")
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

func TestPassive_PrivateIPDisclosure(t *testing.T) {
	resp := fakeResp("https://example.com/", 200, `{"upstream": "10.0.1.45", "status": "ok"}`, nil)
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-INFO-PRIVATE-IP") {
		t.Error("expected a private IP disclosure finding")
	}
}

func TestPassive_PrivateIPIsTargetDoesNotFire(t *testing.T) {
	// The target itself is the private IP - don't flag the host echoing itself.
	resp := fakeResp("http://10.0.1.45/", 200, `{"host": "10.0.1.45"}`, nil)
	ids := findingIDs(t, resp)
	if containsID(ids, "MANTIS-INFO-PRIVATE-IP") {
		t.Error("private IP matching the target host should not trigger the disclosure finding")
	}
}

func TestPassive_NoPrivateIPDoesNotFire(t *testing.T) {
	resp := fakeResp("https://example.com/", 200, `{"host": "api.example.com", "version": "1.2.3"}`, nil)
	ids := findingIDs(t, resp)
	if containsID(ids, "MANTIS-INFO-PRIVATE-IP") {
		t.Error("response with no private IP should not fire")
	}
}

func TestPassive_StackTraceJava(t *testing.T) {
	body := "Internal Server Error\n\tat com.example.UserService.getById(UserService.java:42)\n\tat com.example.Controller.handle(Controller.java:18)"
	resp := fakeResp("https://example.com/api/users/1", 500, body, nil)
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-INFO-STACK-TRACE") {
		t.Error("expected a stack trace finding for Java exception output")
	}
}

func TestPassive_StackTracePython(t *testing.T) {
	body := "Traceback (most recent call last):\n  File \"app.py\", line 12, in handler\nKeyError: 'user_id'"
	resp := fakeResp("https://example.com/", 500, body, nil)
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-INFO-STACK-TRACE") {
		t.Error("expected a stack trace finding for Python traceback")
	}
}

func TestPassive_StackTraceGo(t *testing.T) {
	body := "panic: runtime error\n\ngoroutine 1 [running]:\nmain.handler(0xc000012480)\n\t/app/main.go:23 +0x1a4"
	resp := fakeResp("https://example.com/", 500, body, nil)
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-INFO-STACK-TRACE") {
		t.Error("expected a stack trace finding for Go panic output")
	}
}

func TestPassive_CleanResponseNoStackTrace(t *testing.T) {
	resp := fakeResp("https://example.com/", 200, `{"message": "ok"}`, nil)
	ids := findingIDs(t, resp)
	if containsID(ids, "MANTIS-INFO-STACK-TRACE") {
		t.Error("clean JSON response should not trigger the stack trace finding")
	}
}

func TestPassive_MixedContent(t *testing.T) {
	body := `<html><head></head><body><script src="http://cdn.example.com/app.js"></script></body></html>`
	resp := fakeResp("https://example.com/", 200, body, map[string][]string{
		"Content-Type": {"text/html; charset=utf-8"},
	})
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-MIXED-CONTENT") {
		t.Error("expected a mixed content finding for HTTP script on HTTPS page")
	}
}

func TestPassive_MixedContentImage(t *testing.T) {
	body := `<html><body><img src="http://static.example.com/logo.png"></body></html>`
	resp := fakeResp("https://example.com/", 200, body, map[string][]string{
		"Content-Type": {"text/html"},
	})
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-MIXED-CONTENT") {
		t.Error("expected a mixed content finding for HTTP image on HTTPS page")
	}
}

func TestPassive_MixedContentHTTPPageDoesNotFire(t *testing.T) {
	body := `<html><body><script src="http://cdn.example.com/app.js"></script></body></html>`
	resp := fakeResp("http://example.com/", 200, body, map[string][]string{
		"Content-Type": {"text/html"},
	})
	ids := findingIDs(t, resp)
	if containsID(ids, "MANTIS-MIXED-CONTENT") {
		t.Error("mixed content check should not fire on plain HTTP pages")
	}
}

func TestPassive_MixedContentAllHTTPSDoesNotFire(t *testing.T) {
	body := `<html><body><script src="https://cdn.example.com/app.js"></script></body></html>`
	resp := fakeResp("https://example.com/", 200, body, map[string][]string{
		"Content-Type": {"text/html"},
	})
	ids := findingIDs(t, resp)
	if containsID(ids, "MANTIS-MIXED-CONTENT") {
		t.Error("page with all HTTPS subresources should not fire")
	}
}

func TestPassive_CSRFMissingToken(t *testing.T) {
	body := `<html><body><form method="POST" action="/transfer"><input name="amount" type="text"><button type="submit">Go</button></form></body></html>`
	resp := fakeResp("https://example.com/", 200, body, map[string][]string{
		"Content-Type": {"text/html"},
	})
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-CSRF-NO-TOKEN") {
		t.Error("expected a CSRF finding for POST form with no token field")
	}
}

func TestPassive_CSRFWithToken(t *testing.T) {
	body := `<html><body><form method="POST" action="/transfer"><input name="csrf_token" type="hidden" value="abc123"><input name="amount" type="text"></form></body></html>`
	resp := fakeResp("https://example.com/", 200, body, map[string][]string{
		"Content-Type": {"text/html"},
	})
	ids := findingIDs(t, resp)
	if containsID(ids, "MANTIS-CSRF-NO-TOKEN") {
		t.Error("POST form with a CSRF token hidden field should not fire")
	}
}

func TestPassive_CSRFGetFormDoesNotFire(t *testing.T) {
	body := `<html><body><form method="GET" action="/search"><input name="q" type="text"></form></body></html>`
	resp := fakeResp("https://example.com/", 200, body, map[string][]string{
		"Content-Type": {"text/html"},
	})
	ids := findingIDs(t, resp)
	if containsID(ids, "MANTIS-CSRF-NO-TOKEN") {
		t.Error("GET form does not need a CSRF token")
	}
}

func TestPassive_InsecureFormAction(t *testing.T) {
	body := `<html><body><form method="POST" action="http://example.com/login"><input name="password" type="password"></form></body></html>`
	resp := fakeResp("https://example.com/", 200, body, map[string][]string{
		"Content-Type": {"text/html"},
	})
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-FORM-INSECURE-ACTION") {
		t.Error("expected a finding for a form on an HTTPS page with an HTTP action")
	}
}

func TestPassive_InsecureFormActionHTTPPageDoesNotFire(t *testing.T) {
	body := `<html><body><form method="POST" action="http://example.com/login"><input name="password" type="password"></form></body></html>`
	resp := fakeResp("http://example.com/", 200, body, map[string][]string{
		"Content-Type": {"text/html"},
	})
	ids := findingIDs(t, resp)
	if containsID(ids, "MANTIS-FORM-INSECURE-ACTION") {
		t.Error("insecure form action check should only apply to HTTPS pages")
	}
}

func TestPassive_CacheControlSensitivePath(t *testing.T) {
	resp := fakeResp("https://example.com/login", 200, "login page", nil)
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-CACHE-SENSITIVE") {
		t.Error("expected a cache control finding for /login without Cache-Control: no-store")
	}
}

func TestPassive_CacheControlNoStorePresent(t *testing.T) {
	resp := fakeResp("https://example.com/login", 200, "login page", map[string][]string{
		"Cache-Control": {"no-store, no-cache"},
	})
	ids := findingIDs(t, resp)
	if containsID(ids, "MANTIS-CACHE-SENSITIVE") {
		t.Error("cache control finding should not fire when no-store is present")
	}
}

func TestPassive_CacheControlNonSensitivePath(t *testing.T) {
	resp := fakeResp("https://example.com/about", 200, "about page", nil)
	ids := findingIDs(t, resp)
	if containsID(ids, "MANTIS-CACHE-SENSITIVE") {
		t.Error("cache control finding should not fire on non-sensitive paths")
	}
}

func TestPassive_VulnerableJQueryOneX(t *testing.T) {
	body := `<html><head><script src="https://code.jquery.com/jquery-1.12.4.min.js"></script></head></html>`
	resp := fakeResp("https://example.com/", 200, body, nil)
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-VULN-JQUERY-OUTDATED") {
		t.Error("expected a finding for jQuery 1.x")
	}
}

func TestPassive_VulnerableJQueryTwoX(t *testing.T) {
	body := `<html><head><script src="/static/jquery-2.2.4.min.js"></script></head></html>`
	resp := fakeResp("https://example.com/", 200, body, nil)
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-VULN-JQUERY-OUTDATED") {
		t.Error("expected a finding for jQuery 2.x")
	}
}

func TestPassive_VulnerableJQueryComment(t *testing.T) {
	body := "/*! jQuery v1.11.3 | (c) 2005, 2015 jQuery Foundation, Inc. */"
	resp := fakeResp("https://example.com/jquery.min.js", 200, body, nil)
	ids := findingIDs(t, resp)
	if !containsID(ids, "MANTIS-VULN-JQUERY-OUTDATED") {
		t.Error("expected a finding for jQuery 1.x version comment in body")
	}
}

func TestPassive_CurrentJQueryDoesNotFire(t *testing.T) {
	body := `<html><head><script src="https://code.jquery.com/jquery-3.7.1.min.js"></script></head></html>`
	resp := fakeResp("https://example.com/", 200, body, nil)
	ids := findingIDs(t, resp)
	if containsID(ids, "MANTIS-VULN-JQUERY-OUTDATED") {
		t.Error("jQuery 3.x should not trigger the outdated library finding")
	}
}
