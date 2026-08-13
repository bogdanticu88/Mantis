package dast

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/bogdanticu88/Mantis/internal/findings"
	"github.com/bogdanticu88/Mantis/internal/httpclient"
)

// RunPassiveChecks runs every passive check against one response. These are
// read-only by definition - no extra requests, nothing that could touch
// application state - we're just looking at what came back already.
func RunPassiveChecks(target, environment string, resp *httpclient.Response, redactor *httpclient.Redactor) []findings.Finding {
	var out []findings.Finding
	out = append(out, checkSecurityHeaders(target, environment, resp, redactor)...)
	out = append(out, checkPermissionsPolicy(target, environment, resp, redactor)...)
	out = append(out, checkCookies(target, environment, resp, redactor)...)
	out = append(out, checkCookieDomainScope(target, environment, resp, redactor)...)
	out = append(out, checkCORS(target, environment, resp, redactor)...)
	out = append(out, checkServerDisclosure(target, environment, resp, redactor)...)
	out = append(out, checkDirectoryListing(target, environment, resp, redactor)...)
	out = append(out, checkPrivateIPDisclosure(target, environment, resp, redactor)...)
	out = append(out, checkStackTraceDisclosure(target, environment, resp, redactor)...)
	out = append(out, checkMixedContent(target, environment, resp, redactor)...)
	out = append(out, checkCSRFProtection(target, environment, resp, redactor)...)
	out = append(out, checkInsecureFormAction(target, environment, resp, redactor)...)
	out = append(out, checkCacheControl(target, environment, resp, redactor)...)
	out = append(out, checkVulnerableJSLibraries(target, environment, resp, redactor)...)
	return out
}

func mkFinding(id, name string, severity findings.Severity, target, endpoint, description, cwe, owasp string, resp *httpclient.Response, redactor *httpclient.Redactor, environment string) findings.Finding {
	return findings.Finding{
		ID:          id,
		Name:        name,
		Severity:    severity,
		Confidence:  1.0,
		Environment: environment,
		Target:      target,
		Endpoint:    endpoint,
		Method:      resp.Request.Method,
		Description: description,
		CWE:         cwe,
		OWASP:       owasp,
		Tags:        []string{"passive", "dast"},
		Evidence: findings.Evidence{
			Description: description,
			Exchanges:   []findings.HTTPExchange{redactor.Exchange(resp)},
		},
		Timestamp: time.Now(),
	}
}

func pathOf(resp *httpclient.Response) string {
	u, err := url.Parse(resp.Request.URL)
	if err != nil {
		return resp.Request.URL
	}
	return u.Path
}

// parseResponseHTML parses the response body as HTML. Returns nil, false when
// the Content-Type is not text/html or the body fails to parse.
func parseResponseHTML(resp *httpclient.Response) (*html.Node, bool) {
	if !strings.Contains(strings.ToLower(resp.Headers.Get("Content-Type")), "text/html") {
		return nil, false
	}
	doc, err := html.Parse(strings.NewReader(string(resp.Body)))
	if err != nil {
		return nil, false
	}
	return doc, true
}

func walkHTML(n *html.Node, fn func(*html.Node)) {
	fn(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walkHTML(c, fn)
	}
}

var securityHeaderChecks = []struct {
	Header      string
	Severity    findings.Severity
	Description string
	CWE         string
}{
	{"Strict-Transport-Security", findings.SeverityMedium, "Response is missing the Strict-Transport-Security header, allowing downgrade to plaintext HTTP on future visits.", "CWE-319"},
	{"X-Content-Type-Options", findings.SeverityLow, "Response is missing X-Content-Type-Options: nosniff, allowing browsers to MIME-sniff content types.", "CWE-116"},
	{"X-Frame-Options", findings.SeverityMedium, "Response is missing X-Frame-Options and may be missing an equivalent Content-Security-Policy frame-ancestors directive, allowing clickjacking.", "CWE-1021"},
	{"Content-Security-Policy", findings.SeverityMedium, "Response is missing a Content-Security-Policy header.", "CWE-693"},
	{"Referrer-Policy", findings.SeverityLow, "Response is missing a Referrer-Policy header, which may leak URLs via the Referer header on outbound links.", "CWE-200"},
}

func checkSecurityHeaders(target, environment string, resp *httpclient.Response, redactor *httpclient.Redactor) []findings.Finding {
	var out []findings.Finding
	endpoint := pathOf(resp)
	for _, h := range securityHeaderChecks {
		if resp.Headers.Get(h.Header) != "" {
			continue
		}
		id := "MANTIS-HEADER-" + strings.ToUpper(strings.ReplaceAll(h.Header, "-", "_"))
		out = append(out, mkFinding(id, fmt.Sprintf("Missing %s header", h.Header), h.Severity, target, endpoint, h.Description, h.CWE, "A05:2021-Security Misconfiguration", resp, redactor, environment))
	}
	return out
}

func checkPermissionsPolicy(target, environment string, resp *httpclient.Response, redactor *httpclient.Redactor) []findings.Finding {
	if resp.Headers.Get("Permissions-Policy") != "" {
		return nil
	}
	return []findings.Finding{mkFinding(
		"MANTIS-HEADER-PERMISSIONS_POLICY",
		"Missing Permissions-Policy header",
		findings.SeverityInfo,
		target, pathOf(resp),
		"The response is missing a Permissions-Policy header. Without it, the page grants the browser's default feature access (camera, microphone, geolocation, etc.) to any embedded frame or script.",
		"CWE-693", "A05:2021-Security Misconfiguration",
		resp, redactor, environment,
	)}
}

func checkCookies(target, environment string, resp *httpclient.Response, redactor *httpclient.Redactor) []findings.Finding {
	if len(resp.Headers["Set-Cookie"]) == 0 {
		return nil
	}
	wrapped := &http.Response{Header: resp.Headers}
	var out []findings.Finding
	endpoint := pathOf(resp)
	for _, ck := range wrapped.Cookies() {
		isHTTPS := strings.HasPrefix(strings.ToLower(resp.Request.URL), "https://")
		if isHTTPS && !ck.Secure {
			out = append(out, mkFinding("MANTIS-COOKIE-SECURE", fmt.Sprintf("Cookie %q missing Secure attribute", ck.Name), findings.SeverityMedium, target, endpoint,
				fmt.Sprintf("Cookie %q is set over HTTPS without the Secure attribute, so it may be sent over plaintext HTTP.", ck.Name), "CWE-614", "A05:2021-Security Misconfiguration", resp, redactor, environment))
		}
		if !ck.HttpOnly {
			out = append(out, mkFinding("MANTIS-COOKIE-HTTPONLY", fmt.Sprintf("Cookie %q missing HttpOnly attribute", ck.Name), findings.SeverityMedium, target, endpoint,
				fmt.Sprintf("Cookie %q lacks HttpOnly, so it is readable via JavaScript (document.cookie), increasing XSS impact.", ck.Name), "CWE-1004", "A05:2021-Security Misconfiguration", resp, redactor, environment))
		}
		sameSite := strings.ToLower(sameSiteAttr(ck))
		if sameSite == "" || sameSite == "none" {
			out = append(out, mkFinding("MANTIS-COOKIE-SAMESITE", fmt.Sprintf("Cookie %q has weak SameSite configuration", ck.Name), findings.SeverityLow, target, endpoint,
				fmt.Sprintf("Cookie %q has SameSite=%s (or unset), offering weak CSRF protection.", ck.Name, orNone(sameSite)), "CWE-352", "A01:2021-Broken Access Control", resp, redactor, environment))
		}
	}
	return out
}

func checkCookieDomainScope(target, environment string, resp *httpclient.Response, redactor *httpclient.Redactor) []findings.Finding {
	if len(resp.Headers["Set-Cookie"]) == 0 {
		return nil
	}
	u, err := url.Parse(resp.Request.URL)
	if err != nil {
		return nil
	}
	requestHost := strings.ToLower(u.Hostname())
	if requestHost == "" {
		return nil
	}
	wrapped := &http.Response{Header: resp.Headers}
	var out []findings.Finding
	endpoint := pathOf(resp)
	for _, ck := range wrapped.Cookies() {
		if ck.Domain == "" {
			continue
		}
		// Go strips the leading dot when parsing Set-Cookie, so ck.Domain
		// is the bare domain. A cookie with Domain= set applies to all
		// subdomains; we flag when it's scoped to a parent of the request
		// host, meaning sibling services also receive the cookie.
		cookieDomain := strings.ToLower(strings.TrimPrefix(ck.Domain, "."))
		if cookieDomain != requestHost && strings.HasSuffix(requestHost, "."+cookieDomain) {
			out = append(out, mkFinding(
				"MANTIS-COOKIE-DOMAIN-SCOPE",
				fmt.Sprintf("Cookie %q scoped to parent domain %q", ck.Name, cookieDomain),
				findings.SeverityLow,
				target, endpoint,
				fmt.Sprintf("Cookie %q has Domain=%s, which sends it to all subdomains of %s, including sibling services. Use a host-only cookie (omit Domain=) unless cross-subdomain sharing is intentional.", ck.Name, cookieDomain, cookieDomain),
				"CWE-1275", "A05:2021-Security Misconfiguration",
				resp, redactor, environment,
			))
		}
	}
	return out
}

func sameSiteAttr(ck *http.Cookie) string {
	switch ck.SameSite {
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}

func orNone(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}

func checkCORS(target, environment string, resp *httpclient.Response, redactor *httpclient.Redactor) []findings.Finding {
	acao := resp.Headers.Get("Access-Control-Allow-Origin")
	acac := strings.ToLower(resp.Headers.Get("Access-Control-Allow-Credentials"))
	if acao == "*" && acac == "true" {
		return []findings.Finding{mkFinding("MANTIS-CORS-WILDCARD-CREDENTIALS", "CORS misconfiguration: wildcard origin with credentials", findings.SeverityHigh,
			target, pathOf(resp), "Access-Control-Allow-Origin is \"*\" while Access-Control-Allow-Credentials is \"true\". Browsers reject this combination, but it signals a broken CORS policy likely to fail open elsewhere (e.g. reflecting arbitrary Origin values).",
			"CWE-942", "A05:2021-Security Misconfiguration", resp, redactor, environment)}
	}
	return nil
}

var serverVersionPattern = regexp.MustCompile(`[0-9]+\.[0-9]+`)

func checkServerDisclosure(target, environment string, resp *httpclient.Response, redactor *httpclient.Redactor) []findings.Finding {
	var out []findings.Finding
	for _, h := range []string{"Server", "X-Powered-By"} {
		v := resp.Headers.Get(h)
		if v != "" && serverVersionPattern.MatchString(v) {
			out = append(out, mkFinding("MANTIS-INFO-"+strings.ToUpper(h), fmt.Sprintf("%s header discloses version information", h), findings.SeverityInfo,
				target, pathOf(resp), fmt.Sprintf("%s header value %q discloses software/version information useful for targeted attacks.", h, v),
				"CWE-200", "A05:2021-Security Misconfiguration", resp, redactor, environment))
		}
	}
	return out
}

func checkDirectoryListing(target, environment string, resp *httpclient.Response, redactor *httpclient.Redactor) []findings.Finding {
	body := string(resp.Body)
	if strings.Contains(body, "Index of /") || strings.Contains(body, "<title>Directory listing for") {
		return []findings.Finding{mkFinding("MANTIS-DIRECTORY-LISTING", "Directory listing enabled", findings.SeverityMedium,
			target, pathOf(resp), "The server returned a directory listing instead of an application response, exposing the file/directory structure.",
			"CWE-548", "A05:2021-Security Misconfiguration", resp, redactor, environment)}
	}
	return nil
}

var privateIPPattern = regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

func checkPrivateIPDisclosure(target, environment string, resp *httpclient.Response, redactor *httpclient.Redactor) []findings.Finding {
	match := privateIPPattern.FindString(string(resp.Body))
	if match == "" {
		return nil
	}
	// Don't flag when the target itself is a private IP - the address in
	// the body is most likely just the host echoing itself back.
	if u, err := url.Parse(resp.Request.URL); err == nil && u.Hostname() == match {
		return nil
	}
	return []findings.Finding{mkFinding(
		"MANTIS-INFO-PRIVATE-IP",
		"Private IP address disclosed in response body",
		findings.SeverityLow,
		target, pathOf(resp),
		fmt.Sprintf("The response body contains the private IP address %s, which may reveal internal network topology to an external attacker.", match),
		"CWE-200", "A05:2021-Security Misconfiguration",
		resp, redactor, environment,
	)}
}

var stackTracePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\tat [a-zA-Z_$][a-zA-Z0-9_$.]*\(`),                                      // Java (com.example.Class.method()
	regexp.MustCompile(`Traceback \(most recent call last\):`),                                  // Python
	regexp.MustCompile(`(?i)Fatal error:.*in .+\.php on line \d+`),                              // PHP
	regexp.MustCompile(`goroutine \d+ \[running\]:`),                                            // Go
	regexp.MustCompile(`at Object\.<anonymous> \(`),                                             // Node.js
	regexp.MustCompile(`System\.(NullReference|ArgumentNull|InvalidOperation|Web|IO)Exception`), // .NET
}

func checkStackTraceDisclosure(target, environment string, resp *httpclient.Response, redactor *httpclient.Redactor) []findings.Finding {
	body := string(resp.Body)
	for _, re := range stackTracePatterns {
		if re.MatchString(body) {
			return []findings.Finding{mkFinding(
				"MANTIS-INFO-STACK-TRACE",
				"Stack trace or unhandled exception disclosed in response",
				findings.SeverityMedium,
				target, pathOf(resp),
				"The response contains exception detail or a stack trace, exposing internal file paths, class names, and application structure that aid targeted attacks.",
				"CWE-209", "A05:2021-Security Misconfiguration",
				resp, redactor, environment,
			)}
		}
	}
	return nil
}

func checkMixedContent(target, environment string, resp *httpclient.Response, redactor *httpclient.Redactor) []findings.Finding {
	if !strings.HasPrefix(strings.ToLower(resp.Request.URL), "https://") {
		return nil
	}
	doc, ok := parseResponseHTML(resp)
	if !ok {
		return nil
	}
	var found bool
	walkHTML(doc, func(n *html.Node) {
		if found || n.Type != html.ElementNode {
			return
		}
		switch n.Data {
		case "script", "img", "iframe", "audio", "video":
			if strings.HasPrefix(attr(n, "src"), "http://") {
				found = true
			}
		case "link":
			if strings.HasPrefix(attr(n, "href"), "http://") {
				found = true
			}
		}
	})
	if !found {
		return nil
	}
	return []findings.Finding{mkFinding(
		"MANTIS-MIXED-CONTENT",
		"Mixed content: HTTPS page loads subresources over HTTP",
		findings.SeverityMedium,
		target, pathOf(resp),
		"The page is served over HTTPS but references at least one subresource (script, image, frame, or stylesheet) over plain HTTP, allowing a network attacker to tamper with the loaded content.",
		"CWE-319", "A02:2021-Cryptographic Failures",
		resp, redactor, environment,
	)}
}

var csrfTokenFieldNames = []string{"csrf", "xsrf", "_token", "nonce", "authenticity_token"}

func looksLikeCSRFField(name string) bool {
	lower := strings.ToLower(name)
	for _, tok := range csrfTokenFieldNames {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

func checkCSRFProtection(target, environment string, resp *httpclient.Response, redactor *httpclient.Redactor) []findings.Finding {
	doc, ok := parseResponseHTML(resp)
	if !ok {
		return nil
	}
	var out []findings.Finding
	walkHTML(doc, func(n *html.Node) {
		if n.Type != html.ElementNode || n.Data != "form" {
			return
		}
		method := strings.ToUpper(attr(n, "method"))
		if method == "" {
			method = "GET"
		}
		if method == "GET" {
			return
		}
		hasToken := false
		walkHTML(n, func(c *html.Node) {
			if hasToken || c.Type != html.ElementNode || c.Data != "input" {
				return
			}
			if strings.ToLower(attr(c, "type")) == "hidden" && looksLikeCSRFField(attr(c, "name")) {
				hasToken = true
			}
		})
		if hasToken {
			return
		}
		actionPath := attr(n, "action")
		if actionPath == "" {
			actionPath = pathOf(resp)
		}
		out = append(out, mkFinding(
			"MANTIS-CSRF-NO-TOKEN",
			"State-changing form missing CSRF token",
			findings.SeverityMedium,
			target, actionPath,
			fmt.Sprintf("The %s form submitting to %q contains no recognizable CSRF token hidden field, leaving it vulnerable to cross-site request forgery if the session cookie lacks SameSite protection.", method, actionPath),
			"CWE-352", "A01:2021-Broken Access Control",
			resp, redactor, environment,
		))
	})
	return out
}

func checkInsecureFormAction(target, environment string, resp *httpclient.Response, redactor *httpclient.Redactor) []findings.Finding {
	if !strings.HasPrefix(strings.ToLower(resp.Request.URL), "https://") {
		return nil
	}
	doc, ok := parseResponseHTML(resp)
	if !ok {
		return nil
	}
	var out []findings.Finding
	walkHTML(doc, func(n *html.Node) {
		if n.Type != html.ElementNode || n.Data != "form" {
			return
		}
		action := attr(n, "action")
		if strings.HasPrefix(strings.ToLower(action), "http://") {
			out = append(out, mkFinding(
				"MANTIS-FORM-INSECURE-ACTION",
				"Form on HTTPS page submits over plain HTTP",
				findings.SeverityHigh,
				target, pathOf(resp),
				fmt.Sprintf("A form on this HTTPS page has action=%q, sending form data (potentially including credentials) over an unencrypted connection.", action),
				"CWE-319", "A02:2021-Cryptographic Failures",
				resp, redactor, environment,
			))
		}
	})
	return out
}

var sensitivePaths = []string{
	"/login", "/signin", "/account", "/profile", "/dashboard",
	"/admin", "/settings", "/api/", "/user/", "/me/",
	"/payment", "/checkout", "/password", "/token",
}

func isSensitivePath(p string) bool {
	lower := strings.ToLower(p)
	for _, s := range sensitivePaths {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func checkCacheControl(target, environment string, resp *httpclient.Response, redactor *httpclient.Redactor) []findings.Finding {
	p := pathOf(resp)
	if !isSensitivePath(p) {
		return nil
	}
	if strings.Contains(strings.ToLower(resp.Headers.Get("Cache-Control")), "no-store") {
		return nil
	}
	return []findings.Finding{mkFinding(
		"MANTIS-CACHE-SENSITIVE",
		"Sensitive endpoint missing Cache-Control: no-store",
		findings.SeverityLow,
		target, p,
		fmt.Sprintf("The response for %q does not include Cache-Control: no-store. Browsers and shared proxies may cache it, potentially exposing sensitive data to other users of the same device or proxy.", p),
		"CWE-525", "A05:2021-Security Misconfiguration",
		resp, redactor, environment,
	)}
}

var jqueryVersionPattern = regexp.MustCompile(`(?i)jquery[/\-]v?(1|2)\.\d+\.\d+`)
var jqueryCommentPattern = regexp.MustCompile(`(?i)jquery\s+v(1|2)\.\d+`)

func checkVulnerableJSLibraries(target, environment string, resp *httpclient.Response, redactor *httpclient.Redactor) []findings.Finding {
	body := string(resp.Body)
	match := jqueryVersionPattern.FindString(body)
	if match == "" {
		match = jqueryCommentPattern.FindString(body)
	}
	if match == "" {
		return nil
	}
	return []findings.Finding{mkFinding(
		"MANTIS-VULN-JQUERY-OUTDATED",
		"Outdated jQuery version detected",
		findings.SeverityMedium,
		target, pathOf(resp),
		fmt.Sprintf("The response references %s, a major version with known XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023 and others). Upgrade to jQuery 3.5 or later.", match),
		"CWE-1395", "A06:2021-Vulnerable and Outdated Components",
		resp, redactor, environment,
	)}
}
