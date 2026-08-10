package dast

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"mantis/internal/findings"
	"mantis/internal/httpclient"
)

// RunPassiveChecks runs every passive check against one response. These are
// read-only by definition - no extra requests, nothing that could touch
// application state - we're just looking at what came back already.
func RunPassiveChecks(target, environment string, resp *httpclient.Response, redactor *httpclient.Redactor) []findings.Finding {
	var out []findings.Finding
	out = append(out, checkSecurityHeaders(target, environment, resp, redactor)...)
	out = append(out, checkCookies(target, environment, resp, redactor)...)
	out = append(out, checkCORS(target, environment, resp, redactor)...)
	out = append(out, checkServerDisclosure(target, environment, resp, redactor)...)
	out = append(out, checkDirectoryListing(target, environment, resp, redactor)...)
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
