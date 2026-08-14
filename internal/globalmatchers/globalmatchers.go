// Package globalmatchers runs passive pattern checks against every HTTP
// response that flows through the engine, regardless of which template or
// attack module produced the request. No extra requests are sent — these
// are riders on traffic that would have happened anyway.
package globalmatchers

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/bogdanticu88/Mantis/internal/findings"
	"github.com/bogdanticu88/Mantis/internal/httpclient"
)

// GlobalMatcher is one passive check: a regex applied to a specific part of
// every response, producing a finding when the pattern fires.
type GlobalMatcher struct {
	ID       string
	Name     string
	Severity findings.Severity
	CWE      string
	OWASP    string
	Tags     []string
	Part     string // "body" (default) or "header"
	Pattern  *regexp.Regexp
}

// Builtin is the default set of global matchers enabled by the engine. They
// cover the most common passive disclosures: credentials or key material
// leaking in responses, verbose error messages, and common verbose server
// banners. All patterns are case-insensitive.
var Builtin = buildBuiltin()

func buildBuiltin() []GlobalMatcher {
	return []GlobalMatcher{
		// --- credentials and key material ---

		newGM("MANTIS-GM-AWS-KEY",
			"AWS Access Key Exposed in Response",
			findings.SeverityHigh,
			"CWE-312", "A02:2021-Cryptographic Failures",
			[]string{"secrets", "aws"},
			"body", `AKIA[0-9A-Z]{16}`),

		newGM("MANTIS-GM-PRIVATE-KEY",
			"Private Key Material Exposed in Response",
			findings.SeverityCritical,
			"CWE-312", "A02:2021-Cryptographic Failures",
			[]string{"secrets", "pki"},
			"body", `-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),

		newGM("MANTIS-GM-JWT",
			"JWT Token Exposed in Response Body",
			findings.SeverityMedium,
			"CWE-312", "A02:2021-Cryptographic Failures",
			[]string{"secrets", "jwt"},
			"body", `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),

		// --- verbose error messages ---

		newGM("MANTIS-GM-SQL-ERROR",
			"SQL Error Message Disclosed in Response",
			findings.SeverityMedium,
			"CWE-209", "A05:2021-Security Misconfiguration",
			[]string{"errors", "sqli"},
			"body", `(?:SQL syntax.*near|ORA-\d{5}|PostgreSQL.*ERROR|You have an error in your SQL syntax|Unclosed quotation mark|SQLSTATE\[\w+\])`),

		newGM("MANTIS-GM-STACK-TRACE",
			"Stack Trace Exposed in Response",
			findings.SeverityMedium,
			"CWE-209", "A05:2021-Security Misconfiguration",
			[]string{"errors", "disclosure"},
			"body", `(?:at [a-zA-Z_$.]+\([A-Za-z]+\.java:\d+\)|Traceback \(most recent call last\)|System\.Web\.HttpException|Microsoft\.CSharp\.RuntimeBinder)`),

		newGM("MANTIS-GM-PHP-ERROR",
			"PHP Error or Warning Disclosed in Response",
			findings.SeverityLow,
			"CWE-209", "A05:2021-Security Misconfiguration",
			[]string{"errors", "php"},
			"body", `<b>(?:Fatal error|Warning|Notice)</b>:.*in <b>.*\.php</b> on line <b>\d+</b>`),

		newGM("MANTIS-GM-ASPNET-ERROR",
			"ASP.NET Error Details Exposed in Response",
			findings.SeverityMedium,
			"CWE-209", "A05:2021-Security Misconfiguration",
			[]string{"errors", "aspnet"},
			"body", `Server Error in '.*' Application\.|System\.Web\.HttpUnhandledException`),
	}
}

func newGM(id, name string, sev findings.Severity, cwe, owasp string, tags []string, part, pattern string) GlobalMatcher {
	return GlobalMatcher{
		ID:       id,
		Name:     name,
		Severity: sev,
		CWE:      cwe,
		OWASP:    owasp,
		Tags:     tags,
		Part:     part,
		Pattern:  regexp.MustCompile(`(?i)` + pattern),
	}
}

// EvalAll runs every matcher in matchers against resp and returns a finding
// for each pattern that fires. target, environment, and endpoint are stamped
// onto findings. It is safe to call with a nil or empty matchers slice.
func EvalAll(matchers []GlobalMatcher, resp *httpclient.Response, target, environment, endpoint string) []findings.Finding {
	var out []findings.Finding
	for _, m := range matchers {
		src := responseText(m.Part, resp)
		hit := m.Pattern.FindString(src)
		if hit == "" {
			continue
		}
		out = append(out, findings.Finding{
			ID:          m.ID,
			Name:        m.Name,
			Severity:    m.Severity,
			Confidence:  0.8,
			Environment: environment,
			Target:      target,
			Endpoint:    endpoint,
			Method:      resp.Request.Method,
			CWE:         m.CWE,
			OWASP:       m.OWASP,
			Tags:        m.Tags,
			Description: fmt.Sprintf("Sensitive pattern detected in response %s", m.Part),
			Evidence: findings.Evidence{
				Description: "Global matcher fired without intentional triggering — pattern was present in a response to a normal probe request.",
				MatchedOn:   []string{hit},
			},
			Timestamp: time.Now(),
		})
	}
	return out
}

func responseText(part string, resp *httpclient.Response) string {
	switch strings.ToLower(part) {
	case "header":
		var b strings.Builder
		for k, vs := range resp.Headers {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(strings.Join(vs, ","))
			b.WriteByte('\n')
		}
		return b.String()
	default:
		return string(resp.Body)
	}
}
