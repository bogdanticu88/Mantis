// Package attacks is the per-parameter fuzzing engine: a small, fixed set
// of injection payloads per class, tried against every discovered query
// parameter and form field. Payloads are picked deliberately for low
// false-positive signal (error strings, literal reflection, an arithmetic
// result unlikely to appear on a page by accident, an echo marker) rather
// than blind/timing-based detection, which doesn't hold up well in a CI
// context where request timing is noisy anyway.
package attacks

import (
	"regexp"
	"strings"

	"mantis/internal/findings"
)

// Payload is one probe value plus how to recognize it worked.
type Payload struct {
	Value      string
	MatchWords []string // OR condition: any literal substring present is a hit
	MatchRegex []string // OR condition: any pattern matching is a hit
}

type classInfo struct {
	Name     string
	Severity findings.Severity
	CWE      string
	OWASP    string
}

var classes = map[string]classInfo{
	"sqli":           {"SQL Injection", findings.SeverityCritical, "CWE-89", "A03:2021-Injection"},
	"xss":            {"Reflected Cross-Site Scripting", findings.SeverityHigh, "CWE-79", "A03:2021-Injection"},
	"path-traversal": {"Path Traversal", findings.SeverityCritical, "CWE-22", "A01:2021-Broken Access Control"},
	"ssti":           {"Server-Side Template Injection", findings.SeverityCritical, "CWE-1336", "A03:2021-Injection"},
	"cmdi":           {"OS Command Injection", findings.SeverityCritical, "CWE-78", "A03:2021-Injection"},
}

// AllClasses lists every fuzzing class in a fixed, deterministic order.
func AllClasses() []string {
	return []string{"sqli", "xss", "path-traversal", "ssti", "cmdi"}
}

var payloadsByClass = map[string][]Payload{
	"sqli": {
		{
			Value: "'",
			MatchRegex: []string{
				"SQL syntax.*MySQL", "Warning.*mysql_", "PostgreSQL.*ERROR",
				"ORA-[0-9]{5}", "SQLite3::", "Unclosed quotation mark",
			},
		},
	},
	"xss": {
		{Value: `<script>alert('mantis-xss-8231')</script>`, MatchWords: []string{`<script>alert('mantis-xss-8231')</script>`}},
		{Value: `"><svg onload=alert('mantis-xss-8231')>`, MatchWords: []string{`"><svg onload=alert('mantis-xss-8231')>`}},
	},
	"path-traversal": {
		{Value: "../../../../../../etc/passwd", MatchRegex: []string{"root:.*:0:0:"}},
		{Value: `..\..\..\..\..\..\windows\win.ini`, MatchRegex: []string{`\[fonts\]`, `\[extensions\]`}},
	},
	"ssti": {
		// 7*777 rather than the usual 7*7 - "49" is common enough in real
		// page content (prices, counts, ids) to be a false-positive magnet;
		// "5439" isn't going to show up by accident.
		{Value: "{{7*777}}", MatchRegex: []string{`\b5439\b`}},
		{Value: "${7*777}", MatchRegex: []string{`\b5439\b`}},
	},
	"cmdi": {
		{Value: "; echo MANTIS_CMDI_8231", MatchWords: []string{"MANTIS_CMDI_8231"}},
		{Value: "| echo MANTIS_CMDI_8231", MatchWords: []string{"MANTIS_CMDI_8231"}},
		{Value: "`echo MANTIS_CMDI_8231`", MatchWords: []string{"MANTIS_CMDI_8231"}},
	},
}

func payloadsFor(selected []string) map[string][]Payload {
	if len(selected) == 0 {
		selected = AllClasses()
	}
	out := make(map[string][]Payload, len(selected))
	for _, c := range selected {
		if ps, ok := payloadsByClass[c]; ok {
			out[c] = ps
		}
	}
	return out
}

// matched checks a response body against a payload's match conditions,
// returning what matched (for evidence) if anything did.
func matched(p Payload, body string) (bool, string) {
	for _, w := range p.MatchWords {
		if strings.Contains(body, w) {
			return true, w
		}
	}
	for _, pattern := range p.MatchRegex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if m := re.FindString(body); m != "" {
			return true, m
		}
	}
	return false, ""
}
