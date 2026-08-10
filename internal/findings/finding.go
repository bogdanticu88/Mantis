// Package findings holds the finding type shared by every engine (templates,
// DAST, smoke, API). The whole point is that a finding has to carry enough
// evidence for someone to reproduce it without re-running the scan.
package findings

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// severityRank orders severities from most to least severe, lower is worse.
var severityRank = map[Severity]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
	SeverityInfo:     4,
}

// AtLeast reports whether s is at least as severe as threshold.
func (s Severity) AtLeast(threshold Severity) bool {
	sr, ok := severityRank[s]
	if !ok {
		return false
	}
	tr, ok := severityRank[threshold]
	if !ok {
		return false
	}
	return sr <= tr
}

// HTTPExchange captures a single request/response pair for evidence.
// Secrets in headers/body must be redacted by the producer before this
// struct is populated (see internal/httpclient redaction).
type HTTPExchange struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	RequestBody     string            `json:"request_body,omitempty"`
	StatusCode      int               `json:"status_code"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
	DurationMS      int64             `json:"duration_ms"`
}

// Evidence is the deterministic proof behind a finding: what was expected,
// what actually happened, and the raw exchange(s) that demonstrate it.
type Evidence struct {
	Description   string         `json:"description,omitempty"`
	Expected      string         `json:"expected,omitempty"`
	Actual        string         `json:"actual,omitempty"`
	MatchedOn     []string       `json:"matched_on,omitempty"`
	ExtractedVars map[string]any `json:"extracted_vars,omitempty"`
	Exchanges     []HTTPExchange `json:"exchanges,omitempty"`
}

// Finding is one result record - a template match, a passive check hit, an
// API test failure, whatever produced it.
type Finding struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Severity    Severity  `json:"severity"`
	Confidence  float64   `json:"confidence"` // derived from the evidence, not guessed
	Environment string    `json:"environment"`
	Target      string    `json:"target"`
	Endpoint    string    `json:"endpoint"`
	Method      string    `json:"method"`
	Template    string    `json:"template,omitempty"`
	Description string    `json:"description,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	CWE         string    `json:"cwe,omitempty"`
	OWASP       string    `json:"owasp,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Evidence    Evidence  `json:"evidence"`
	Timestamp   time.Time `json:"timestamp"`
}

// Summary aggregates findings by severity, used for gate decisions and reports.
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

func Summarize(fs []Finding) Summary {
	var s Summary
	for _, f := range fs {
		switch f.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		case SeverityInfo:
			s.Info++
		}
	}
	return s
}

// WorstSeverity returns the most severe severity present, or "" if fs is empty.
func WorstSeverity(fs []Finding) Severity {
	best := Severity("")
	bestRank := 1 << 30
	for _, f := range fs {
		if r, ok := severityRank[f.Severity]; ok && r < bestRank {
			bestRank = r
			best = f.Severity
		}
	}
	return best
}
