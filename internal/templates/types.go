// Package templates is the template engine: parsing the YAML, rendering
// variables, chaining requests, running matchers/extractors, and turning a
// match into a findings.Finding.
package templates

import (
	"fmt"
	"strings"
)

type Info struct {
	Name        string   `yaml:"name"`
	Severity    string   `yaml:"severity"`
	Tags        []string `yaml:"tags,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Remediation string   `yaml:"remediation,omitempty"`
	CWE         string   `yaml:"cwe,omitempty"`
	OWASP       string   `yaml:"owasp,omitempty"`
}

var validSeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "info": true,
}

// Matcher describes a single condition evaluated against a response.
// Type is one of: status, word, regex, json, dsl, timing.
type Matcher struct {
	Type string `yaml:"type"`

	// status
	Status []int `yaml:"status,omitempty"`

	// word / regex
	Words     []string `yaml:"words,omitempty"`
	Regex     []string `yaml:"regex,omitempty"`
	Part      string   `yaml:"part,omitempty"`      // body (default), header, all
	Condition string   `yaml:"condition,omitempty"` // and/or across Words/Regex, default "or"

	// json
	Path  string `yaml:"path,omitempty"`
	Value string `yaml:"value,omitempty"` // empty = existence check only

	// dsl
	DSL string `yaml:"dsl,omitempty"`

	// timing: matches when the response took >= MinDurationMS milliseconds.
	// Useful for detecting blind time-based injection (SQLi, SSRF delays, etc.)
	// where the payload causes the server to sleep before responding.
	MinDurationMS int64 `yaml:"duration_ms,omitempty"`

	Negative bool `yaml:"negative,omitempty"`
}

// Extractor pulls a named variable out of a response for use by later
// requests in the same template (chaining) or for evidence.
type Extractor struct {
	Type   string `yaml:"type"` // json, regex, header
	Name   string `yaml:"name"`
	Path   string `yaml:"path,omitempty"`   // json
	Regex  string `yaml:"regex,omitempty"`  // regex
	Group  int    `yaml:"group,omitempty"`  // regex capture group, default 0 (whole match)
	Header string `yaml:"header,omitempty"` // header
}

// RequestSpec is one HTTP request in a template's chain.
type RequestSpec struct {
	Method string   `yaml:"method"`
	Path   string   `yaml:"path,omitempty"`  // single path; use Path or Paths, not both
	Paths  []string `yaml:"paths,omitempty"` // multiple paths tried independently

	// StopAtFirstMatch only applies when Paths is used. When false (default)
	// every matching path produces its own finding. Set to true for templates
	// that only need to know whether any path is reachable.
	StopAtFirstMatch bool `yaml:"stop-at-first-match,omitempty"`

	Headers map[string]string `yaml:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty"`

	// When is an optional DSL expression (same syntax as dsl matchers) that
	// gates whether this request runs at all. It is evaluated against the
	// variables extracted by earlier steps in the chain. A false result skips
	// the request without failing the chain, allowing templates to branch on
	// what earlier steps discovered.
	//
	//   when: 'csrf_token != ""'
	//   when: 'contains(content_type, "application/json")'
	When string `yaml:"when,omitempty"`

	MatchersCondition string      `yaml:"matchers-condition,omitempty"` // and (default) / or, across Matchers
	Matchers          []Matcher   `yaml:"matchers,omitempty"`
	Extractors        []Extractor `yaml:"extractors,omitempty"`
}

// allPaths returns the effective path list. A single Path is wrapped in a
// slice so the executor never needs to branch on which field was used.
func (r RequestSpec) allPaths() []string {
	if len(r.Paths) > 0 {
		return r.Paths
	}
	return []string{r.Path}
}

// Template is one template file: an id, some info for reporting, and a
// chain of one or more requests to run.
type Template struct {
	ID        string            `yaml:"id"`
	Info      Info              `yaml:"info"`
	Variables map[string]string `yaml:"variables,omitempty"`

	// Payloads defines named lists of values to inject into request
	// placeholders. Each placeholder {{name}} or ${name} in a request's
	// path, body, or headers is replaced with the current payload value.
	//
	//   payloads:
	//     injection: ["'", "' OR 1=1--", "1; DROP TABLE users--"]
	//
	// Use attack to control how multiple payload sets are combined.
	Payloads map[string][]string `yaml:"payloads,omitempty"`

	// Attack controls how payload sets are combined when there is more than
	// one. "sniper" (default) supports exactly one payload set. "pitchfork"
	// zips multiple sets in lockstep, stopping at the shortest.
	Attack string `yaml:"attack,omitempty"`

	Requests []RequestSpec `yaml:"requests"`

	SourcePath string `yaml:"-"`
}

// Validate checks structural correctness. It does not execute anything.
func (t *Template) Validate() error {
	if t.ID == "" {
		return fmt.Errorf("template %s: missing id", t.SourcePath)
	}
	if t.Info.Name == "" {
		return fmt.Errorf("template %s: info.name is required", t.ID)
	}
	if !validSeverities[t.Info.Severity] {
		return fmt.Errorf("template %s: invalid severity %q (want one of critical/high/medium/low/info)", t.ID, t.Info.Severity)
	}
	if len(t.Requests) == 0 {
		return fmt.Errorf("template %s: at least one request is required", t.ID)
	}
	for i, r := range t.Requests {
		if r.Method == "" {
			return fmt.Errorf("template %s: requests[%d]: method is required", t.ID, i)
		}
		if r.Path == "" && len(r.Paths) == 0 {
			return fmt.Errorf("template %s: requests[%d]: path or paths is required", t.ID, i)
		}
		if r.Path != "" && len(r.Paths) > 0 {
			return fmt.Errorf("template %s: requests[%d]: use either path or paths, not both", t.ID, i)
		}
		for j, m := range r.Matchers {
			if err := m.validate(); err != nil {
				return fmt.Errorf("template %s: requests[%d]: matchers[%d]: %w", t.ID, i, j, err)
			}
		}
		for j, ex := range r.Extractors {
			if err := ex.validate(); err != nil {
				return fmt.Errorf("template %s: requests[%d]: extractors[%d]: %w", t.ID, i, j, err)
			}
		}
	}

	// Payload validation.
	if len(t.Payloads) > 0 {
		mode := strings.ToLower(t.Attack)
		switch mode {
		case "", "sniper":
			if len(t.Payloads) > 1 {
				return fmt.Errorf("template %s: sniper attack mode supports exactly one payload set; use attack: pitchfork or clusterbomb for multiple sets", t.ID)
			}
		case "pitchfork":
			// Multiple sets are fine; they are zipped in lockstep.
		case "clusterbomb":
			// Multiple sets produce a Cartesian product; any count is valid.
		default:
			return fmt.Errorf("template %s: unknown attack mode %q (want sniper, pitchfork, or clusterbomb)", t.ID, t.Attack)
		}
		for name, vals := range t.Payloads {
			if len(vals) == 0 {
				return fmt.Errorf("template %s: payload set %q is empty", t.ID, name)
			}
		}
	} else if t.Attack != "" {
		return fmt.Errorf("template %s: attack mode %q set but no payloads defined", t.ID, t.Attack)
	}

	return nil
}

func (m Matcher) validate() error {
	switch m.Type {
	case "status":
		if len(m.Status) == 0 {
			return fmt.Errorf("status matcher requires at least one status code")
		}
	case "word":
		if len(m.Words) == 0 {
			return fmt.Errorf("word matcher requires at least one word")
		}
	case "regex":
		if len(m.Regex) == 0 {
			return fmt.Errorf("regex matcher requires at least one pattern")
		}
	case "json":
		if m.Path == "" {
			return fmt.Errorf("json matcher requires a path")
		}
	case "dsl":
		if m.DSL == "" {
			return fmt.Errorf("dsl matcher requires an expression")
		}
	case "timing":
		if m.MinDurationMS <= 0 {
			return fmt.Errorf("timing matcher requires duration_ms > 0")
		}
	default:
		return fmt.Errorf("unknown matcher type %q", m.Type)
	}
	return nil
}

func (e Extractor) validate() error {
	if e.Name == "" {
		return fmt.Errorf("extractor requires a name")
	}
	switch e.Type {
	case "json":
		if e.Path == "" {
			return fmt.Errorf("json extractor requires a path")
		}
	case "regex":
		if e.Regex == "" {
			return fmt.Errorf("regex extractor requires a pattern")
		}
	case "header":
		if e.Header == "" {
			return fmt.Errorf("header extractor requires a header name")
		}
	default:
		return fmt.Errorf("unknown extractor type %q", e.Type)
	}
	return nil
}
