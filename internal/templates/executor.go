package templates

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bogdanticu88/Mantis/internal/findings"
	"github.com/bogdanticu88/Mantis/internal/httpclient"
)

// RunResult is the outcome of executing one template against one target.
type RunResult struct {
	Template *Template
	Target   string
	Matched  bool
	Findings []findings.Finding
	Vars     map[string]string
	Error    error
}

// Run executes tpl against target. baseVars seeds the variable set (e.g.
// secrets resolved from an environment/auth config) and is layered over the
// template's own `variables` block. environment is stamped onto any finding.
//
// Payload semantics: when the template defines a `payloads` block, Run
// iterates over each payload combination (sniper or pitchfork, controlled by
// the `attack` field) and executes the full request chain once per
// combination. All matching combinations contribute findings to the result.
// A connection error on one combination does not abort the rest.
//
// Chain semantics: requests execute in order. A request with matchers that
// fails to match stops the chain. A request with no matchers always passes and
// exists purely to extract variables for later steps.
//
// Multi-path semantics: when a request spec uses `paths` instead of `path`,
// each path is tried independently. Every path that matches produces its own
// finding. For intermediate chain steps, execution stops at the first matching
// path so the next step has a single, deterministic context.
func Run(ctx context.Context, client *httpclient.Client, redactor *httpclient.Redactor, tpl *Template, target, environment string, baseVars map[string]string) RunResult {
	vars := make(map[string]string, len(tpl.Variables)+len(baseVars))
	for k, v := range tpl.Variables {
		vars[k] = v
	}
	for k, v := range baseVars {
		vars[k] = v
	}

	combos := generatePayloadCombinations(tpl)
	if len(combos) == 0 {
		return executeChain(ctx, client, redactor, tpl, target, environment, vars)
	}

	var allFindings []findings.Finding
	for _, combo := range combos {
		iterVars := make(map[string]string, len(vars)+len(combo))
		for k, v := range vars {
			iterVars[k] = v
		}
		for k, v := range combo {
			iterVars[k] = v
		}
		r := executeChain(ctx, client, redactor, tpl, target, environment, iterVars)
		if r.Error != nil {
			// A transport error on one payload does not abort the rest of the
			// set. The caller can correlate by inspecting findings vs payloads.
			continue
		}
		allFindings = append(allFindings, r.Findings...)
	}

	return RunResult{
		Template: tpl,
		Target:   target,
		Matched:  len(allFindings) > 0,
		Findings: allFindings,
		Vars:     vars,
	}
}

// executeChain runs tpl's request chain exactly once with the given vars.
func executeChain(ctx context.Context, client *httpclient.Client, redactor *httpclient.Redactor, tpl *Template, target, environment string, vars map[string]string) RunResult {
	var allExchanges []findings.HTTPExchange
	chainMatched := true
	var chainFindings []findings.Finding

	for i, spec := range tpl.Requests {
		isLast := i == len(tpl.Requests)-1
		paths := spec.allPaths()
		specMatched := false

		for _, path := range paths {
			req := httpclient.Request{
				Method:  spec.Method,
				URL:     renderVars(joinURL(target, path), vars),
				Headers: renderHeaders(spec.Headers, vars),
				Body:    []byte(renderVars(spec.Body, vars)),
			}

			resp, err := client.Do(ctx, req)
			if err != nil {
				return RunResult{Template: tpl, Target: target, Vars: vars, Error: fmt.Errorf("template %s: %w", tpl.ID, err)}
			}
			allExchanges = append(allExchanges, redactor.Exchange(resp))

			if err := runExtractors(spec, resp, vars); err != nil {
				return RunResult{Template: tpl, Target: target, Vars: vars, Error: fmt.Errorf("template %s: %w", tpl.ID, err)}
			}

			matched, on, err := evalMatchers(spec, resp)
			if err != nil {
				return RunResult{Template: tpl, Target: target, Vars: vars, Error: fmt.Errorf("template %s: %w", tpl.ID, err)}
			}

			if matched {
				specMatched = true
				if isLast {
					chainFindings = append(chainFindings, newFinding(tpl, target, path, spec.Method, environment, on, allExchanges, vars))
				}
				// Intermediate steps always stop at first match so the next
				// step has a single, deterministic context to build on.
				if !isLast || spec.StopAtFirstMatch {
					break
				}
			}
		}

		if !specMatched && len(spec.Matchers) > 0 {
			chainMatched = false
			break
		}
	}

	result := RunResult{Template: tpl, Target: target, Matched: chainMatched && len(chainFindings) > 0, Vars: vars}
	if result.Matched {
		result.Findings = chainFindings
	}
	return result
}

// generatePayloadCombinations builds the sequence of variable maps to merge
// into vars for each payload run. Returns nil when no payloads are defined
// (the template runs the chain exactly once with its base variables).
func generatePayloadCombinations(tpl *Template) []map[string]string {
	if len(tpl.Payloads) == 0 {
		return nil
	}
	if strings.ToLower(tpl.Attack) == "pitchfork" {
		return pitchforkCombos(tpl.Payloads)
	}
	return sniperCombos(tpl.Payloads)
}

// sniperCombos iterates the single payload set one value at a time.
// Validate() ensures sniper mode never has more than one set.
func sniperCombos(payloads map[string][]string) []map[string]string {
	for name, values := range payloads {
		combos := make([]map[string]string, len(values))
		for i, v := range values {
			combos[i] = map[string]string{name: v}
		}
		return combos
	}
	return nil
}

// pitchforkCombos zips all payload sets in lockstep, stopping at the shortest.
// Names are sorted so iteration order is deterministic regardless of map order.
func pitchforkCombos(payloads map[string][]string) []map[string]string {
	names := sortedKeys(payloads)

	minLen := len(payloads[names[0]])
	for _, name := range names[1:] {
		if l := len(payloads[name]); l < minLen {
			minLen = l
		}
	}

	combos := make([]map[string]string, minLen)
	for i := range combos {
		combo := make(map[string]string, len(names))
		for _, name := range names {
			combo[name] = payloads[name][i]
		}
		combos[i] = combo
	}
	return combos
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func newFinding(tpl *Template, target, path, method, environment string, matchedOn []string, exchanges []findings.HTTPExchange, vars map[string]string) findings.Finding {
	return findings.Finding{
		ID:          tpl.ID,
		Name:        tpl.Info.Name,
		Severity:    findings.Severity(tpl.Info.Severity),
		Confidence:  1.0,
		Environment: environment,
		Target:      target,
		Endpoint:    path,
		Method:      method,
		Template:    tpl.ID,
		Description: tpl.Info.Description,
		Remediation: tpl.Info.Remediation,
		CWE:         tpl.Info.CWE,
		OWASP:       tpl.Info.OWASP,
		Tags:        tpl.Info.Tags,
		Evidence: findings.Evidence{
			Description:   "Template matched, indicating the condition it tests for is present.",
			MatchedOn:     matchedOn,
			ExtractedVars: toAnyMap(vars),
			Exchanges:     exchanges,
		},
		Timestamp: time.Now(),
	}
}

func renderHeaders(headers map[string]string, vars map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		out[k] = renderVars(v, vars)
	}
	return out
}

func toAnyMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
