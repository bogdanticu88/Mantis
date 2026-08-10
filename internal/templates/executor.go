package templates

import (
	"context"
	"fmt"
	"time"

	"mantis/internal/findings"
	"mantis/internal/httpclient"
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

// Run executes tpl's request chain against target. baseVars seeds the
// variable set (e.g. secrets resolved from an environment/auth config) and
// is layered over the template's own `variables` block. environment is
// stamped onto any resulting finding.
//
// Chain semantics: requests execute in order. A request with matchers that
// fails to match stops the chain (its extractors still ran, but later
// requests do not execute) - this lets a template express "step 2 only
// makes sense if step 1 succeeded" without a separate control-flow construct.
// A request with no matchers always "passes" and exists purely to extract
// variables for later steps (e.g. a login request).
func Run(ctx context.Context, client *httpclient.Client, redactor *httpclient.Redactor, tpl *Template, target, environment string, baseVars map[string]string) RunResult {
	vars := map[string]string{}
	for k, v := range tpl.Variables {
		vars[k] = v
	}
	for k, v := range baseVars {
		vars[k] = v
	}

	var exchanges []findings.HTTPExchange
	var matchedOn []string
	overallMatched := true
	var lastReq RequestSpec

	for _, spec := range tpl.Requests {
		lastReq = spec
		req := httpclient.Request{
			Method:  spec.Method,
			URL:     renderVars(joinURL(target, spec.Path), vars),
			Headers: renderHeaders(spec.Headers, vars),
			Body:    []byte(renderVars(spec.Body, vars)),
		}

		resp, err := client.Do(ctx, req)
		if err != nil {
			return RunResult{Template: tpl, Target: target, Vars: vars, Error: fmt.Errorf("template %s: %w", tpl.ID, err)}
		}
		exchanges = append(exchanges, redactor.Exchange(resp))

		if err := runExtractors(spec, resp, vars); err != nil {
			return RunResult{Template: tpl, Target: target, Vars: vars, Error: fmt.Errorf("template %s: %w", tpl.ID, err)}
		}

		matched, on, err := evalMatchers(spec, resp)
		if err != nil {
			return RunResult{Template: tpl, Target: target, Vars: vars, Error: fmt.Errorf("template %s: %w", tpl.ID, err)}
		}
		matchedOn = append(matchedOn, on...)
		if !matched {
			overallMatched = false
			break
		}
	}

	result := RunResult{Template: tpl, Target: target, Matched: overallMatched, Vars: vars}
	if overallMatched {
		result.Findings = []findings.Finding{{
			ID:          tpl.ID,
			Name:        tpl.Info.Name,
			Severity:    findings.Severity(tpl.Info.Severity),
			Confidence:  1.0,
			Environment: environment,
			Target:      target,
			Endpoint:    lastReq.Path,
			Method:      lastReq.Method,
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
		}}
	}
	return result
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
