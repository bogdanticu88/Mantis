package smoke

import (
	"context"
	"encoding/json"
	"fmt"

	"mantis/internal/dsl"
	"mantis/internal/httpclient"
	"mantis/internal/jsonpath"
	"mantis/internal/templates"
)

type StepResult struct {
	StepID     string
	Passed     bool
	StatusCode int
	Failures   []string
}

type WorkflowResult struct {
	Workflow   *Workflow
	Passed     bool
	Skipped    bool
	SkipReason string
	Steps      []StepResult
	Vars       map[string]string
}

// RunAll executes workflows in the order given (callers should pass the
// depends_on-sorted order from LoadDir). A workflow whose dependency did not
// pass is skipped rather than run - its downstream state is unknown, so
// running it would risk asserting against a broken chain.
func RunAll(ctx context.Context, client *httpclient.Client, workflows []*Workflow, target string, baseVars map[string]string) []WorkflowResult {
	results := make([]WorkflowResult, 0, len(workflows))
	passed := map[string]bool{}

	for _, w := range workflows {
		var blockedBy string
		for _, dep := range w.DependsOn {
			if !passed[dep] {
				blockedBy = dep
				break
			}
		}
		if blockedBy != "" {
			results = append(results, WorkflowResult{
				Workflow: w, Skipped: true,
				SkipReason: fmt.Sprintf("dependency %q did not pass", blockedBy),
			})
			passed[w.ID] = false
			continue
		}
		r := Run(ctx, client, w, target, baseVars)
		results = append(results, r)
		passed[w.ID] = r.Passed
	}
	return results
}

// Run executes a single workflow's steps in order against target, stopping
// at the first failing step (later steps typically depend on its output),
// then always runs cleanup requests best-effort.
func Run(ctx context.Context, client *httpclient.Client, w *Workflow, target string, baseVars map[string]string) WorkflowResult {
	vars := map[string]string{}
	for k, v := range w.Variables {
		vars[k] = v
	}
	for k, v := range baseVars {
		vars[k] = v
	}

	result := WorkflowResult{Workflow: w, Passed: true, Vars: vars}
	for _, step := range w.Steps {
		sr := runStep(ctx, client, step, target, vars)
		result.Steps = append(result.Steps, sr)
		if !sr.Passed {
			result.Passed = false
			break
		}
	}

	for _, c := range w.Cleanup {
		req := httpclient.Request{
			Method:  c.Method,
			URL:     templates.RenderVars(templates.JoinURL(target, c.Path), vars),
			Headers: renderHeaders(c.Headers, vars),
			Body:    []byte(templates.RenderVars(c.Body, vars)),
		}
		_, _ = client.Do(ctx, req) // best-effort: cleanup failures are not test failures
	}

	return result
}

func runStep(ctx context.Context, client *httpclient.Client, step Step, target string, vars map[string]string) StepResult {
	req := httpclient.Request{
		Method:  step.Request.Method,
		URL:     templates.RenderVars(templates.JoinURL(target, step.Request.Path), vars),
		Headers: renderHeaders(step.Request.Headers, vars),
		Body:    []byte(templates.RenderVars(step.Request.Body, vars)),
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return StepResult{StepID: step.ID, Passed: false, Failures: []string{err.Error()}}
	}

	sr := StepResult{StepID: step.ID, StatusCode: resp.StatusCode, Passed: true}

	var data any
	bodyParsed := json.Unmarshal(resp.Body, &data) == nil

	for _, a := range step.Assertions {
		if ok, reason := evalAssertion(a, resp, data, bodyParsed); !ok {
			sr.Passed = false
			sr.Failures = append(sr.Failures, reason)
		}
	}

	for _, ex := range step.Extract {
		if !bodyParsed {
			continue
		}
		if v, ok := jsonpath.Get(data, ex.Path); ok {
			vars[ex.Name] = fmt.Sprintf("%v", v)
		}
	}

	return sr
}

func evalAssertion(a Assertion, resp *httpclient.Response, data any, bodyParsed bool) (bool, string) {
	if a.Status != 0 && resp.StatusCode != a.Status {
		return false, fmt.Sprintf("expected status %d, got %d", a.Status, resp.StatusCode)
	}
	if a.DSL != "" {
		env := dsl.Env{
			Vars: map[string]any{
				"status_code": int64(resp.StatusCode),
				"body":        string(resp.Body),
			},
			Funcs: dsl.DefaultFuncs(),
		}
		ok, err := dsl.EvalBool(a.DSL, env)
		if err != nil {
			return false, err.Error()
		}
		if !ok {
			return false, fmt.Sprintf("assertion failed: %s", a.DSL)
		}
	}
	if a.Path != "" {
		if !bodyParsed {
			return false, fmt.Sprintf("%s: response body is not valid JSON", a.Path)
		}
		v, exists := jsonpath.Get(data, a.Path)
		if a.Exists && !exists {
			return false, fmt.Sprintf("%s: expected to exist", a.Path)
		}
		if a.Equals != "" {
			if !exists {
				return false, fmt.Sprintf("%s: expected %q, path does not exist", a.Path, a.Equals)
			}
			if got := fmt.Sprintf("%v", v); got != a.Equals {
				return false, fmt.Sprintf("%s: expected %q, got %q", a.Path, a.Equals, got)
			}
		}
	}
	return true, ""
}

func renderHeaders(headers map[string]string, vars map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		out[k] = templates.RenderVars(v, vars)
	}
	return out
}
