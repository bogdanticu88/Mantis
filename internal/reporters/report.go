// Package reporters turns a Report (findings + smoke results + gate
// outcome) into whatever format the pipeline actually needs: console
// output, JSON, SARIF, JUnit XML, HTML, or Azure DevOps logging commands.
package reporters

import (
	"time"

	"github.com/bogdanticu88/Mantis/internal/findings"
)

type SmokeStepSummary struct {
	StepID   string   `json:"step_id"`
	Passed   bool     `json:"passed"`
	Failures []string `json:"failures,omitempty"`
}

type SmokeWorkflowSummary struct {
	ID         string             `json:"id"`
	Passed     bool               `json:"passed"`
	Skipped    bool               `json:"skipped"`
	SkipReason string             `json:"skip_reason,omitempty"`
	Steps      []SmokeStepSummary `json:"steps,omitempty"`
}

// Report is the full result of a `mantis validate` (or narrower scan/dast/
// smoke/api) run, ready to hand to any reporter.
type Report struct {
	Application string                 `json:"application"`
	Environment string                 `json:"environment"`
	Target      string                 `json:"target"`
	Timestamp   time.Time              `json:"timestamp"`
	Smoke       []SmokeWorkflowSummary `json:"smoke,omitempty"`
	Findings    []findings.Finding     `json:"findings"`
	Summary     findings.Summary       `json:"summary"`
	FailOn      string                 `json:"fail_on"`
	GatePassed  bool                   `json:"gate_passed"`
	ExitCode    int                    `json:"exit_code"`
}
