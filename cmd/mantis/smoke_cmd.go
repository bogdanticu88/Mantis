package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bogdanticu88/Mantis/internal/gate"
	"github.com/bogdanticu88/Mantis/internal/reporters"
	"github.com/bogdanticu88/Mantis/internal/smoke"
)

func cmdSmoke(args []string) error {
	fs := flag.NewFlagSet("smoke", flag.ExitOnError)
	environment := fs.String("environment", "", "environment name")
	envFile := fs.String("environments-file", "environments.yaml", "path to environments.yaml")
	workflowsDir := fs.String("workflows-dir", "smoke", "directory of smoke workflow YAML files")
	target := fs.String("target", "", "target base URL (overrides environment base_url)")
	report := fs.String("report", "", "comma-separated report formats to write: json,sarif,junit,html,azdo,github")
	output := fs.String("output", "", "exact report output path (only when a single file-based --report format is given)")
	outputDir := fs.String("output-dir", "", "directory for default-named report files when writing multiple formats (default: current directory)")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS certificate verification")
	timeout := fs.Duration("timeout", 15*time.Second, "per-request timeout")
	fs.Parse(args)

	baseURL, policy, auth, appName, err := resolveTargetAndPolicy(*envFile, *environment, *target)
	if err != nil {
		return err
	}
	if !policy.Smoke {
		return fmt.Errorf("smoke testing is disabled by policy for this environment")
	}

	client, err := buildClient(policy, *insecure, *timeout, baseURL, nil, nil)
	if err != nil {
		return err
	}
	ctx := context.Background()

	if err := probeReachable(ctx, client, baseURL); err != nil {
		return err
	}

	headers, _, err := resolveAuth(ctx, client, auth)
	if err != nil {
		return err
	}
	baseVars := mergeVars(map[string]string{"BaseURL": baseURL}, authVars(headers))

	workflows, err := smoke.LoadDir(*workflowsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mantis: smoke: %v\n", err)
	}
	if len(workflows) == 0 {
		return fmt.Errorf("no valid smoke workflows found in %s", *workflowsDir)
	}

	results := smoke.RunAll(ctx, client, workflows, baseURL, baseVars)

	var summaries []reporters.SmokeWorkflowSummary
	anyFailed := false
	for _, r := range results {
		s := reporters.SmokeWorkflowSummary{ID: r.Workflow.ID, Passed: r.Passed, Skipped: r.Skipped, SkipReason: r.SkipReason}
		for _, st := range r.Steps {
			s.Steps = append(s.Steps, reporters.SmokeStepSummary{StepID: st.StepID, Passed: st.Passed, Failures: st.Failures})
		}
		summaries = append(summaries, s)
		if !r.Skipped && !r.Passed {
			anyFailed = true
		}
	}

	rpt := reporters.Report{
		Application: appName,
		Environment: *environment,
		Target:      baseURL,
		Timestamp:   time.Now(),
		Smoke:       summaries,
		FailOn:      "smoke",
	}
	passed, exitCode := gate.Decide("high", nil, anyFailed)
	rpt.GatePassed = passed
	rpt.ExitCode = exitCode

	reporters.WriteConsole(os.Stdout, rpt)
	if err := writeReports(*report, *output, *outputDir, rpt, os.Stdout); err != nil {
		return err
	}
	if !passed {
		return &gateFailure{ExitCode: exitCode}
	}
	return nil
}
