package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bogdanticu88/Mantis/internal/api"
	"github.com/bogdanticu88/Mantis/internal/dast"
	"github.com/bogdanticu88/Mantis/internal/findings"
	"github.com/bogdanticu88/Mantis/internal/gate"
	"github.com/bogdanticu88/Mantis/internal/httpclient"
	"github.com/bogdanticu88/Mantis/internal/reporters"
	"github.com/bogdanticu88/Mantis/internal/smoke"
	"github.com/bogdanticu88/Mantis/internal/templates"
)

// cmdValidate is the actual CI/CD gate: smoke + passive DAST + active DAST
// (plus API tests if an OpenAPI spec was given), all governed by the
// target environment's policy, collapsed down into one pass/fail call.
func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	environment := fs.String("environment", "", "environment name (required)")
	envFile := fs.String("environments-file", "environments.yaml", "path to environments.yaml")
	templatesDir := fs.String("templates-dir", "templates-community", "directory of templates for active testing")
	workflowsDir := fs.String("workflows-dir", "smoke", "directory of smoke workflow YAML files")
	openapiPath := fs.String("openapi", "", "optional path to an OpenAPI spec for API security tests")
	failOn := fs.String("fail-on", "high", "minimum severity that fails the gate: critical|high|medium|low|any")
	report := fs.String("report", "", "comma-separated report formats to write: json,sarif,junit,html,azdo,github")
	output := fs.String("output", "", "exact report output path (only when a single file-based --report format is given)")
	outputDir := fs.String("output-dir", "", "directory for default-named report files when writing multiple formats (default: current directory)")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS certificate verification")
	timeout := fs.Duration("timeout", 15*time.Second, "per-request timeout")
	destructive := fs.Bool("destructive", false, "allow destructive testing (non-GET form fuzzing, state-changing API method probes) - also requires the environment's policy to allow it")
	fs.Parse(args)

	if *environment == "" {
		return fmt.Errorf("--environment is required for validate")
	}

	baseURL, policy, auth, appName, err := resolveTargetAndPolicy(*envFile, *environment, "")
	if err != nil {
		return err
	}

	destructiveAllowed := *destructive && policy.Destructive
	if *destructive && !policy.Destructive {
		fmt.Fprintln(os.Stderr, "mantis: --destructive requested but this environment's policy disallows it; running non-destructive checks only")
	}

	client, err := buildClient(policy, *insecure, *timeout, baseURL, nil, nil)
	if err != nil {
		return err
	}
	ctx := context.Background()

	if err := probeReachable(ctx, client, baseURL); err != nil {
		return err
	}

	headers, secrets, err := resolveAuth(ctx, client, auth)
	if err != nil {
		return err
	}
	redactor := httpclient.NewRedactor(secrets...)
	baseVars := mergeVars(map[string]string{"BaseURL": baseURL}, authVars(headers))

	var allFindings []findings.Finding
	var smokeSummaries []reporters.SmokeWorkflowSummary
	anySmokeFailed := false

	if policy.Smoke {
		workflows, err := smoke.LoadDir(*workflowsDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mantis: smoke: %v\n", err)
		} else {
			results := smoke.RunAll(ctx, client, workflows, baseURL, baseVars)
			for _, r := range results {
				s := reporters.SmokeWorkflowSummary{ID: r.Workflow.ID, Passed: r.Passed, Skipped: r.Skipped, SkipReason: r.SkipReason}
				for _, st := range r.Steps {
					s.Steps = append(s.Steps, reporters.SmokeStepSummary{StepID: st.StepID, Passed: st.Passed, Failures: st.Failures})
				}
				smokeSummaries = append(smokeSummaries, s)
				if !r.Skipped && !r.Passed {
					anySmokeFailed = true
				}
			}
		}
	}

	tpls, err := templates.LoadDir(*templatesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mantis: templates: %v\n", err)
	}

	dastResult, err := dast.Run(ctx, client, redactor, dast.Options{
		Target:      baseURL,
		Environment: *environment,
		Policy:      policy,
		Templates:   tpls,
		BaseVars:    baseVars,
		Headers:     headers,
		Destructive: destructiveAllowed,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mantis: dast: %v\n", err)
	} else {
		allFindings = append(allFindings, dastResult.PassiveFindings...)
		allFindings = append(allFindings, dastResult.ActiveFindings...)
	}

	if *openapiPath != "" {
		spec, err := api.ParseOpenAPI(*openapiPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mantis: api: %v\n", err)
		} else {
			apiFindings := api.Run(ctx, client, redactor, spec, api.Options{
				Target:      baseURL,
				Environment: *environment,
				AuthHeaders: headers,
				Destructive: destructiveAllowed,
			})
			allFindings = append(allFindings, apiFindings...)
		}
	}

	rpt := reporters.Report{
		Application: appName,
		Environment: *environment,
		Target:      baseURL,
		Timestamp:   time.Now(),
		Smoke:       smokeSummaries,
		Findings:    allFindings,
		Summary:     findings.Summarize(allFindings),
		FailOn:      *failOn,
	}
	passed, exitCode := gate.Decide(*failOn, allFindings, anySmokeFailed)
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
