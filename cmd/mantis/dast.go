package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bogdanticu88/Mantis/internal/dast"
	"github.com/bogdanticu88/Mantis/internal/findings"
	"github.com/bogdanticu88/Mantis/internal/gate"
	"github.com/bogdanticu88/Mantis/internal/httpclient"
	"github.com/bogdanticu88/Mantis/internal/reporters"
	"github.com/bogdanticu88/Mantis/internal/templates"
)

func cmdDast(args []string) error {
	fs := flag.NewFlagSet("dast", flag.ExitOnError)
	environment := fs.String("environment", "", "environment name (optional; reads environments file for policy/auth)")
	envFile := fs.String("environments-file", "environments.yaml", "path to environments.yaml")
	templatesDir := fs.String("templates-dir", "templates-community", "directory of templates to run during active testing")
	failOn := fs.String("fail-on", "high", "minimum severity that fails the gate: critical|high|medium|low|any")
	report := fs.String("report", "", "comma-separated report formats to write: json,sarif,junit,html,azdo,github")
	output := fs.String("output", "", "exact report output path (only when a single file-based --report format is given)")
	outputDir := fs.String("output-dir", "", "directory for default-named report files when writing multiple formats (default: current directory)")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS certificate verification")
	timeout := fs.Duration("timeout", 15*time.Second, "per-request timeout")
	destructive := fs.Bool("destructive", false, "allow fuzzing non-GET form fields (real POST/PUT/PATCH submissions carrying injection payloads) - also requires the environment's policy to allow destructive testing")
	flagArgs, positional := splitArgs(fs, args)
	fs.Parse(flagArgs)

	target := ""
	if len(positional) > 0 {
		target = positional[0]
	}

	baseURL, policy, auth, appName, err := resolveTargetAndPolicy(*envFile, *environment, target)
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

	tpls, err := templates.LoadDir(*templatesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mantis: templates: %v\n", err)
	}

	baseVars := mergeVars(map[string]string{"BaseURL": baseURL}, authVars(headers))

	result, err := dast.Run(ctx, client, redactor, dast.Options{
		Target:      baseURL,
		Environment: *environment,
		Policy:      policy,
		Templates:   tpls,
		BaseVars:    baseVars,
		Headers:     headers,
		Destructive: destructiveAllowed,
	})
	if err != nil {
		return err
	}
	if !policy.ActiveDAST {
		fmt.Fprintf(os.Stderr, "mantis: active testing skipped (policy %q is passive-only for this environment)\n", policy.Level)
	}

	allFindings := append(append([]findings.Finding{}, result.PassiveFindings...), result.ActiveFindings...)

	rpt := reporters.Report{
		Application: appName,
		Environment: *environment,
		Target:      baseURL,
		Timestamp:   time.Now(),
		Findings:    allFindings,
		Summary:     findings.Summarize(allFindings),
		FailOn:      *failOn,
	}
	passed, exitCode := gate.Decide(*failOn, allFindings, false)
	rpt.GatePassed = passed
	rpt.ExitCode = exitCode

	fmt.Fprintf(os.Stderr, "Discovered %d URLs, %d forms\n", len(result.Surface.URLs), len(result.Surface.Forms))
	reporters.WriteConsole(os.Stdout, rpt)
	if err := writeReports(*report, *output, *outputDir, rpt, os.Stdout); err != nil {
		return err
	}
	if !passed {
		return &gateFailure{ExitCode: exitCode}
	}
	return nil
}
