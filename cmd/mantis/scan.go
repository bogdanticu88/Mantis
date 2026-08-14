package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bogdanticu88/Mantis/internal/findings"
	"github.com/bogdanticu88/Mantis/internal/gate"
	"github.com/bogdanticu88/Mantis/internal/globalmatchers"
	"github.com/bogdanticu88/Mantis/internal/httpclient"
	"github.com/bogdanticu88/Mantis/internal/reporters"
	"github.com/bogdanticu88/Mantis/internal/templates"
)

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	environment := fs.String("environment", "", "environment name (optional; reads environments file for policy/auth)")
	envFile := fs.String("environments-file", "environments.yaml", "path to environments.yaml")
	templatesDir := fs.String("templates-dir", "templates-community", "directory of templates to run")
	failOn := fs.String("fail-on", "high", "minimum severity that fails the gate: critical|high|medium|low|any")
	report := fs.String("report", "", "comma-separated report formats to write: json,sarif,junit,html,azdo,github")
	output := fs.String("output", "", "exact report output path (only when a single file-based --report format is given)")
	outputDir := fs.String("output-dir", "", "directory for default-named report files when writing multiple formats (default: current directory)")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS certificate verification")
	timeout := fs.Duration("timeout", 15*time.Second, "per-request timeout")
	clientCert := fs.String("client-cert", "", "path to PEM client certificate for mTLS")
	clientKey := fs.String("client-key", "", "path to PEM client private key for mTLS")
	oobServer := fs.String("oob-server", "", "interactsh-compatible OOB server for blind detection (e.g. https://interact.sh)")
	oobWait := fs.Duration("oob-wait", 5*time.Second, "time to wait for OOB callbacks after templates finish")
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

	client, err := buildClient(policy, *insecure, *timeout, baseURL, *clientCert, *clientKey, nil, nil)
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
	if len(tpls) == 0 {
		return fmt.Errorf("no valid templates found in %s", *templatesDir)
	}

	baseVars := mergeVars(map[string]string{"BaseURL": baseURL}, authVars(headers))
	oobSession := setupOOB(ctx, *oobServer, baseVars)

	gmHook := func(resp *httpclient.Response, target, env, path string) []findings.Finding {
		return globalmatchers.EvalAll(globalmatchers.Builtin, resp, target, env, path)
	}

	var allFindings []findings.Finding
	for _, tpl := range tpls {
		r := templates.Run(ctx, client, redactor, tpl, baseURL, *environment, baseVars, gmHook)
		if r.Error != nil {
			fmt.Fprintf(os.Stderr, "mantis: template %s: %v\n", tpl.ID, r.Error)
			continue
		}
		allFindings = append(allFindings, r.PassiveFindings...)
		allFindings = append(allFindings, r.Findings...)
	}

	allFindings = collectOOBFindings(ctx, oobSession, *oobWait, allFindings, *environment, baseURL)

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

	reporters.WriteConsole(os.Stdout, rpt)
	if err := writeReports(*report, *output, *outputDir, rpt, os.Stdout); err != nil {
		return err
	}
	if !passed {
		return &gateFailure{ExitCode: exitCode}
	}
	return nil
}
