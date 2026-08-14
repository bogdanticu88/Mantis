package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bogdanticu88/Mantis/internal/api"
	"github.com/bogdanticu88/Mantis/internal/findings"
	"github.com/bogdanticu88/Mantis/internal/gate"
	"github.com/bogdanticu88/Mantis/internal/httpclient"
	"github.com/bogdanticu88/Mantis/internal/reporters"
)

func cmdAPI(args []string) error {
	if len(args) < 1 || args[0] != "scan" {
		return fmt.Errorf("usage: mantis api scan --target <url> --openapi <file> [flags]")
	}

	fs := flag.NewFlagSet("api scan", flag.ExitOnError)
	environment := fs.String("environment", "", "environment name (optional; reads environments file for policy/auth)")
	envFile := fs.String("environments-file", "environments.yaml", "path to environments.yaml")
	target := fs.String("target", "", "target base URL")
	openapiPath := fs.String("openapi", "", "path to OpenAPI/Swagger spec (required)")
	failOn := fs.String("fail-on", "high", "minimum severity that fails the gate: critical|high|medium|low|any")
	report := fs.String("report", "", "comma-separated report formats to write: json,sarif,junit,html,azdo,github")
	output := fs.String("output", "", "exact report output path (only when a single file-based --report format is given)")
	outputDir := fs.String("output-dir", "", "directory for default-named report files when writing multiple formats (default: current directory)")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS certificate verification")
	timeout := fs.Duration("timeout", 15*time.Second, "per-request timeout")
	clientCert := fs.String("client-cert", "", "path to PEM client certificate for mTLS")
	clientKey := fs.String("client-key", "", "path to PEM client private key for mTLS")
	destructive := fs.Bool("destructive", false, "allow state-changing probe requests (POST/PUT/PATCH/DELETE)")
	fs.Parse(args[1:])

	if *openapiPath == "" {
		return fmt.Errorf("--openapi is required")
	}

	baseURL, policy, auth, appName, err := resolveTargetAndPolicy(*envFile, *environment, *target)
	if err != nil {
		return err
	}

	destructiveAllowed := *destructive && policy.Destructive
	if *destructive && !policy.Destructive {
		fmt.Fprintln(os.Stderr, "mantis: --destructive requested but this environment's policy disallows it; running non-destructive probes only")
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

	// A second (third, ...) identity turns the BOLA check from a heuristic
	// into a real cross-identity confirmation - see environments.Identity.
	var apiIdentities []api.Identity
	for _, id := range resolveIdentities(*envFile, *environment) {
		idHeaders, idSecrets, err := resolveAuth(ctx, client, id.Authentication)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mantis: identity %q: %v\n", id.Name, err)
			continue
		}
		secrets = append(secrets, idSecrets...)
		apiIdentities = append(apiIdentities, api.Identity{Name: id.Name, Headers: idHeaders, Owns: id.Owns})
	}
	redactor := httpclient.NewRedactor(secrets...)

	spec, err := api.ParseOpenAPI(*openapiPath)
	if err != nil {
		return err
	}
	if len(spec.Endpoints) == 0 {
		fmt.Fprintln(os.Stderr, "mantis: no endpoints found in OpenAPI spec")
	}

	allFindings := api.Run(ctx, client, redactor, spec, api.Options{
		Target:      baseURL,
		Environment: *environment,
		AuthHeaders: headers,
		Identities:  apiIdentities,
		Destructive: destructiveAllowed,
	})

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
