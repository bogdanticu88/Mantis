package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mantis/internal/environments"
	"mantis/internal/httpclient"
	"mantis/internal/reporters"
)

// splitArgs partitions args into flag tokens and positional tokens so a
// command can accept `mantis scan <target> --flag value` as well as
// `mantis scan --flag value <target>`. The standard library's flag package
// stops parsing at the first non-flag token, which would otherwise silently
// drop every flag written after a positional target - exactly the calling
// style this CLI's own usage examples use.
func splitArgs(fs *flag.FlagSet, args []string) (flagArgs, positional []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			positional = append(positional, a)
			continue
		}
		flagArgs = append(flagArgs, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue // value embedded, no extra token consumed
		}
		if fl := fs.Lookup(name); fl != nil {
			if b, ok := fl.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
				continue // bool flags never consume the following token
			}
		}
		if i+1 < len(args) {
			i++
			flagArgs = append(flagArgs, args[i])
		}
	}
	return flagArgs, positional
}

// probeReachable does one baseline request before we bother running dozens
// of checks. Every individual check already treats a request failure as
// "this probe didn't fire" and moves on, so one broken endpoint won't kill
// a whole scan - but that also means a target that's down for everything
// would otherwise finish with zero findings and report a clean pass. Found
// this the hard way while testing against a target I'd forgotten to start.
func probeReachable(ctx context.Context, client *httpclient.Client, target string) error {
	if _, err := client.Do(ctx, httpclient.Request{Method: "GET", URL: target}); err != nil {
		return fmt.Errorf("target %s is not reachable: %w", target, err)
	}
	return nil
}

// resolveTargetAndPolicy figures out the base URL and security policy to
// run with. If envName is set, it's read from envFile (production-safe:
// resolving an unknown environment name is an error, never a silent
// downgrade to some guessed policy). If only target is set (no
// environment), it defaults to the "standard" policy - this path is for ad
// hoc, explicitly-targeted local runs, not CI environment gates.
func resolveTargetAndPolicy(envFile, envName, target string) (baseURL string, policy environments.Policy, auth *environments.AuthConfig, appName string, err error) {
	if envName != "" {
		if envFile == "" {
			envFile = "environments.yaml"
		}
		cfg, err := environments.Load(envFile)
		if err != nil {
			return "", environments.Policy{}, nil, "", fmt.Errorf("loading %s: %w", envFile, err)
		}
		res, err := environments.Resolve(cfg, envName)
		if err != nil {
			return "", environments.Policy{}, nil, "", err
		}
		base := target
		if base == "" {
			base = res.BaseURL
		}
		if base == "" {
			return "", environments.Policy{}, nil, "", fmt.Errorf("environment %q has no base_url and no --target was given", envName)
		}
		return base, res.Policy, res.Authentication, cfg.Application.Name, nil
	}

	if target == "" {
		return "", environments.Policy{}, nil, "", fmt.Errorf("no target specified: pass a target argument or --environment")
	}
	return target, environments.PolicyFor("standard"), nil, "", nil
}

func buildClient(policy environments.Policy, insecure bool, timeout time.Duration, target string, extraAllowed, denied []string) (*httpclient.Client, error) {
	allowed := extraAllowed
	if len(allowed) == 0 {
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
			allowed = []string{u.Hostname()}
		}
	}
	cfg := httpclient.Config{
		Timeout:            timeout,
		RequestsPerSecond:  policy.RateLimit,
		MaxConcurrency:     policy.MaxConcurrency,
		InsecureSkipVerify: insecure,
		AllowedHosts:       allowed,
		DeniedHosts:        denied,
		Retries:            1,
	}
	return httpclient.New(cfg)
}

// resolveAuth turns an environment's authentication config into request
// headers plus the literal secret values that need to be redacted from any
// captured evidence before it's written anywhere.
func resolveAuth(ctx context.Context, client *httpclient.Client, auth *environments.AuthConfig) (headers map[string]string, secrets []string, err error) {
	if auth == nil {
		return nil, nil, nil
	}
	switch strings.ToLower(auth.Type) {
	case "bearer":
		if auth.Token == "" {
			return nil, nil, nil
		}
		return map[string]string{"Authorization": "Bearer " + auth.Token}, []string{auth.Token}, nil

	case "basic":
		token := base64.StdEncoding.EncodeToString([]byte(auth.Username + ":" + auth.Password))
		return map[string]string{"Authorization": "Basic " + token}, []string{auth.Password, token}, nil

	case "oauth2":
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("client_id", auth.ClientID)
		form.Set("client_secret", auth.ClientSecret)
		resp, err := client.Do(ctx, httpclient.Request{
			Method:  "POST",
			URL:     auth.TokenURL,
			Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body:    []byte(form.Encode()),
		})
		if err != nil {
			return nil, nil, fmt.Errorf("oauth2: token request failed: %w", err)
		}
		var parsed struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(resp.Body, &parsed); err != nil || parsed.AccessToken == "" {
			return nil, nil, fmt.Errorf("oauth2: token response did not contain access_token")
		}
		return map[string]string{"Authorization": "Bearer " + parsed.AccessToken}, []string{auth.ClientSecret, parsed.AccessToken}, nil

	default:
		return nil, nil, nil
	}
}

// defaultReportFilenames gives each file-based format a conventional
// extension (rather than naively "mantis-report."+format) so CI systems
// that auto-discover results by glob (e.g. "**/*.xml" for JUnit) find them
// without extra configuration.
var defaultReportFilenames = map[string]string{
	"json":  "mantis-report.json",
	"sarif": "mantis-report.sarif",
	"junit": "mantis-report.junit.xml",
	"html":  "mantis-report.html",
}

// writeReports writes one or more report formats (comma-separated, e.g.
// "junit,sarif,azdo"). "azdo" is special: it always streams Azure Pipelines
// logging commands to stdout rather than a file, since that's the only
// place the pipeline agent will ever read them from.
//
// For file-based formats: if exactly one is requested and output names an
// exact path, that path is used verbatim. Otherwise each format is written
// to its conventional default filename inside outputDir (outputDir empty
// means the current directory) - this is what lets a single command produce
// a JUnit file for PublishTestResults@2 alongside a SARIF/HTML file for
// artifact publishing, at predictable paths, in one scan.
func writeReports(formatsCSV, output, outputDir string, report reporters.Report) error {
	if formatsCSV == "" {
		return nil
	}
	var formats []string
	for _, f := range strings.Split(formatsCSV, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		if f != "" {
			formats = append(formats, f)
		}
	}

	fileFormats := 0
	for _, f := range formats {
		if f != "azdo" && f != "azure-devops" {
			fileFormats++
		}
	}
	if output != "" && fileFormats > 1 {
		fmt.Fprintln(os.Stderr, "mantis: --output ignored (multiple file-based report formats requested; use --output-dir, or request one file-based format at a time)")
	}

	for _, f := range formats {
		if f == "azdo" || f == "azure-devops" {
			if err := reporters.WriteAzureDevOps(os.Stdout, report); err != nil {
				return fmt.Errorf("writing azure devops output: %w", err)
			}
			continue
		}

		var out string
		if fileFormats == 1 && output != "" {
			out = output
		} else {
			name := defaultReportFilenames[f]
			if name == "" {
				name = "mantis-report." + f
			}
			out = filepath.Join(outputDir, name)
		}

		file, err := os.Create(out)
		if err != nil {
			return fmt.Errorf("creating report file %s: %w", out, err)
		}
		werr := writeFormat(f, file, report)
		cerr := file.Close()
		if werr != nil {
			return werr
		}
		if cerr != nil {
			return cerr
		}
		fmt.Fprintf(os.Stderr, "Report written to %s\n", out)
	}
	return nil
}

func writeFormat(format string, w io.Writer, report reporters.Report) error {
	switch strings.ToLower(format) {
	case "console":
		reporters.WriteConsole(w, report)
		return nil
	case "json":
		return reporters.WriteJSON(w, report)
	case "sarif":
		return reporters.WriteSARIF(w, report)
	case "junit":
		return reporters.WriteJUnit(w, report)
	case "html":
		return reporters.WriteHTML(w, report)
	default:
		return fmt.Errorf("unknown report format %q (want json|sarif|junit|html|azdo|console)", format)
	}
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func defaultDir(candidates ...string) string {
	for _, c := range candidates {
		if fileExists(c) {
			return c
		}
	}
	return candidates[0]
}
