package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

const sampleTemplate = `
id: test-header-check
info:
  name: Test Header Check
  severity: low
requests:
  - method: GET
    path: /
    matchers:
      - type: status
        status: [200]
`

func TestCmdScan_FlagsAfterTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeFile(t, dir, "test.yaml", sampleTemplate)

	// This is the exact style the README uses, and the exact style that
	// used to silently drop --fail-on before splitArgs existed.
	err := cmdScan([]string{srv.URL, "--templates-dir", dir, "--fail-on", "critical"})
	if err != nil {
		t.Fatalf("cmdScan returned an error: %v", err)
	}
}

func TestCmdScan_GateFailureReturnsGateFailureError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeFile(t, dir, "test.yaml", sampleTemplate) // matches status 200 -> low severity finding

	err := cmdScan([]string{srv.URL, "--templates-dir", dir, "--fail-on", "any"})
	if err == nil {
		t.Fatal("expected the gate to fail with --fail-on any and a matching low-severity template")
	}
	if _, ok := err.(*gateFailure); !ok {
		t.Errorf("error type = %T, want *gateFailure", err)
	}
}

func TestCmdScan_UnreachableTargetIsOperationalErrorNotGateFailure(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "test.yaml", sampleTemplate)

	err := cmdScan([]string{"http://127.0.0.1:1", "--templates-dir", dir})
	if err == nil {
		t.Fatal("expected an error for an unreachable target")
	}
	if _, ok := err.(*gateFailure); ok {
		t.Error("an unreachable target should be an operational error, not a security gate failure")
	}
}

func TestCmdDast_DiscoversAndReports(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/about">About</a></body></html>`))
	}))
	defer srv.Close()

	dir := t.TempDir() // empty templates dir - just testing discovery/passive wiring

	err := cmdDast([]string{srv.URL, "--templates-dir", dir, "--fail-on", "any"})
	// Missing security headers on a plain HTML response should trip --fail-on any.
	if err == nil {
		t.Fatal("expected the passive header checks to produce at least one finding")
	}
	if _, ok := err.(*gateFailure); !ok {
		t.Errorf("error type = %T, want *gateFailure", err)
	}
}

// End-to-end proof of the double-gate at the actual CLI layer: an
// environment's security_level: aggressive is not, by itself, enough to
// make `mantis dast` submit forms - --destructive has to be passed on
// this specific invocation too.
func newDestructiveTestFormServer(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	var submitCount int
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><form method="POST" action="/submit"><input name="cmd"></form></body></html>`))
	})
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		submitCount++
		w.Write([]byte("submitted"))
	})
	return httptest.NewServer(mux), &submitCount
}

func TestCmdDast_DestructiveRequiresExplicitFlagEvenUnderAggressivePolicy(t *testing.T) {
	srv, submitCount := newDestructiveTestFormServer(t)
	defer srv.Close()

	dir := t.TempDir()
	envFile := writeFile(t, dir, "environments.yaml", `
environments:
  dev:
    base_url: `+srv.URL+`
    security_level: aggressive
`)
	emptyTemplates := t.TempDir()

	// No --destructive: the form must not be submitted, even though the
	// environment's policy allows destructive testing in principle.
	if err := cmdDast([]string{"--environment", "dev", "--environments-file", envFile, "--templates-dir", emptyTemplates, "--fail-on", "critical"}); err != nil {
		if _, ok := err.(*gateFailure); !ok {
			t.Fatalf("cmdDast: %v", err)
		}
	}
	if *submitCount != 0 {
		t.Fatalf("form was submitted %d time(s) without --destructive", *submitCount)
	}

	// With --destructive: now it should be.
	if err := cmdDast([]string{"--environment", "dev", "--environments-file", envFile, "--templates-dir", emptyTemplates, "--fail-on", "critical", "--destructive"}); err != nil {
		if _, ok := err.(*gateFailure); !ok {
			t.Fatalf("cmdDast: %v", err)
		}
	}
	if *submitCount == 0 {
		t.Error("form was never submitted even with --destructive and an aggressive-policy environment")
	}
}

func TestCmdSmoke_RunsWorkflowAndPasses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeFile(t, dir, "health.yaml", `
id: health
type: smoke
steps:
  - id: check
    request:
      method: GET
      path: /
    assertions:
      - status: 200
`)

	if err := cmdSmoke([]string{"--target", srv.URL, "--workflows-dir", dir}); err != nil {
		t.Errorf("cmdSmoke returned an error for a passing workflow: %v", err)
	}
}

func TestCmdSmoke_FailingWorkflowFailsTheGate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeFile(t, dir, "health.yaml", `
id: health
type: smoke
steps:
  - id: check
    request:
      method: GET
      path: /
    assertions:
      - status: 200
`)

	err := cmdSmoke([]string{"--target", srv.URL, "--workflows-dir", dir})
	if err == nil {
		t.Fatal("expected a failing smoke assertion to fail the gate")
	}
	if _, ok := err.(*gateFailure); !ok {
		t.Errorf("error type = %T, want *gateFailure", err)
	}
}

func TestCmdAPI_RequiresScanSubcommand(t *testing.T) {
	if err := cmdAPI([]string{}); err == nil {
		t.Error("cmdAPI with no subcommand should return an error")
	}
	if err := cmdAPI([]string{"bogus"}); err == nil {
		t.Error("cmdAPI with an unrecognized subcommand should return an error")
	}
}

func TestCmdAPI_ScanFindsMissingAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // never enforces auth, regardless of what the spec declares
	}))
	defer srv.Close()

	dir := t.TempDir()
	specPath := writeFile(t, dir, "openapi.yaml", `
openapi: 3.0.0
info: {title: test, version: "1.0"}
security:
  - bearerAuth: []
paths:
  /secure:
    get:
      responses: {"200": {description: ok}}
components:
  securitySchemes:
    bearerAuth: {type: http, scheme: bearer}
`)

	err := cmdAPI([]string{"scan", "--target", srv.URL, "--openapi", specPath, "--fail-on", "any"})
	if err == nil {
		t.Fatal("expected a missing-auth finding to fail the gate")
	}
	if _, ok := err.(*gateFailure); !ok {
		t.Errorf("error type = %T, want *gateFailure", err)
	}
}

// This is the end-to-end path for item 5 of the roadmap: identities
// declared in environments.yaml should flow all the way through to a
// confirmed (not heuristic) BOLA finding.
func TestCmdAPI_ScanConfirmsBOLAFromEnvironmentIdentities(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // vulnerable: never checks resource ownership
	}))
	defer srv.Close()

	dir := t.TempDir()
	specPath := writeFile(t, dir, "openapi.yaml", `
openapi: 3.0.0
info: {title: test, version: "1.0"}
security:
  - bearerAuth: []
paths:
  /accounts/{account_id}:
    get:
      parameters:
        - name: account_id
          in: path
          required: true
          schema: {type: string}
      responses: {"200": {description: ok}}
components:
  securitySchemes:
    bearerAuth: {type: http, scheme: bearer}
`)
	envFile := writeFile(t, dir, "environments.yaml", `
environments:
  test:
    base_url: `+srv.URL+`
    security_level: aggressive
    identities:
      - name: userA
        authentication:
          type: bearer
          token: token-a
        owns:
          account_id: "1001"
      - name: userB
        authentication:
          type: bearer
          token: token-b
        owns:
          account_id: "1002"
`)

	err := cmdAPI([]string{
		"scan",
		"--environment", "test",
		"--environments-file", envFile,
		"--openapi", specPath,
		"--fail-on", "any",
	})
	if err == nil {
		t.Fatal("expected a confirmed BOLA finding to fail the gate")
	}
	if _, ok := err.(*gateFailure); !ok {
		t.Errorf("error type = %T, want *gateFailure", err)
	}
}

func TestCmdValidate_RequiresEnvironment(t *testing.T) {
	if err := cmdValidate([]string{}); err == nil {
		t.Error("cmdValidate with no --environment should return an error")
	}
}

func TestCmdValidate_EndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	envFile := writeFile(t, dir, "environments.yaml", `
application:
  name: Test App
environments:
  test:
    base_url: `+srv.URL+`
    security_level: aggressive
`)
	smokeDir := filepath.Join(dir, "smoke")
	os.MkdirAll(smokeDir, 0o755)
	writeFile(t, smokeDir, "health.yaml", `
id: health
type: smoke
steps:
  - id: check
    request:
      method: GET
      path: /api/health
    assertions:
      - status: 200
      - path: "$.status"
        equals: ok
`)
	templatesDir := filepath.Join(dir, "templates")
	os.MkdirAll(templatesDir, 0o755)
	writeFile(t, templatesDir, "test.yaml", sampleTemplate)

	err := cmdValidate([]string{
		"--environment", "test",
		"--environments-file", envFile,
		"--workflows-dir", smokeDir,
		"--templates-dir", templatesDir,
		"--fail-on", "high", // the only findings here are low-severity, so this should pass
	})
	if err != nil {
		t.Errorf("cmdValidate returned an error for a passing environment: %v", err)
	}
}

// validate.go used to wire the API-scan portion's Destructive option
// straight from policy.Destructive with no --destructive flag check at
// all - this is the regression test for that fix, proven through the
// actual cmdValidate entry point rather than by calling dast/api directly.
func TestCmdValidate_DestructiveRequiresExplicitFlagEvenUnderAggressivePolicy(t *testing.T) {
	srv, submitCount := newDestructiveTestFormServer(t)
	defer srv.Close()

	dir := t.TempDir()
	envFile := writeFile(t, dir, "environments.yaml", `
environments:
  dev:
    base_url: `+srv.URL+`
    security_level: aggressive
`)
	emptyDir := t.TempDir()

	run := func(extraArgs ...string) {
		args := append([]string{
			"--environment", "dev",
			"--environments-file", envFile,
			"--workflows-dir", emptyDir,
			"--templates-dir", emptyDir,
			"--fail-on", "critical",
		}, extraArgs...)
		if err := cmdValidate(args); err != nil {
			if _, ok := err.(*gateFailure); !ok {
				t.Fatalf("cmdValidate: %v", err)
			}
		}
	}

	run() // no --destructive
	if *submitCount != 0 {
		t.Fatalf("form was submitted %d time(s) via validate without --destructive", *submitCount)
	}

	run("--destructive")
	if *submitCount == 0 {
		t.Error("form was never submitted via validate even with --destructive and an aggressive-policy environment")
	}
}

func TestCmdTemplates_ListAndValidate(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "good.yaml", sampleTemplate)
	writeFile(t, dir, "bad.yaml", "id: bad\ninfo:\n  name: Bad\n  severity: not-real\nrequests: []\n")

	if err := cmdTemplates([]string{"list", "--templates-dir", dir}); err != nil {
		t.Errorf("templates list returned an error: %v", err)
	}

	// One bad template among good ones should fail `templates validate`
	// specifically (unlike scan/dast, which should tolerate and skip it).
	if err := cmdTemplates([]string{"validate", "--templates-dir", dir}); err == nil {
		t.Error("templates validate should fail when the directory contains an invalid template")
	}
}

func TestCmdScan_SkipsInvalidTemplateInsteadOfAborting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeFile(t, dir, "good.yaml", sampleTemplate)
	writeFile(t, dir, "bad.yaml", "id: bad\ninfo:\n  name: Bad\n  severity: not-real\nrequests: []\n")

	// This is a regression test: scan/dast used to abort the entire run if
	// even one template file in the directory failed to parse, discarding
	// every successfully-parsed template along with it.
	err := cmdScan([]string{srv.URL, "--templates-dir", dir, "--fail-on", "critical"})
	if err != nil {
		t.Errorf("cmdScan with one bad template among good ones should still run the good ones, got: %v", err)
	}
}
