package main

import (
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"mantis/internal/httpclient"
	"mantis/internal/reporters"
)

// This is a direct regression test for the flag-ordering bug found while
// testing against a live target: `mantis scan <target> --fail-on high`
// silently dropped every flag after the target, because the stdlib flag
// package stops parsing at the first non-flag token.
func TestSplitArgs_FlagsBeforeAndAfterPositional(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	failOn := fs.String("fail-on", "high", "")
	insecure := fs.Bool("insecure-skip-verify", false, "")

	cases := [][]string{
		{"https://example.com", "--fail-on", "critical", "--insecure-skip-verify"},
		{"--fail-on", "critical", "--insecure-skip-verify", "https://example.com"},
		{"--fail-on", "critical", "https://example.com", "--insecure-skip-verify"},
	}
	for _, args := range cases {
		*failOn = "high"
		*insecure = false
		flagArgs, positional := splitArgs(fs, args)
		if err := fs.Parse(flagArgs); err != nil {
			t.Fatalf("args=%v: fs.Parse: %v", args, err)
		}
		if *failOn != "critical" {
			t.Errorf("args=%v: --fail-on = %q, want critical", args, *failOn)
		}
		if !*insecure {
			t.Errorf("args=%v: --insecure-skip-verify was not applied", args)
		}
		if len(positional) != 1 || positional[0] != "https://example.com" {
			t.Errorf("args=%v: positional = %v, want [https://example.com]", args, positional)
		}
	}
}

func TestSplitArgs_BoolFlagDoesNotConsumeNextToken(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Bool("insecure-skip-verify", false, "")

	flagArgs, positional := splitArgs(fs, []string{"--insecure-skip-verify", "https://example.com"})
	if len(flagArgs) != 1 || flagArgs[0] != "--insecure-skip-verify" {
		t.Errorf("flagArgs = %v, want just [--insecure-skip-verify] (the target should not be swallowed as its value)", flagArgs)
	}
	if len(positional) != 1 || positional[0] != "https://example.com" {
		t.Errorf("positional = %v, want [https://example.com]", positional)
	}
}

func TestSplitArgs_EqualsSyntax(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	failOn := fs.String("fail-on", "high", "")

	flagArgs, _ := splitArgs(fs, []string{"target", "--fail-on=critical"})
	if err := fs.Parse(flagArgs); err != nil {
		t.Fatalf("fs.Parse: %v", err)
	}
	if *failOn != "critical" {
		t.Errorf("--fail-on=critical was not applied, got %q", *failOn)
	}
}

// This is a direct regression test for the dead-target bug: every
// individual check treats a request failure as "this probe didn't fire"
// and moves on, which used to mean a completely unreachable target quietly
// produced zero findings and a clean pass.
func TestProbeReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, err := httpclient.New(httpclient.Config{})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}

	if err := probeReachable(context.Background(), client, srv.URL); err != nil {
		t.Errorf("probeReachable against a live server returned an error: %v", err)
	}
	if err := probeReachable(context.Background(), client, "http://127.0.0.1:1"); err == nil {
		t.Error("probeReachable against an unreachable target should return an error")
	}
}

func TestAuthVarsAndMergeVars(t *testing.T) {
	vars := authVars(map[string]string{"Authorization": "Bearer sometoken", "X-Other": "ignored"})
	if vars["MANTIS_TOKEN"] != "sometoken" {
		t.Errorf("MANTIS_TOKEN = %q, want sometoken", vars["MANTIS_TOKEN"])
	}
	if vars["MANTIS_AUTH_HEADER"] != "Bearer sometoken" {
		t.Errorf("MANTIS_AUTH_HEADER = %q", vars["MANTIS_AUTH_HEADER"])
	}

	merged := mergeVars(map[string]string{"a": "1", "b": "1"}, map[string]string{"b": "2"})
	if merged["a"] != "1" || merged["b"] != "2" {
		t.Errorf("mergeVars = %v, want a=1 b=2 (later maps win)", merged)
	}
}

func TestWriteReports_SingleFormatUsesExactOutputPath(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "custom-name.json")
	if err := writeReports("json", out, "", reporters.Report{}); err != nil {
		t.Fatalf("writeReports: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("expected report at %s: %v", out, err)
	}
}

func TestWriteReports_MultipleFormatsUseConventionalNames(t *testing.T) {
	dir := t.TempDir()
	if err := writeReports("json,junit", "", dir, reporters.Report{}); err != nil {
		t.Fatalf("writeReports: %v", err)
	}
	for _, name := range []string{"mantis-report.json", "mantis-report.junit.xml"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
		}
	}
}

func TestWriteReports_AzdoNeverWritesAFile(t *testing.T) {
	dir := t.TempDir()
	if err := writeReports("azdo", "", dir, reporters.Report{GatePassed: true}); err != nil {
		t.Fatalf("writeReports: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("azdo format wrote %d file(s) to disk, want 0 (it must only ever go to stdout)", len(entries))
	}
}

func TestResolveTargetAndPolicy_NoTargetNoEnvironment(t *testing.T) {
	if _, _, _, _, err := resolveTargetAndPolicy("", "", ""); err == nil {
		t.Error("expected an error when neither a target nor an environment is given")
	}
}

func TestResolveTargetAndPolicy_UnknownEnvironmentFails(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "environments.yaml")
	os.WriteFile(envFile, []byte("environments:\n  dev:\n    base_url: https://dev.example.com\n    security_level: standard\n"), 0o644)

	if _, _, _, _, err := resolveTargetAndPolicy(envFile, "typo-env", ""); err == nil {
		t.Error("expected an error for an environment name that isn't in the file")
	}
}
