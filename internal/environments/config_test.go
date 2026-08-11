package environments

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "environments.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("writing temp environments file: %v", err)
	}
	return path
}

const sampleConfig = `
application:
  name: Payments API

environments:
  dev:
    base_url: https://dev.example.com
    security_level: aggressive
  production:
    base_url: https://api.example.com
    security_level: passive
  custom-limits:
    base_url: https://custom.example.com
    security_level: standard
    rate_limit: 1
    max_requests: 5
    allow_destructive: true
`

func TestLoadAndResolve(t *testing.T) {
	path := writeTempFile(t, sampleConfig)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Application.Name != "Payments API" {
		t.Errorf("Application.Name = %q, want %q", cfg.Application.Name, "Payments API")
	}

	res, err := Resolve(cfg, "dev")
	if err != nil {
		t.Fatalf("Resolve(dev): %v", err)
	}
	if res.BaseURL != "https://dev.example.com" {
		t.Errorf("dev BaseURL = %q", res.BaseURL)
	}
	if res.Policy.Level != LevelAggressive {
		t.Errorf("dev Policy.Level = %q, want aggressive", res.Policy.Level)
	}
}

func TestResolve_UnknownEnvironmentIsAnError(t *testing.T) {
	path := writeTempFile(t, sampleConfig)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// This is the important one: a typo'd environment name must fail loudly,
	// not silently resolve to some default target.
	if _, err := Resolve(cfg, "prod"); err == nil {
		t.Error("Resolve(\"prod\") succeeded, want an error (the real name is \"production\")")
	}
}

func TestResolve_CaseInsensitiveLookup(t *testing.T) {
	path := writeTempFile(t, sampleConfig)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	res, err := Resolve(cfg, "DEV")
	if err != nil {
		t.Fatalf("Resolve(\"DEV\"): %v", err)
	}
	if res.BaseURL != "https://dev.example.com" {
		t.Errorf("Resolve(\"DEV\").BaseURL = %q", res.BaseURL)
	}
}

func TestResolve_NilConfigFallsBackToPassive(t *testing.T) {
	res, err := Resolve(nil, "anything")
	if err != nil {
		t.Fatalf("Resolve(nil, ...) returned an error: %v", err)
	}
	if res.Policy.Level != LevelPassive {
		t.Errorf("Resolve(nil, ...).Policy.Level = %q, want passive", res.Policy.Level)
	}
	if res.BaseURL != "" {
		t.Errorf("Resolve(nil, ...).BaseURL = %q, want empty", res.BaseURL)
	}
}

func TestResolve_PerEnvironmentOverrides(t *testing.T) {
	path := writeTempFile(t, sampleConfig)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	res, err := Resolve(cfg, "custom-limits")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Policy.RateLimit != 1 {
		t.Errorf("RateLimit override = %v, want 1", res.Policy.RateLimit)
	}
	if res.Policy.MaxRequests != 5 {
		t.Errorf("MaxRequests override = %v, want 5", res.Policy.MaxRequests)
	}
	if !res.Policy.Destructive {
		t.Error("allow_destructive: true override was not applied")
	}
}

func TestLoad_ExpandsEnvVars(t *testing.T) {
	t.Setenv("MANTIS_TEST_TOKEN", "super-secret-value")
	path := writeTempFile(t, `
environments:
  dev:
    base_url: https://dev.example.com
    security_level: aggressive
    authentication:
      type: bearer
      token: ${MANTIS_TEST_TOKEN}
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	env := cfg.Environments["dev"]
	if env.Authentication == nil || env.Authentication.Token != "super-secret-value" {
		t.Errorf("token = %+v, want expanded to \"super-secret-value\"", env.Authentication)
	}
}

func TestLoad_UnresolvedEnvVarLeftVisible(t *testing.T) {
	// An unset env var should NOT silently become an empty string - that
	// would turn a missing secret into a request that just quietly has no
	// auth header, which is much harder to notice than a visibly broken
	// placeholder in the output.
	path := writeTempFile(t, `
environments:
  dev:
    base_url: https://dev.example.com
    security_level: aggressive
    authentication:
      type: bearer
      token: ${THIS_VAR_IS_DEFINITELY_NOT_SET}
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.Environments["dev"].Authentication.Token
	want := "${THIS_VAR_IS_DEFINITELY_NOT_SET}"
	if got != want {
		t.Errorf("token = %q, want %q (left untouched)", got, want)
	}
}

func TestLoad_IdentitiesExpandedAndResolved(t *testing.T) {
	t.Setenv("MANTIS_USER_A_TOKEN", "token-a")
	t.Setenv("MANTIS_USER_B_TOKEN", "token-b")
	path := writeTempFile(t, `
environments:
  test:
    base_url: https://test.example.com
    security_level: aggressive
    identities:
      - name: userA
        authentication:
          type: bearer
          token: ${MANTIS_USER_A_TOKEN}
        owns:
          account_id: "1001"
      - name: userB
        authentication:
          type: bearer
          token: ${MANTIS_USER_B_TOKEN}
        owns:
          account_id: "1002"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	ids := cfg.Environments["test"].Identities
	if len(ids) != 2 {
		t.Fatalf("got %d identities, want 2", len(ids))
	}
	if ids[0].Authentication.Token != "token-a" {
		t.Errorf("userA token = %q, want expanded to token-a", ids[0].Authentication.Token)
	}
	if ids[1].Owns["account_id"] != "1002" {
		t.Errorf("userB owns[account_id] = %q, want 1002", ids[1].Owns["account_id"])
	}

	res, err := Resolve(cfg, "test")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Identities) != 2 {
		t.Fatalf("Resolve: got %d identities, want 2", len(res.Identities))
	}
	if res.Identities[0].Name != "userA" || res.Identities[1].Name != "userB" {
		t.Errorf("Resolve: identity names = %q, %q", res.Identities[0].Name, res.Identities[1].Name)
	}
}
