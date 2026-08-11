package environments

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// AuthConfig describes how to authenticate against an environment. Fields
// are read from the environments file as-is - they're normally ${ENV_VAR}
// references that get expanded from the process environment at load time,
// since actual secrets have no business being committed into
// environments.yaml.
type AuthConfig struct {
	Type         string `yaml:"type"` // bearer, basic, oauth2, session
	Token        string `yaml:"token,omitempty"`
	Username     string `yaml:"username,omitempty"`
	Password     string `yaml:"password,omitempty"`
	TokenURL     string `yaml:"token_url,omitempty"`
	ClientID     string `yaml:"client_id,omitempty"`
	ClientSecret string `yaml:"client_secret,omitempty"`
	LoginPath    string `yaml:"login_path,omitempty"`
	LoginBody    string `yaml:"login_body,omitempty"`
}

// Secrets returns the resolved secret values that must never be written to
// reports or logs, for use with httpclient.NewRedactor.
func (a *AuthConfig) Secrets() []string {
	if a == nil {
		return nil
	}
	return []string{a.Token, a.Password, a.ClientSecret}
}

// Identity is a second (third, ...) set of credentials for the same
// environment, used to make the BOLA check a real cross-identity
// confirmation instead of a same-credentials heuristic. Owns maps a path
// parameter name (matching what's in the OpenAPI spec, e.g. "id" or
// "account_id") to a resource id this identity is known to own - that
// mapping is inherently test-fixture data only a human can provide, there's
// no way to discover "which account belongs to which test user" from the
// spec alone.
type Identity struct {
	Name           string            `yaml:"name"`
	Authentication *AuthConfig       `yaml:"authentication,omitempty"`
	Owns           map[string]string `yaml:"owns,omitempty"`
}

type EnvironmentConfig struct {
	BaseURL          string      `yaml:"base_url"`
	SecurityLevel    string      `yaml:"security_level"`
	Authentication   *AuthConfig `yaml:"authentication,omitempty"`
	Identities       []Identity  `yaml:"identities,omitempty"`
	RateLimit        float64     `yaml:"rate_limit,omitempty"`
	MaxConcurrency   int         `yaml:"max_concurrency,omitempty"`
	MaxCrawlDepth    int         `yaml:"max_crawl_depth,omitempty"`
	MaxRequests      int         `yaml:"max_requests,omitempty"`
	AllowDestructive *bool       `yaml:"allow_destructive,omitempty"`
	AllowedHosts     []string    `yaml:"allowed_hosts,omitempty"`
	DeniedHosts      []string    `yaml:"denied_hosts,omitempty"`
}

type ApplicationConfig struct {
	Name string `yaml:"name"`
}

type Config struct {
	Application  ApplicationConfig            `yaml:"application"`
	Environments map[string]EnvironmentConfig `yaml:"environments"`
}

// Load parses an environments.yaml file and expands ${VAR} references
// against the process environment in base_url and authentication fields.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("environments: reading %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("environments: parsing %s: %w", path, err)
	}
	for name, env := range cfg.Environments {
		env.BaseURL = expandEnv(env.BaseURL)
		env.Authentication = expandAuth(env.Authentication)
		for i, id := range env.Identities {
			id.Authentication = expandAuth(id.Authentication)
			env.Identities[i] = id
		}
		cfg.Environments[name] = env
	}
	return &cfg, nil
}

func expandAuth(a *AuthConfig) *AuthConfig {
	if a == nil {
		return nil
	}
	out := *a
	out.Token = expandEnv(out.Token)
	out.Username = expandEnv(out.Username)
	out.Password = expandEnv(out.Password)
	out.ClientID = expandEnv(out.ClientID)
	out.ClientSecret = expandEnv(out.ClientSecret)
	return &out
}

// Resolved is a fully resolved environment ready to drive an httpclient and
// engine run: base URL, policy limits, and authentication.
type Resolved struct {
	Name           string
	BaseURL        string
	Policy         Policy
	Authentication *AuthConfig
	Identities     []Identity
	AllowedHosts   []string
	DeniedHosts    []string
}

// Resolve looks up name in cfg and computes its effective policy. If cfg is
// nil or name isn't present, it still succeeds but returns the safest
// (passive) policy with no base URL - callers must supply target/policy
// overrides explicitly in that case. This means an operator can never get
// aggressive/active/destructive testing merely by mistyping an environment
// name.
func Resolve(cfg *Config, name string) (Resolved, error) {
	r := Resolved{Name: name, Policy: PolicyFor("")}
	if cfg == nil {
		return r, nil
	}
	env, ok := lookupEnv(cfg.Environments, name)
	if !ok {
		return r, fmt.Errorf("environments: %q is not defined in the environments file", name)
	}

	policy := PolicyFor(env.SecurityLevel)
	if env.RateLimit > 0 {
		policy.RateLimit = env.RateLimit
	}
	if env.MaxConcurrency > 0 {
		policy.MaxConcurrency = env.MaxConcurrency
	}
	if env.MaxCrawlDepth > 0 {
		policy.MaxCrawlDepth = env.MaxCrawlDepth
	}
	if env.MaxRequests > 0 {
		policy.MaxRequests = env.MaxRequests
	}
	if env.AllowDestructive != nil {
		policy.Destructive = *env.AllowDestructive
	}

	r.BaseURL = env.BaseURL
	r.Policy = policy
	r.Authentication = env.Authentication
	r.Identities = env.Identities
	r.AllowedHosts = env.AllowedHosts
	r.DeniedHosts = env.DeniedHosts
	return r, nil
}

func lookupEnv(envs map[string]EnvironmentConfig, name string) (EnvironmentConfig, bool) {
	if e, ok := envs[name]; ok {
		return e, true
	}
	lname := strings.ToLower(name)
	for k, e := range envs {
		if strings.ToLower(k) == lname {
			return e, true
		}
	}
	return EnvironmentConfig{}, false
}

var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)\}`)

func expandEnv(s string) string {
	return envVarPattern.ReplaceAllStringFunc(s, func(m string) string {
		name := envVarPattern.FindStringSubmatch(m)[1]
		if v, ok := os.LookupEnv(name); ok {
			return v
		}
		return m
	})
}
