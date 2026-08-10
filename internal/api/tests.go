package api

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"mantis/internal/findings"
	"mantis/internal/httpclient"
	"mantis/internal/templates"
)

var safeMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}
var allMethods = []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}

type Options struct {
	Target      string
	Environment string
	AuthHeaders map[string]string // applied to "authenticated" probes; omitted entirely for the missing-auth probe
	SampleIDs   [2]string         // two distinct sample values substituted into ID-like path params for the BOLA heuristic
	Destructive bool              // permit probing with state-changing methods (POST/PUT/PATCH/DELETE)
}

func (o Options) sampleIDs() [2]string {
	if o.SampleIDs[0] == "" && o.SampleIDs[1] == "" {
		return [2]string{"1", "2"}
	}
	return o.SampleIDs
}

// Run executes every generated API security test against spec's endpoints.
func Run(ctx context.Context, client *httpclient.Client, redactor *httpclient.Redactor, spec *Spec, opts Options) []findings.Finding {
	var out []findings.Finding
	out = append(out, checkMissingAuth(ctx, client, redactor, spec, opts)...)
	out = append(out, checkMethodAbuse(ctx, client, redactor, spec, opts)...)
	out = append(out, checkBOLA(ctx, client, redactor, spec, opts)...)
	out = append(out, checkSensitiveData(ctx, client, redactor, spec, opts)...)
	return out
}

func do(ctx context.Context, client *httpclient.Client, method, url string, headers map[string]string) (*httpclient.Response, error) {
	return client.Do(ctx, httpclient.Request{Method: method, URL: url, Headers: headers})
}

// checkMissingAuth calls every endpoint that declares a security
// requirement with no auth headers at all, and flags any that still
// respond successfully.
func checkMissingAuth(ctx context.Context, client *httpclient.Client, redactor *httpclient.Redactor, spec *Spec, opts Options) []findings.Finding {
	var out []findings.Finding
	ids := opts.sampleIDs()
	for _, ep := range spec.Endpoints {
		if !ep.RequiresAuth {
			continue
		}
		if !opts.Destructive && !safeMethods[ep.Method] {
			continue
		}
		url := templates.JoinURL(opts.Target, FillPath(ep.Path, ids[0]))
		resp, err := do(ctx, client, ep.Method, url, nil)
		if err != nil {
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			out = append(out, mkAPIFinding("MANTIS-API-MISSING-AUTH", "Endpoint accessible without authentication", findings.SeverityHigh,
				opts.Target, ep.Path, ep.Method, opts.Environment,
				fmt.Sprintf("Endpoint declares a security requirement in the OpenAPI spec but returned %d with no Authorization header sent.", resp.StatusCode),
				"CWE-306", "API2:2023-Broken Authentication", resp, redactor))
		}
	}
	return out
}

// checkMethodAbuse tries HTTP methods not declared for a path and flags any
// that unexpectedly succeed. State-changing probe methods only run when
// opts.Destructive is set.
func checkMethodAbuse(ctx context.Context, client *httpclient.Client, redactor *httpclient.Redactor, spec *Spec, opts Options) []findings.Finding {
	declared := map[string]map[string]bool{} // path -> set of declared methods
	for _, ep := range spec.Endpoints {
		if declared[ep.Path] == nil {
			declared[ep.Path] = map[string]bool{}
		}
		declared[ep.Path][ep.Method] = true
	}

	var out []findings.Finding
	ids := opts.sampleIDs()
	for path, methods := range declared {
		url := templates.JoinURL(opts.Target, FillPath(path, ids[0]))
		for _, m := range allMethods {
			if methods[m] {
				continue
			}
			if !opts.Destructive && !safeMethods[m] {
				continue
			}
			headers := opts.AuthHeaders
			resp, err := do(ctx, client, m, url, headers)
			if err != nil {
				continue
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				out = append(out, mkAPIFinding("MANTIS-API-METHOD-ABUSE", "Undeclared HTTP method accepted", findings.SeverityMedium,
					opts.Target, path, m, opts.Environment,
					fmt.Sprintf("%s is not declared for this path in the OpenAPI spec but returned %d instead of 404/405.", m, resp.StatusCode),
					"CWE-650", "API8:2023-Security Misconfiguration", resp, redactor))
			}
		}
	}
	return out
}

// checkBOLA is a heuristic: it substitutes two different sample values into
// an ID-like path parameter and flags endpoints where both authenticated
// requests return 2xx. This does NOT prove object-level authorization is
// broken (that requires two different user identities, one of whom must be
// denied) - it flags candidates for manual verification, and is reported at
// reduced confidence for exactly that reason.
func checkBOLA(ctx context.Context, client *httpclient.Client, redactor *httpclient.Redactor, spec *Spec, opts Options) []findings.Finding {
	if len(opts.AuthHeaders) == 0 {
		return nil
	}
	ids := opts.sampleIDs()
	var out []findings.Finding
	for _, ep := range spec.Endpoints {
		if !ep.RequiresAuth || ep.Method != "GET" {
			continue
		}
		if !hasIDParam(ep) {
			continue
		}

		url1 := templates.JoinURL(opts.Target, FillPath(ep.Path, ids[0]))
		url2 := templates.JoinURL(opts.Target, FillPath(ep.Path, ids[1]))
		resp1, err1 := do(ctx, client, "GET", url1, opts.AuthHeaders)
		resp2, err2 := do(ctx, client, "GET", url2, opts.AuthHeaders)
		if err1 != nil || err2 != nil {
			continue
		}
		if resp1.StatusCode == 200 && resp2.StatusCode == 200 {
			f := mkAPIFinding("MANTIS-API-BOLA-CANDIDATE", "Possible Broken Object Level Authorization (needs manual verification)", findings.SeverityMedium,
				opts.Target, ep.Path, ep.Method, opts.Environment,
				fmt.Sprintf("Requests substituting %q and %q for the same ID-like path parameter both returned 200 with the same credentials. This does not by itself prove BOLA - confirm with a second user's credentials that object %q is not theirs to access.", ids[0], ids[1], ids[1]),
				"CWE-639", "API1:2023-Broken Object Level Authorization", resp2, redactor)
			f.Confidence = 0.5
			f.Evidence.Exchanges = []findings.HTTPExchange{redactor.Exchange(resp1), redactor.Exchange(resp2)}
			out = append(out, f)
		}
	}
	return out
}

func hasIDParam(ep Endpoint) bool {
	for _, p := range ep.Parameters {
		if p.In == "path" && IsIDLike(p.Name) {
			return true
		}
	}
	// fall back to scanning the path template itself in case the spec
	// didn't declare the parameter explicitly.
	return pathParamPattern.MatchString(ep.Path) && IsIDLike(strings.Trim(pathParamPattern.FindString(ep.Path), "{}"))
}

var sensitiveKeyPattern = regexp.MustCompile(`(?i)^(password|secret|token|api_?key|ssn|social_security|credit_card|card_number|cvv)$`)

// checkSensitiveData walks GET responses' JSON bodies looking for keys that
// commonly indicate secrets or PII being returned in an API response.
func checkSensitiveData(ctx context.Context, client *httpclient.Client, redactor *httpclient.Redactor, spec *Spec, opts Options) []findings.Finding {
	ids := opts.sampleIDs()
	var out []findings.Finding
	seen := map[string]bool{}
	for _, ep := range spec.Endpoints {
		if ep.Method != "GET" || seen[ep.Path] {
			continue
		}
		seen[ep.Path] = true

		headers := map[string]string{}
		if ep.RequiresAuth {
			headers = opts.AuthHeaders
		}
		url := templates.JoinURL(opts.Target, FillPath(ep.Path, ids[0]))
		resp, err := do(ctx, client, "GET", url, headers)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		var data any
		if json.Unmarshal(resp.Body, &data) != nil {
			continue
		}
		hits := findSensitiveKeys(data, "")
		if len(hits) == 0 {
			continue
		}
		f := mkAPIFinding("MANTIS-API-SENSITIVE-DATA", "Possible sensitive data in API response", findings.SeverityMedium,
			opts.Target, ep.Path, ep.Method, opts.Environment,
			fmt.Sprintf("Response body contains field(s) matching common secret/PII key names: %s.", strings.Join(hits, ", ")),
			"CWE-213", "API3:2023-Broken Object Property Level Authorization", resp, redactor)
		f.Evidence.MatchedOn = hits
		out = append(out, f)
	}
	return out
}

func findSensitiveKeys(data any, prefix string) []string {
	var out []string
	switch t := data.(type) {
	case map[string]any:
		for k, v := range t {
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			if s, ok := v.(string); ok && s != "" && sensitiveKeyPattern.MatchString(k) {
				out = append(out, path)
				continue
			}
			out = append(out, findSensitiveKeys(v, path)...)
		}
	case []any:
		for _, v := range t {
			out = append(out, findSensitiveKeys(v, prefix)...)
		}
	}
	return out
}

func mkAPIFinding(id, name string, severity findings.Severity, target, endpoint, method, environment, description, cwe, owasp string, resp *httpclient.Response, redactor *httpclient.Redactor) findings.Finding {
	return findings.Finding{
		ID:          id,
		Name:        name,
		Severity:    severity,
		Confidence:  1.0,
		Environment: environment,
		Target:      target,
		Endpoint:    endpoint,
		Method:      method,
		Description: description,
		CWE:         cwe,
		OWASP:       owasp,
		Tags:        []string{"api"},
		Evidence: findings.Evidence{
			Description: description,
			Exchanges:   []findings.HTTPExchange{redactor.Exchange(resp)},
		},
		Timestamp: time.Now(),
	}
}
