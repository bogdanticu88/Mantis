package dast

import (
	"context"

	"github.com/bogdanticu88/Mantis/internal/attacks"
	"github.com/bogdanticu88/Mantis/internal/environments"
	"github.com/bogdanticu88/Mantis/internal/findings"
	"github.com/bogdanticu88/Mantis/internal/httpclient"
	"github.com/bogdanticu88/Mantis/internal/templates"
)

type Result struct {
	Surface         *AttackSurface
	PassiveFindings []findings.Finding
	ActiveFindings  []findings.Finding
}

type Options struct {
	Target      string
	Environment string
	Policy      environments.Policy
	Templates   []*templates.Template
	BaseVars    map[string]string
	Headers     map[string]string // applied to crawl requests, e.g. resolved auth (authenticated crawling)

	// Destructive must be true for non-GET form fields to get fuzzed (real
	// POST/PUT/PATCH submissions carrying injection payloads - this creates
	// real records/side effects in the target if it doesn't reject the
	// input). This is deliberately a second, explicit gate on top of
	// Policy.Destructive: an environment's security_level: aggressive
	// authorizes destructive testing in principle, but doesn't by itself
	// run it on any given invocation - the caller (cmd/mantis) only sets
	// this when --destructive was passed on that specific command, the
	// same double-gate api.Options.Destructive already used. One YAML line
	// should never be enough, forever, to make every future `mantis
	// validate` run start submitting forms.
	Destructive bool
}

// Run does discovery (crawl + inline passive checks) and then, if the
// policy allows it, active testing on top. Passive-only environments just
// stop after discovery - no active requests get sent at all.
//
// Active testing runs the loaded templates against the target root, then
// fuzzes every discovered query parameter (always, once ActiveDAST is
// permitted - GET requests only, each independently retryable) and every
// discovered form field (GET forms unconditionally, other methods only
// when Destructive is set).
func Run(ctx context.Context, client *httpclient.Client, redactor *httpclient.Redactor, opts Options) (*Result, error) {
	crawler := &Crawler{
		Client:      client,
		MaxDepth:    opts.Policy.MaxCrawlDepth,
		MaxRequests: opts.Policy.MaxRequests,
		Headers:     opts.Headers,
	}
	surface, passiveFindings, err := crawler.Crawl(ctx, opts.Target, opts.Environment, redactor)
	if err != nil {
		return nil, err
	}

	result := &Result{Surface: surface, PassiveFindings: passiveFindings}
	if !opts.Policy.ActiveDAST {
		return result, nil
	}

	for _, tpl := range opts.Templates {
		r := templates.Run(ctx, client, redactor, tpl, opts.Target, opts.Environment, opts.BaseVars)
		if r.Error != nil {
			continue
		}
		result.ActiveFindings = append(result.ActiveFindings, r.Findings...)
	}

	fuzzOpts := attacks.Options{
		Environment: opts.Environment,
		MaxRequests: opts.Policy.MaxRequests,
		Destructive: opts.Destructive,
	}
	result.ActiveFindings = append(result.ActiveFindings, attacks.FuzzQueryParams(ctx, client, redactor, surface.URLs, fuzzOpts)...)

	attackForms := make([]attacks.Form, len(surface.Forms))
	for i, f := range surface.Forms {
		attackForms[i] = attacks.Form{Action: f.Action, Method: f.Method, Inputs: f.Inputs}
	}
	result.ActiveFindings = append(result.ActiveFindings, attacks.FuzzForms(ctx, client, redactor, attackForms, fuzzOpts)...)
	result.ActiveFindings = append(result.ActiveFindings, attacks.FuzzHeaders(ctx, client, redactor, surface.URLs, fuzzOpts)...)
	result.ActiveFindings = append(result.ActiveFindings, attacks.FuzzCookies(ctx, client, redactor, surface.Cookies, surface.URLs, fuzzOpts)...)

	return result, nil
}
