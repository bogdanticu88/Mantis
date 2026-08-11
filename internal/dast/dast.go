package dast

import (
	"context"

	"mantis/internal/attacks"
	"mantis/internal/environments"
	"mantis/internal/findings"
	"mantis/internal/httpclient"
	"mantis/internal/templates"
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
}

// Run does discovery (crawl + inline passive checks) and then, if the
// policy allows it, active testing on top. Passive-only environments just
// stop after discovery - no active requests get sent at all.
//
// Active testing runs the loaded templates against the target root, then
// fuzzes every discovered query parameter (always, once ActiveDAST is
// permitted - GET requests only, each independently retryable) and every
// discovered form field (GET forms unconditionally, other methods only
// when the policy also allows destructive testing).
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
		Destructive: opts.Policy.Destructive,
	}
	result.ActiveFindings = append(result.ActiveFindings, attacks.FuzzQueryParams(ctx, client, redactor, surface.URLs, fuzzOpts)...)

	attackForms := make([]attacks.Form, len(surface.Forms))
	for i, f := range surface.Forms {
		attackForms[i] = attacks.Form{Action: f.Action, Method: f.Method, Inputs: f.Inputs}
	}
	result.ActiveFindings = append(result.ActiveFindings, attacks.FuzzForms(ctx, client, redactor, attackForms, fuzzOpts)...)

	return result, nil
}
