package dast

import (
	"context"

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
// Right now active testing just runs the loaded templates against the
// target root. It doesn't fuzz every discovered form field yet (that's a
// real attack-module job, not something to bolt onto here), so what you get
// today is whatever the config/exposure templates catch, which happen to be
// root-relative anyway.
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
	return result, nil
}
