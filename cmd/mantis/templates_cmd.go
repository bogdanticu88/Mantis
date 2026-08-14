package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bogdanticu88/Mantis/internal/environments"
	"github.com/bogdanticu88/Mantis/internal/httpclient"
	"github.com/bogdanticu88/Mantis/internal/templates"
)

func cmdTemplates(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mantis templates list|validate|test [flags]")
	}
	switch args[0] {
	case "list":
		return templatesList(args[1:])
	case "validate":
		return templatesValidate(args[1:])
	case "test":
		return templatesTest(args[1:])
	default:
		return fmt.Errorf("unknown templates subcommand %q", args[0])
	}
}

func templatesList(args []string) error {
	fs := flag.NewFlagSet("templates list", flag.ExitOnError)
	dir := fs.String("templates-dir", "templates-community", "directory of templates")
	fs.Parse(args)

	tpls, err := templates.LoadDir(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mantis: %v\n", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSEVERITY\tNAME\tTAGS")
	for _, t := range tpls {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", t.ID, t.Info.Severity, t.Info.Name, strings.Join(t.Info.Tags, ","))
	}
	return w.Flush()
}

func templatesValidate(args []string) error {
	fs := flag.NewFlagSet("templates validate", flag.ExitOnError)
	dir := fs.String("templates-dir", "templates-community", "directory of templates")
	fs.Parse(args)

	tpls, err := templates.LoadDir(*dir)
	fmt.Printf("%d template(s) valid\n", len(tpls))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return fmt.Errorf("template validation failed")
	}
	return nil
}

func templatesTest(args []string) error {
	fs := flag.NewFlagSet("templates test", flag.ExitOnError)
	file := fs.String("template", "", "path to a single template file to test (required)")
	target := fs.String("target", "", "target base URL (required)")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS certificate verification")
	timeout := fs.Duration("timeout", 15*time.Second, "per-request timeout")
	clientCert := fs.String("client-cert", "", "path to PEM client certificate for mTLS")
	clientKey := fs.String("client-key", "", "path to PEM client private key for mTLS")
	fs.Parse(args)

	if *file == "" || *target == "" {
		return fmt.Errorf("--template and --target are required")
	}

	tpl, err := templates.Load(*file)
	if err != nil {
		return err
	}

	client, err := buildClient(environments.PolicyFor("standard"), *insecure, *timeout, *target, *clientCert, *clientKey, nil, nil)
	if err != nil {
		return err
	}
	redactor := httpclient.NewRedactor()

	r := templates.Run(context.Background(), client, redactor, tpl, *target, "", map[string]string{"BaseURL": *target})
	if r.Error != nil {
		return r.Error
	}
	if r.Matched {
		fmt.Printf("MATCHED: %s\n", tpl.ID)
		for _, f := range r.Findings {
			fmt.Printf("  severity=%s matched_on=%v\n", f.Severity, f.Evidence.MatchedOn)
		}
	} else {
		fmt.Printf("NO MATCH: %s\n", tpl.ID)
	}
	return nil
}
