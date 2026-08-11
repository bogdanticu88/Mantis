package main

import (
	"fmt"
	"os"
)

// version, commit and date are set at build time via -ldflags, e.g.:
//
//	go build -ldflags "-X main.version=v0.2.0 -X main.commit=$(git rev-parse --short HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" ./cmd/mantis
//
// Left at their defaults for a plain `go build`/`go run`.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "scan":
		err = cmdScan(os.Args[2:])
	case "dast":
		err = cmdDast(os.Args[2:])
	case "smoke":
		err = cmdSmoke(os.Args[2:])
	case "api":
		err = cmdAPI(os.Args[2:])
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "templates":
		err = cmdTemplates(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("mantis %s (commit %s, built %s)\n", version, commit, date)
		return
	case "-h", "--help", "help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "mantis: unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}

	if err != nil {
		if ge, ok := err.(*gateFailure); ok {
			os.Exit(ge.ExitCode)
		}
		fmt.Fprintf(os.Stderr, "mantis: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `mantis - CI/CD-native application validation and DAST engine

Usage:
  mantis scan <target> [flags]           Template-driven scan
  mantis dast <target> [flags]           Automated discovery + passive + active DAST
  mantis smoke [flags]                   Run smoke test workflows
  mantis api scan [flags]                OpenAPI-driven API security tests
  mantis validate [flags]                Smoke + DAST + API per environment policy, with a security gate
  mantis templates list|validate|test    Template management
  mantis version                         Print version info

Run 'mantis <command> -h' for flags on a specific command.
`)
}

// gateFailure signals that the security gate failed (as opposed to an
// operational error), so main can exit 1 without printing an extra error line
// (the report itself already explains the failure).
type gateFailure struct{ ExitCode int }

func (g *gateFailure) Error() string { return "security gate failed" }
