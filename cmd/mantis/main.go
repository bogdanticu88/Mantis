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
	err := dispatch(os.Args[1:])
	if err != nil {
		if _, ok := err.(*gateFailure); !ok {
			if _, ok := err.(*usageError); !ok {
				fmt.Fprintf(os.Stderr, "mantis: %v\n", err)
			}
		}
	}
	os.Exit(exitCodeFor(err))
}

// dispatch does the actual command routing. It's separated from main so
// tests can drive it directly without going through os.Exit.
func dispatch(args []string) error {
	if len(args) < 1 {
		printUsage()
		return &usageError{"no command given"}
	}

	switch args[0] {
	case "scan":
		return cmdScan(args[1:])
	case "dast":
		return cmdDast(args[1:])
	case "smoke":
		return cmdSmoke(args[1:])
	case "api":
		return cmdAPI(args[1:])
	case "validate":
		return cmdValidate(args[1:])
	case "templates":
		return cmdTemplates(args[1:])
	case "version", "-v", "--version":
		fmt.Printf("mantis %s (commit %s, built %s)\n", version, commit, date)
		return nil
	case "-h", "--help", "help":
		printUsage()
		return nil
	default:
		fmt.Fprintf(os.Stderr, "mantis: unknown command %q\n\n", args[0])
		printUsage()
		return &usageError{fmt.Sprintf("unknown command %q", args[0])}
	}
}

// exitCodeFor has no side effects, which is what makes it easy to test on
// its own: given what dispatch returned, what should the process exit code
// be.
func exitCodeFor(err error) int {
	if err == nil {
		return 0
	}
	if ge, ok := err.(*gateFailure); ok {
		return ge.ExitCode
	}
	if _, ok := err.(*usageError); ok {
		return 2
	}
	return 1
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

// usageError signals a CLI usage mistake (no command, unknown command) -
// distinct from an operational error, and from a gate failure. The usage
// text has already been printed to stderr by the time this is returned, so
// main must not print its Error() on top of that.
type usageError struct{ msg string }

func (u *usageError) Error() string { return u.msg }
