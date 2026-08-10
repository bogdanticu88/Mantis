package reporters

import (
	"fmt"
	"io"
	"strings"
)

func WriteConsole(w io.Writer, r Report) {
	fmt.Fprintln(w, "MANTIS Security Gate")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Environment: %s\n", r.Environment)
	if r.Application != "" {
		fmt.Fprintf(w, "Application: %s\n", r.Application)
	}
	fmt.Fprintf(w, "Target: %s\n", r.Target)
	fmt.Fprintln(w)

	if len(r.Smoke) > 0 {
		fmt.Fprintln(w, "Smoke Tests")
		for _, wf := range r.Smoke {
			switch {
			case wf.Skipped:
				fmt.Fprintf(w, "- %s (skipped: %s)\n", wf.ID, wf.SkipReason)
			case wf.Passed:
				fmt.Fprintf(w, "✓ %s\n", wf.ID)
			default:
				fmt.Fprintf(w, "✗ %s\n", wf.ID)
				for _, s := range wf.Steps {
					if !s.Passed {
						for _, f := range s.Failures {
							fmt.Fprintf(w, "    %s: %s\n", s.StepID, f)
						}
					}
				}
			}
		}
		fmt.Fprintln(w)
	}

	if len(r.Findings) > 0 {
		fmt.Fprintln(w, "Findings")
		for _, f := range r.Findings {
			fmt.Fprintf(w, "✗ [%s] %s (%s %s)\n", strings.ToUpper(string(f.Severity)), f.Name, f.Method, f.Endpoint)
		}
		fmt.Fprintln(w)
	}

	s := r.Summary
	fmt.Fprintf(w, "CRITICAL: %d\n", s.Critical)
	fmt.Fprintf(w, "HIGH: %d\n", s.High)
	fmt.Fprintf(w, "MEDIUM: %d\n", s.Medium)
	fmt.Fprintf(w, "LOW: %d\n", s.Low)
	fmt.Fprintf(w, "INFO: %d\n", s.Info)
	fmt.Fprintln(w)

	if r.GatePassed {
		fmt.Fprintln(w, "Pipeline: PASSED")
	} else {
		fmt.Fprintln(w, "Pipeline: FAILED")
	}
	fmt.Fprintf(w, "Exit code: %d\n", r.ExitCode)
}
