package reporters

import (
	"fmt"
	"io"
	"os"
	"strings"

	"mantis/internal/findings"
)

// WriteGitHubActions emits GitHub Actions workflow commands
// (https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions)
// so findings show up as annotations on the run. Like azdo, this only
// means anything printed live to the running job's console - callers must
// write it to os.Stdout, not a file. When GITHUB_STEP_SUMMARY is set
// (which every GitHub Actions run sets automatically), a markdown summary
// also gets appended there - that's what renders as the nicer formatted
// report at the bottom of the run page, since cramming a full findings
// table into annotations alone doesn't read well.
func WriteGitHubActions(w io.Writer, r Report) error {
	for _, f := range r.Findings {
		title := fmt.Sprintf("[%s] %s", strings.ToUpper(string(f.Severity)), f.Name)
		body := fmt.Sprintf("%s %s - %s", f.Method, f.Endpoint, f.Description)
		fmt.Fprintf(w, "::%s title=%s::%s\n", ghLevel(f.Severity), escapeGHProperty(title), escapeGHData(body))
	}

	for _, wf := range r.Smoke {
		if wf.Skipped || wf.Passed {
			continue
		}
		for _, s := range wf.Steps {
			if s.Passed {
				continue
			}
			title := fmt.Sprintf("smoke: %s/%s", wf.ID, s.StepID)
			fmt.Fprintf(w, "::error title=%s::%s\n", escapeGHProperty(title), escapeGHData(strings.Join(s.Failures, "; ")))
		}
	}

	summary := fmt.Sprintf("Mantis: critical=%d high=%d medium=%d low=%d info=%d (fail-on: %s)",
		r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info, r.FailOn)
	if r.GatePassed {
		fmt.Fprintf(w, "::notice::%s - gate passed\n", escapeGHData(summary))
	} else {
		fmt.Fprintf(w, "::error::%s - gate FAILED\n", escapeGHData(summary))
	}

	if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
		if err := appendGitHubStepSummary(path, r); err != nil {
			return fmt.Errorf("writing GITHUB_STEP_SUMMARY: %w", err)
		}
	}
	return nil
}

func ghLevel(sev findings.Severity) string {
	switch sev {
	case findings.SeverityCritical, findings.SeverityHigh:
		return "error"
	case findings.SeverityMedium:
		return "warning"
	default:
		return "notice"
	}
}

// escapeGHData applies the substitutions GitHub Actions workflow commands
// require for a command's data (message) portion.
func escapeGHData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

// escapeGHProperty applies the extra substitutions required for a
// property value (e.g. title=...), on top of the data escaping.
func escapeGHProperty(s string) string {
	s = escapeGHData(s)
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ",", "%2C")
	return s
}

func appendGitHubStepSummary(path string, r Report) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "## Mantis - %s\n\n", r.Environment)
	if r.GatePassed {
		fmt.Fprintf(f, "**Pipeline: PASSED**\n\n")
	} else {
		fmt.Fprintf(f, "**Pipeline: FAILED** (fail-on: %s)\n\n", r.FailOn)
	}
	fmt.Fprintf(f, "| Critical | High | Medium | Low | Info |\n|---|---|---|---|---|\n| %d | %d | %d | %d | %d |\n\n",
		r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info)

	if len(r.Smoke) > 0 {
		fmt.Fprintf(f, "### Smoke Tests\n\n")
		for _, wf := range r.Smoke {
			status := "PASS"
			switch {
			case wf.Skipped:
				status = "SKIPPED: " + wf.SkipReason
			case !wf.Passed:
				status = "FAIL"
			}
			fmt.Fprintf(f, "- **%s**: %s\n", mdEscape(wf.ID), mdEscape(status))
		}
		fmt.Fprintln(f)
	}

	if len(r.Findings) > 0 {
		fmt.Fprintf(f, "### Findings\n\n")
		fmt.Fprintf(f, "| Severity | Name | Endpoint | Method |\n|---|---|---|---|\n")
		for _, fnd := range r.Findings {
			fmt.Fprintf(f, "| %s | %s | %s | %s |\n",
				strings.ToUpper(string(fnd.Severity)), mdEscape(fnd.Name), mdEscape(fnd.Endpoint), mdEscape(fnd.Method))
		}
	}
	return nil
}

func mdEscape(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}
