// Package gate is the pass/fail call: given a --fail-on threshold, the
// findings from a run, and whether smoke passed, decide whether the
// pipeline should fail and what exit code to use.
package gate

import (
	"strings"

	"github.com/bogdanticu88/Mantis/internal/findings"
)

// Decide returns whether the run passes and the process exit code to use.
// A failing smoke test always fails the pipeline regardless of failOn,
// since "the application doesn't work" is a harder failure than any
// security threshold.
func Decide(failOn string, fs []findings.Finding, smokeFailed bool) (passed bool, exitCode int) {
	if smokeFailed {
		return false, 1
	}
	worst := findings.WorstSeverity(fs)
	if worst == "" {
		return true, 0
	}
	if worst.AtLeast(Threshold(failOn)) {
		return false, 1
	}
	return true, 0
}

// Threshold maps a --fail-on value to the severity it corresponds to.
// "any" maps to info, since every real severity is at-least-as-severe as
// info - i.e. any finding at all trips the gate.
func Threshold(failOn string) findings.Severity {
	switch strings.ToLower(strings.TrimSpace(failOn)) {
	case "critical":
		return findings.SeverityCritical
	case "high":
		return findings.SeverityHigh
	case "medium":
		return findings.SeverityMedium
	case "low":
		return findings.SeverityLow
	case "any":
		return findings.SeverityInfo
	default:
		return findings.SeverityHigh
	}
}
