package gate

import (
	"testing"

	"github.com/bogdanticu88/Mantis/internal/findings"
)

func f(sev findings.Severity) findings.Finding {
	return findings.Finding{Severity: sev}
}

func TestDecide(t *testing.T) {
	cases := []struct {
		name        string
		failOn      string
		fs          []findings.Finding
		smokeFailed bool
		wantPassed  bool
		wantExit    int
	}{
		{"no findings, no smoke failure", "high", nil, false, true, 0},
		{"high finding trips high threshold", "high", []findings.Finding{f(findings.SeverityHigh)}, false, false, 1},
		{"medium finding does not trip high threshold", "high", []findings.Finding{f(findings.SeverityMedium)}, false, true, 0},
		{"critical always trips high threshold", "high", []findings.Finding{f(findings.SeverityCritical)}, false, false, 1},
		{"low does not trip critical threshold", "critical", []findings.Finding{f(findings.SeverityLow)}, false, true, 0},
		{"any trips on info", "any", []findings.Finding{f(findings.SeverityInfo)}, false, false, 1},
		{"smoke failure trips gate even with zero findings", "critical", nil, true, false, 1},
		{"smoke failure trips gate even when findings would have passed", "critical", []findings.Finding{f(findings.SeverityLow)}, true, false, 1},
		{"worst of several findings is what matters", "high", []findings.Finding{f(findings.SeverityLow), f(findings.SeverityCritical), f(findings.SeverityMedium)}, false, false, 1},
		{"unrecognized fail-on falls back to high", "not-a-real-level", []findings.Finding{f(findings.SeverityHigh)}, false, false, 1},
		{"unrecognized fail-on does not catch medium (falls back to high)", "not-a-real-level", []findings.Finding{f(findings.SeverityMedium)}, false, true, 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			passed, exit := Decide(c.failOn, c.fs, c.smokeFailed)
			if passed != c.wantPassed || exit != c.wantExit {
				t.Errorf("Decide(%q, %d findings, smokeFailed=%v) = (%v, %d), want (%v, %d)",
					c.failOn, len(c.fs), c.smokeFailed, passed, exit, c.wantPassed, c.wantExit)
			}
		})
	}
}

func TestThreshold(t *testing.T) {
	cases := map[string]findings.Severity{
		"critical": findings.SeverityCritical,
		"HIGH":     findings.SeverityHigh,   // case-insensitive
		" medium ": findings.SeverityMedium, // trims whitespace
		"low":      findings.SeverityLow,
		"any":      findings.SeverityInfo,
		"":         findings.SeverityHigh, // default
		"garbage":  findings.SeverityHigh, // default, never grants a looser gate on a typo
	}
	for in, want := range cases {
		if got := Threshold(in); got != want {
			t.Errorf("Threshold(%q) = %q, want %q", in, got, want)
		}
	}
}
