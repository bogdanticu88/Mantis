package findings

import "testing"

func TestSeverityAtLeast(t *testing.T) {
	cases := []struct {
		sev, threshold Severity
		want           bool
	}{
		{SeverityCritical, SeverityHigh, true}, // more severe than the bar
		{SeverityHigh, SeverityHigh, true},     // exactly at the bar
		{SeverityMedium, SeverityHigh, false},  // less severe than the bar
		{SeverityInfo, SeverityInfo, true},
		{SeverityCritical, SeverityInfo, true},   // critical clears every bar
		{Severity("bogus"), SeverityHigh, false}, // unknown severity never trips a gate
		{SeverityHigh, Severity("bogus"), false}, // unknown threshold never gets cleared
	}
	for _, c := range cases {
		if got := c.sev.AtLeast(c.threshold); got != c.want {
			t.Errorf("%q.AtLeast(%q) = %v, want %v", c.sev, c.threshold, got, c.want)
		}
	}
}

func TestSummarize(t *testing.T) {
	fs := []Finding{
		{Severity: SeverityCritical},
		{Severity: SeverityHigh},
		{Severity: SeverityHigh},
		{Severity: SeverityMedium},
		{Severity: SeverityLow},
		{Severity: SeverityLow},
		{Severity: SeverityLow},
		{Severity: SeverityInfo},
	}
	got := Summarize(fs)
	want := Summary{Critical: 1, High: 2, Medium: 1, Low: 3, Info: 1}
	if got != want {
		t.Errorf("Summarize() = %+v, want %+v", got, want)
	}
}

func TestSummarize_Empty(t *testing.T) {
	if got := Summarize(nil); got != (Summary{}) {
		t.Errorf("Summarize(nil) = %+v, want zero value", got)
	}
}

func TestWorstSeverity(t *testing.T) {
	cases := []struct {
		name string
		fs   []Finding
		want Severity
	}{
		{"empty", nil, ""},
		{"single", []Finding{{Severity: SeverityMedium}}, SeverityMedium},
		{"picks the worst regardless of order", []Finding{
			{Severity: SeverityLow}, {Severity: SeverityCritical}, {Severity: SeverityMedium},
		}, SeverityCritical},
		{"all same severity", []Finding{
			{Severity: SeverityHigh}, {Severity: SeverityHigh},
		}, SeverityHigh},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := WorstSeverity(c.fs); got != c.want {
				t.Errorf("WorstSeverity() = %q, want %q", got, c.want)
			}
		})
	}
}
