package reporters

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteGitHubActions_SeverityMapping(t *testing.T) {
	r := sampleReport() // one high, one low finding, gate failed

	var buf bytes.Buffer
	if err := WriteGitHubActions(&buf, r); err != nil {
		t.Fatalf("WriteGitHubActions: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "::error title=") {
		t.Error("expected an ::error annotation for the high-severity finding")
	}
	if !strings.Contains(out, "::notice title=") {
		t.Error("expected a ::notice annotation for the low-severity finding")
	}
	if !strings.Contains(out, "::error::") {
		t.Error("expected an overall ::error:: line since the gate failed")
	}
}

func TestWriteGitHubActions_GatePassedUsesNotice(t *testing.T) {
	r := sampleReport()
	r.Findings = nil
	r.GatePassed = true

	var buf bytes.Buffer
	if err := WriteGitHubActions(&buf, r); err != nil {
		t.Fatalf("WriteGitHubActions: %v", err)
	}
	if !strings.Contains(buf.String(), "::notice::") {
		t.Error("expected a ::notice:: summary line when the gate passed")
	}
	if strings.Contains(buf.String(), "::error::") {
		t.Error("should not emit an ::error:: summary line when the gate passed")
	}
}

func TestWriteGitHubActions_EscapesSpecialCharacters(t *testing.T) {
	r := sampleReport()
	r.Findings[0].Description = "line one\nline two: 100%, done"

	var buf bytes.Buffer
	if err := WriteGitHubActions(&buf, r); err != nil {
		t.Fatalf("WriteGitHubActions: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "\nline two") {
		t.Error("a literal newline in the message should have been escaped to %0A, not passed through raw (it would break the workflow command parser)")
	}
	if !strings.Contains(out, "%0A") {
		t.Error("expected %0A in place of the embedded newline")
	}
	if !strings.Contains(out, "%25") {
		t.Error("expected %25 in place of the literal percent sign")
	}
}

func TestWriteGitHubActions_AppendsStepSummaryWhenEnvSet(t *testing.T) {
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "summary.md")
	if err := os.WriteFile(summaryPath, []byte("# existing content\n\n"), 0o644); err != nil {
		t.Fatalf("seeding summary file: %v", err)
	}
	t.Setenv("GITHUB_STEP_SUMMARY", summaryPath)

	var buf bytes.Buffer
	if err := WriteGitHubActions(&buf, sampleReport()); err != nil {
		t.Fatalf("WriteGitHubActions: %v", err)
	}

	content, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("reading summary file: %v", err)
	}
	got := string(content)
	if !strings.HasPrefix(got, "# existing content") {
		t.Error("step summary should be appended, not overwrite what's already there (other steps in the same job may have written first)")
	}
	if !strings.Contains(got, "## Mantis - test") {
		t.Errorf("expected the summary heading to appear, got:\n%s", got)
	}
	if !strings.Contains(got, "Actuator Exposure") {
		t.Error("expected the finding name to appear in the summary table")
	}
}

func TestWriteGitHubActions_NoStepSummaryWhenEnvUnset(t *testing.T) {
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	var buf bytes.Buffer
	if err := WriteGitHubActions(&buf, sampleReport()); err != nil {
		t.Fatalf("WriteGitHubActions: %v", err)
	}
	// nothing to assert on disk - this just confirms it doesn't try to open
	// an empty path and error out.
}
