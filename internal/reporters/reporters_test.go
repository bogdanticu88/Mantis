package reporters

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"testing"
	"time"

	"mantis/internal/findings"
)

func sampleReport() Report {
	return Report{
		Application: "Test App",
		Environment: "test",
		Target:      "https://example.com",
		Timestamp:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Smoke: []SmokeWorkflowSummary{
			{ID: "health-check", Passed: true},
			{ID: "payments", Passed: false, Steps: []SmokeStepSummary{
				{StepID: "create", Passed: false, Failures: []string{"expected status 201, got 500"}},
			}},
		},
		Findings: []findings.Finding{
			{ID: "MANTIS-ACTUATOR", Name: "Actuator Exposure", Severity: findings.SeverityHigh, Endpoint: "/actuator/env", Method: "GET", Description: "exposed"},
			{ID: "MANTIS-HEADER", Name: "Missing Header", Severity: findings.SeverityLow, Endpoint: "/", Method: "GET", Description: "missing"},
		},
		Summary:    findings.Summary{High: 1, Low: 1},
		FailOn:     "high",
		GatePassed: false,
		ExitCode:   1,
	}
}

func TestWriteJSON_RoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(decoded.Findings) != 2 {
		t.Errorf("decoded %d findings, want 2", len(decoded.Findings))
	}
	if decoded.GatePassed {
		t.Error("decoded GatePassed = true, want false")
	}
}

func TestWriteSARIF_ValidStructureAndCounts(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, sampleReport()); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid SARIF JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(doc.Runs))
	}
	if len(doc.Runs[0].Results) != 2 {
		t.Errorf("got %d results, want 2 (one per finding)", len(doc.Runs[0].Results))
	}
	if len(doc.Runs[0].Tool.Driver.Rules) != 2 {
		t.Errorf("got %d rules, want 2 (one per unique finding id)", len(doc.Runs[0].Tool.Driver.Rules))
	}

	foundError := false
	for _, r := range doc.Runs[0].Results {
		if r.RuleID == "MANTIS-ACTUATOR" && r.Level == "error" {
			foundError = true
		}
	}
	if !foundError {
		t.Error("high-severity finding should map to SARIF level \"error\"")
	}
}

func TestWriteSARIF_EmptyFindingsStillValid(t *testing.T) {
	r := sampleReport()
	r.Findings = nil
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, r); err != nil {
		t.Fatalf("WriteSARIF with no findings: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs = %v, want a single run even with zero findings", doc["runs"])
	}
	run := runs[0].(map[string]any)
	if _, ok := run["results"].([]any); !ok {
		t.Error("results should be an empty array, not null/omitted, so downstream SARIF consumers don't choke")
	}
}

func TestWriteJUnit_ValidXMLAndCounts(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJUnit(&buf, sampleReport()); err != nil {
		t.Fatalf("WriteJUnit: %v", err)
	}
	var doc struct {
		XMLName xml.Name `xml:"testsuites"`
		Suites  []struct {
			Name      string `xml:"name,attr"`
			Tests     int    `xml:"tests,attr"`
			Failures  int    `xml:"failures,attr"`
			Testcases []struct {
				Name    string `xml:"name,attr"`
				Failure *struct {
					Message string `xml:"message,attr"`
				} `xml:"failure"`
			} `xml:"testcase"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid XML: %v", err)
	}
	if len(doc.Suites) != 2 {
		t.Fatalf("got %d testsuites, want 2 (smoke + security)", len(doc.Suites))
	}

	smoke := doc.Suites[0]
	// "health-check" has no recorded steps, so it becomes one workflow-level
	// testcase; "payments" has one recorded (failing) step, so that's a
	// second testcase - 2 total, 1 of them failing.
	if smoke.Tests != 2 {
		t.Errorf("smoke suite tests = %d, want 2", smoke.Tests)
	}
	if smoke.Failures != 1 {
		t.Errorf("smoke suite failures = %d, want 1", smoke.Failures)
	}

	security := doc.Suites[1]
	if security.Tests != 2 || security.Failures != 2 {
		t.Errorf("security suite = %d tests / %d failures, want 2/2 (every finding is reported as a failed testcase)", security.Tests, security.Failures)
	}
}

func TestWriteConsole_DoesNotPanicAndMentionsGateResult(t *testing.T) {
	var buf bytes.Buffer
	WriteConsole(&buf, sampleReport())
	out := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("FAILED")) {
		t.Errorf("console output should mention the gate failed, got:\n%s", out)
	}
}

func TestWriteHTML_ProducesWellFormedOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, sampleReport()); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("HTML output is empty")
	}
	if !bytes.Contains(buf.Bytes(), []byte("Actuator Exposure")) {
		t.Error("HTML output should contain the finding name")
	}
}
