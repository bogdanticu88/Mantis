package reporters

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

type junitTestsuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []junitTestsuite `xml:"testsuite"`
}

type junitTestsuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Testcases []junitTestcase `xml:"testcase"`
}

type junitTestcase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Content string `xml:",chardata"`
}

func WriteJUnit(w io.Writer, r Report) error {
	var out junitTestsuites

	smoke := junitTestsuite{Name: "Mantis Smoke Tests"}
	for _, wf := range r.Smoke {
		if wf.Skipped {
			continue // JUnit has no first-class "skipped whole suite" concept we rely on here; omit rather than mis-report as passed.
		}
		if len(wf.Steps) == 0 {
			tc := junitTestcase{Name: wf.ID, Classname: "smoke"}
			if !wf.Passed {
				tc.Failure = &junitFailure{Message: "workflow failed"}
				smoke.Failures++
			}
			smoke.Tests++
			smoke.Testcases = append(smoke.Testcases, tc)
			continue
		}
		for _, s := range wf.Steps {
			tc := junitTestcase{Name: wf.ID + "/" + s.StepID, Classname: "smoke"}
			if !s.Passed {
				tc.Failure = &junitFailure{Message: "assertion failed", Content: strings.Join(s.Failures, "\n")}
				smoke.Failures++
			}
			smoke.Tests++
			smoke.Testcases = append(smoke.Testcases, tc)
		}
	}
	out.Suites = append(out.Suites, smoke)

	security := junitTestsuite{Name: "Mantis Security Findings"}
	for _, f := range r.Findings {
		tc := junitTestcase{
			Name:      fmt.Sprintf("[%s] %s", strings.ToUpper(string(f.Severity)), f.Name),
			Classname: f.Endpoint,
			Failure: &junitFailure{
				Message: f.Description,
				Content: fmt.Sprintf("Severity: %s\nEndpoint: %s %s\nTemplate: %s", f.Severity, f.Method, f.Endpoint, f.Template),
			},
		}
		security.Tests++
		security.Failures++
		security.Testcases = append(security.Testcases, tc)
	}
	out.Suites = append(out.Suites, security)

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(out)
}
