package reporters

import (
	"fmt"
	"io"
	"strings"

	"github.com/bogdanticu88/Mantis/internal/findings"
)

// WriteAzureDevOps emits Azure Pipelines logging commands
// (https://learn.microsoft.com/azure/devops/pipelines/scripts/logging-commands)
// so findings and the gate result show up natively in the pipeline's Issues
// panel and task result, with no marketplace extension required. These
// commands only do anything when printed to the live task's stdout during a
// pipeline run - the agent parses them out of the running task's console
// output in real time, so writing them to a file (the way json/sarif/junit/
// html work) would be inert. Callers must write this to os.Stdout, not a
// file.
func WriteAzureDevOps(w io.Writer, r Report) error {
	for _, f := range r.Findings {
		issueType := "warning"
		if f.Severity == findings.SeverityCritical || f.Severity == findings.SeverityHigh {
			issueType = "error"
		}
		msg := fmt.Sprintf("[%s] %s (%s %s): %s", strings.ToUpper(string(f.Severity)), f.Name, f.Method, f.Endpoint, f.Description)
		fmt.Fprintf(w, "##vso[task.logissue type=%s]%s\n", issueType, escapeVSO(msg))
	}

	for _, wf := range r.Smoke {
		if wf.Skipped || wf.Passed {
			continue
		}
		for _, s := range wf.Steps {
			if s.Passed {
				continue
			}
			msg := fmt.Sprintf("smoke %s/%s failed: %s", wf.ID, s.StepID, strings.Join(s.Failures, "; "))
			fmt.Fprintf(w, "##vso[task.logissue type=error]%s\n", escapeVSO(msg))
		}
	}

	fmt.Fprintf(w, "##vso[task.setvariable variable=MantisGatePassed]%t\n", r.GatePassed)
	fmt.Fprintf(w, "##vso[task.setvariable variable=MantisCritical]%d\n", r.Summary.Critical)
	fmt.Fprintf(w, "##vso[task.setvariable variable=MantisHigh]%d\n", r.Summary.High)

	if !r.GatePassed {
		summary := fmt.Sprintf("Mantis security gate failed (fail-on: %s) - critical:%d high:%d medium:%d low:%d info:%d",
			r.FailOn, r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info)
		fmt.Fprintf(w, "##vso[task.complete result=Failed]%s\n", escapeVSO(summary))
	}
	return nil
}

// escapeVSO applies the substitutions Azure Pipelines logging commands
// require for values (percent-encoding first, so it doesn't double-escape
// the '%' characters it just inserted for the other substitutions).
func escapeVSO(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	s = strings.ReplaceAll(s, "]", "%5D")
	s = strings.ReplaceAll(s, ";", "%3B")
	return s
}
