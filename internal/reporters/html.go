package reporters

import (
	"html/template"
	"io"
)

const htmlTemplate = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Mantis Security Report - {{.Environment}}</title>
<style>
  body { font-family: -apple-system, Segoe UI, sans-serif; margin: 2rem; color: #1a1a1a; background: #fafafa; }
  h1 { margin-bottom: 0; }
  .meta { color: #555; margin-bottom: 1.5rem; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; background: #fff; }
  th, td { border: 1px solid #ddd; padding: 0.5rem 0.75rem; text-align: left; font-size: 0.9rem; }
  th { background: #f0f0f0; }
  .sev-critical { color: #fff; background: #7a0000; }
  .sev-high { color: #fff; background: #c62828; }
  .sev-medium { color: #fff; background: #ef6c00; }
  .sev-low { color: #1a1a1a; background: #fdd835; }
  .sev-info { color: #1a1a1a; background: #90caf9; }
  .pass { color: #2e7d32; }
  .fail { color: #c62828; }
  .skip { color: #888; }
  .gate-pass { color: #2e7d32; font-weight: bold; }
  .gate-fail { color: #c62828; font-weight: bold; }
  pre { background: #f5f5f5; padding: 0.5rem; overflow-x: auto; font-size: 0.8rem; }
</style>
</head>
<body>
<h1>Mantis Security Report</h1>
<div class="meta">
  Application: {{.Application}}<br>
  Environment: {{.Environment}}<br>
  Target: {{.Target}}<br>
  Timestamp: {{.Timestamp}}
</div>

<h2>Summary</h2>
<table>
  <tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr>
  <tr>
    <td class="sev-critical">{{.Summary.Critical}}</td>
    <td class="sev-high">{{.Summary.High}}</td>
    <td class="sev-medium">{{.Summary.Medium}}</td>
    <td class="sev-low">{{.Summary.Low}}</td>
    <td class="sev-info">{{.Summary.Info}}</td>
  </tr>
</table>
<p>Pipeline: <span class="{{if .GatePassed}}gate-pass">PASSED{{else}}gate-fail">FAILED{{end}}</span> (fail-on: {{.FailOn}}, exit code {{.ExitCode}})</p>

{{if .Smoke}}
<h2>Smoke Tests</h2>
<table>
  <tr><th>Workflow</th><th>Result</th><th>Detail</th></tr>
  {{range .Smoke}}
  <tr>
    <td>{{.ID}}</td>
    {{if .Skipped}}
    <td class="skip">SKIPPED</td><td>{{.SkipReason}}</td>
    {{else if .Passed}}
    <td class="pass">PASS</td><td></td>
    {{else}}
    <td class="fail">FAIL</td>
    <td>{{range .Steps}}{{if not .Passed}}{{.StepID}}: {{range .Failures}}{{.}}; {{end}}<br>{{end}}{{end}}</td>
    {{end}}
  </tr>
  {{end}}
</table>
{{end}}

<h2>Findings ({{len .Findings}})</h2>
<table>
  <tr><th>Severity</th><th>Name</th><th>Endpoint</th><th>Method</th><th>Description</th><th>Evidence</th></tr>
  {{range .Findings}}
  <tr>
    <td class="sev-{{.Severity}}">{{.Severity}}</td>
    <td>{{.Name}}</td>
    <td>{{.Endpoint}}</td>
    <td>{{.Method}}</td>
    <td>{{.Description}}</td>
    <td>
      {{if .Evidence.Exchanges}}
      <details><summary>{{len .Evidence.Exchanges}} exchange(s)</summary>
      {{range .Evidence.Exchanges}}
      <pre>{{.Method}} {{.URL}}
Status: {{.StatusCode}}</pre>
      {{end}}
      </details>
      {{end}}
    </td>
  </tr>
  {{end}}
</table>

</body>
</html>
`

var htmlTmpl = template.Must(template.New("report").Parse(htmlTemplate))

func WriteHTML(w io.Writer, r Report) error {
	return htmlTmpl.Execute(w, r)
}
