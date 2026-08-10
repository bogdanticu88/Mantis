package reporters

import (
	"encoding/json"
	"io"

	"mantis/internal/findings"
)

// SARIF 2.1.0 output, mainly for GitHub code scanning.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription sarifText `json:"shortDescription"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

func severityToSARIFLevel(s findings.Severity) string {
	switch s {
	case findings.SeverityCritical, findings.SeverityHigh:
		return "error"
	case findings.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func WriteSARIF(w io.Writer, r Report) error {
	ruleSeen := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult

	for _, f := range r.Findings {
		if !ruleSeen[f.ID] {
			ruleSeen[f.ID] = true
			rules = append(rules, sarifRule{
				ID:               f.ID,
				Name:             f.Name,
				ShortDescription: sarifText{Text: f.Name},
			})
		}
		uri := f.Endpoint
		if uri == "" {
			uri = f.Target
		}
		results = append(results, sarifResult{
			RuleID:  f.ID,
			Level:   severityToSARIFLevel(f.Severity),
			Message: sarifText{Text: f.Description},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: uri},
				},
			}},
		})
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Mantis",
				InformationURI: "https://github.com/mantis-scanner/mantis",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	if rules == nil {
		log.Runs[0].Tool.Driver.Rules = []sarifRule{}
	}
	if results == nil {
		log.Runs[0].Results = []sarifResult{}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
