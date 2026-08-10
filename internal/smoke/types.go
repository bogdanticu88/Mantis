// Package smoke answers a different question than the rest of the tool:
// not "is it secure" but "does it actually work". Workflows are ordered
// steps that chain together through extracted variables, and can depend on
// other workflows to control run order.
package smoke

import "fmt"

type Assertion struct {
	Status int    `yaml:"status,omitempty"` // expect exact HTTP status code
	Path   string `yaml:"path,omitempty"`   // JSON path into the response body
	Exists bool   `yaml:"exists,omitempty"` // path must resolve to a value
	Equals string `yaml:"equals,omitempty"` // path value must equal (string compare)
	DSL    string `yaml:"dsl,omitempty"`    // arbitrary boolean expression, see internal/dsl
}

func (a Assertion) describe() string {
	switch {
	case a.Status != 0:
		return fmt.Sprintf("status == %d", a.Status)
	case a.DSL != "":
		return a.DSL
	case a.Equals != "":
		return fmt.Sprintf("%s == %q", a.Path, a.Equals)
	case a.Exists:
		return fmt.Sprintf("%s exists", a.Path)
	default:
		return "(empty assertion)"
	}
}

type Extract struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
}

type StepRequest struct {
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty"`
}

type Step struct {
	ID         string      `yaml:"id"`
	Request    StepRequest `yaml:"request"`
	Assertions []Assertion `yaml:"assertions,omitempty"`
	Extract    []Extract   `yaml:"extract,omitempty"`
}

// Workflow is one smoke test suite: an ordered chain of HTTP steps with
// shared variables, plus best-effort cleanup requests that always run last.
type Workflow struct {
	ID        string            `yaml:"id"`
	Type      string            `yaml:"type"` // must be "smoke"
	DependsOn []string          `yaml:"depends_on,omitempty"`
	Variables map[string]string `yaml:"variables,omitempty"`
	Steps     []Step            `yaml:"steps"`
	Cleanup   []StepRequest     `yaml:"cleanup,omitempty"`

	SourcePath string `yaml:"-"`
}

func (w *Workflow) Validate() error {
	if w.ID == "" {
		return fmt.Errorf("smoke workflow %s: missing id", w.SourcePath)
	}
	if len(w.Steps) == 0 {
		return fmt.Errorf("smoke workflow %s: at least one step is required", w.ID)
	}
	for i, s := range w.Steps {
		if s.Request.Method == "" || s.Request.Path == "" {
			return fmt.Errorf("smoke workflow %s: steps[%d]: request.method and request.path are required", w.ID, i)
		}
		for j, a := range s.Assertions {
			if a.Status == 0 && a.Path == "" && a.DSL == "" {
				return fmt.Errorf("smoke workflow %s: steps[%d]: assertions[%d]: must set status, path, or dsl", w.ID, i, j)
			}
		}
	}
	return nil
}
