package smoke

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func Load(path string) (*Workflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("smoke: reading %s: %w", path, err)
	}
	var w Workflow
	if err := yaml.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("smoke: parsing %s: %w", path, err)
	}
	w.SourcePath = path
	if err := w.Validate(); err != nil {
		return nil, err
	}
	return &w, nil
}

// LoadDir loads every *.yaml/*.yml smoke workflow under dir (recursively),
// topologically sorted by depends_on so callers can execute them in order.
func LoadDir(dir string) ([]*Workflow, error) {
	var workflows []*Workflow
	var errs []error

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		w, err := Load(path)
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		workflows = append(workflows, w)
		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return workflows, errors.Join(errs...)
	}

	sorted, err := topoSort(workflows)
	if err != nil {
		return workflows, err
	}
	return sorted, nil
}

// topoSort orders workflows so every workflow appears after everything in
// its depends_on list. Unknown dependency ids are reported as errors rather
// than silently ignored, since a mistyped id would otherwise run tests out
// of the order the author intended.
func topoSort(workflows []*Workflow) ([]*Workflow, error) {
	byID := make(map[string]*Workflow, len(workflows))
	for _, w := range workflows {
		byID[w.ID] = w
	}
	for _, w := range workflows {
		for _, dep := range w.DependsOn {
			if _, ok := byID[dep]; !ok {
				return nil, fmt.Errorf("smoke workflow %s: depends_on unknown workflow %q", w.ID, dep)
			}
		}
	}

	var sorted []*Workflow
	visited := map[string]int{} // 0=unvisited 1=visiting 2=done
	var visit func(w *Workflow) error
	visit = func(w *Workflow) error {
		switch visited[w.ID] {
		case 2:
			return nil
		case 1:
			return fmt.Errorf("smoke workflow %s: circular depends_on", w.ID)
		}
		visited[w.ID] = 1
		for _, dep := range w.DependsOn {
			if err := visit(byID[dep]); err != nil {
				return err
			}
		}
		visited[w.ID] = 2
		sorted = append(sorted, w)
		return nil
	}
	for _, w := range workflows {
		if err := visit(w); err != nil {
			return nil, err
		}
	}
	return sorted, nil
}
