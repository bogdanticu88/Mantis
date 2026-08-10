package templates

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load parses and validates a single template file.
func Load(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("templates: reading %s: %w", path, err)
	}
	var tpl Template
	if err := yaml.Unmarshal(data, &tpl); err != nil {
		return nil, fmt.Errorf("templates: parsing %s: %w", path, err)
	}
	tpl.SourcePath = path
	if err := tpl.Validate(); err != nil {
		return nil, err
	}
	return &tpl, nil
}

// LoadDir loads every *.yaml/*.yml file under dir (recursively). It returns
// all templates that parsed and validated successfully; errors from
// individual files are joined and returned alongside so callers can decide
// whether a partial load is acceptable (e.g. `templates validate` wants to
// see every error; `scan` may want to fail fast instead).
func LoadDir(dir string) ([]*Template, error) {
	var tpls []*Template
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
		tpl, err := Load(path)
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		tpls = append(tpls, tpl)
		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}
	return tpls, errors.Join(errs...)
}
