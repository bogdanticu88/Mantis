package templates

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"mantis/internal/httpclient"
	"mantis/internal/jsonpath"
)

// runExtractors populates vars with any values spec's extractors can pull
// from resp. Extractors that find nothing are silently skipped - a template
// author who needs a value to exist should also assert on it via a matcher.
func runExtractors(spec RequestSpec, resp *httpclient.Response, vars map[string]string) error {
	for _, ex := range spec.Extractors {
		switch strings.ToLower(ex.Type) {
		case "json":
			var data any
			if err := json.Unmarshal(resp.Body, &data); err != nil {
				continue
			}
			if v, ok := jsonpath.Get(data, ex.Path); ok {
				vars[ex.Name] = fmt.Sprintf("%v", v)
			}

		case "regex":
			re, err := regexp.Compile(ex.Regex)
			if err != nil {
				return fmt.Errorf("extractor %q: invalid regex %q: %w", ex.Name, ex.Regex, err)
			}
			if m := re.FindStringSubmatch(string(resp.Body)); m != nil {
				idx := ex.Group
				if idx < 0 || idx >= len(m) {
					idx = 0
				}
				vars[ex.Name] = m[idx]
			}

		case "header":
			if v := resp.Headers.Get(ex.Header); v != "" {
				vars[ex.Name] = v
			}

		default:
			return fmt.Errorf("extractor %q: unknown type %q", ex.Name, ex.Type)
		}
	}
	return nil
}
