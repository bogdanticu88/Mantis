package templates

import (
	"regexp"
	"strings"
)

// varPattern matches both ${NAME} and {{NAME}} placeholder styles - people
// reach for either one depending on habit, so just support both instead of
// picking a fight about it.
var varPattern = regexp.MustCompile(`\$\{([A-Za-z0-9_.]+)\}|\{\{([A-Za-z0-9_.]+)\}\}`)

// RenderVars substitutes placeholders in s from vars. Unresolved
// placeholders are left intact rather than blanked, so a missing variable
// produces a visibly broken request instead of a silently wrong one. This is
// shared by the template, smoke and API engines.
func RenderVars(s string, vars map[string]string) string {
	return varPattern.ReplaceAllStringFunc(s, func(m string) string {
		sub := varPattern.FindStringSubmatch(m)
		name := sub[1]
		if name == "" {
			name = sub[2]
		}
		if v, ok := vars[name]; ok {
			return v
		}
		return m
	})
}

func renderVars(s string, vars map[string]string) string { return RenderVars(s, vars) }

// JoinURL joins a base URL and a path, ensuring exactly one slash between them.
func JoinURL(base, path string) string {
	base = strings.TrimSuffix(base, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

func joinURL(base, path string) string { return JoinURL(base, path) }
