// Package jsonpath implements a minimal, dependency-free subset of JSONPath
// (dot and bracket-index access, e.g. "$.data.items[0].id") sufficient for
// template extractors, matchers and smoke-test assertions. It operates on
// data already decoded by encoding/json into interface{} (map[string]any,
// []any, and scalars).
package jsonpath

import (
	"strconv"
	"strings"
)

// Get resolves path against data. Both "$.a.b[0]" and "a.b[0]" are accepted.
func Get(data any, path string) (any, bool) {
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "$")
	path = strings.TrimPrefix(path, ".")
	if path == "" {
		return data, true
	}

	cur := data
	for _, tok := range tokenize(path) {
		switch t := cur.(type) {
		case map[string]any:
			v, ok := t[tok]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			idx, err := strconv.Atoi(tok)
			if err != nil || idx < 0 || idx >= len(t) {
				return nil, false
			}
			cur = t[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

// Exists reports whether path resolves to any value (including a zero value).
func Exists(data any, path string) bool {
	_, ok := Get(data, path)
	return ok
}

func tokenize(path string) []string {
	var tokens []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(path); i++ {
		switch path[i] {
		case '.', '[', ']':
			flush()
		default:
			cur.WriteByte(path[i])
		}
	}
	flush()
	return tokens
}
