// Package api is the OpenAPI-driven testing side: a small reader for paths,
// parameters and per-operation auth requirements, plus a handful of checks
// generated straight from that spec.
//
// Didn't want a full OpenAPI object-model library just for this - the spec
// is really just YAML/JSON with a few keys we care about (paths, methods,
// parameters, security), so it's read as a generic document and walked
// directly instead.
package api

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Parameter struct {
	Name     string
	In       string // path, query, header, cookie
	Required bool
}

type Endpoint struct {
	Path         string
	Method       string
	Parameters   []Parameter
	RequiresAuth bool
	OperationID  string
}

type Spec struct {
	Endpoints []Endpoint
}

var httpMethods = []string{"get", "post", "put", "delete", "patch", "head", "options"}

// ParseOpenAPI reads an OpenAPI 3 (or Swagger 2 - the fields Mantis reads
// are identical between the two) document from path.
func ParseOpenAPI(path string) (*Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("api: reading %s: %w", path, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("api: parsing %s: %w", path, err)
	}

	globalSecurity := doc["security"]

	pathsRaw, _ := doc["paths"].(map[string]any)
	var endpoints []Endpoint
	for path, pathItemRaw := range pathsRaw {
		pathItem, ok := pathItemRaw.(map[string]any)
		if !ok {
			continue
		}
		var pathLevelParams []Parameter
		if pl, ok := pathItem["parameters"].([]any); ok {
			pathLevelParams = parseParams(pl)
		}

		for _, method := range httpMethods {
			opRaw, ok := pathItem[method]
			if !ok {
				continue
			}
			op, ok := opRaw.(map[string]any)
			if !ok {
				continue
			}

			params := append([]Parameter{}, pathLevelParams...)
			if pl, ok := op["parameters"].([]any); ok {
				params = append(params, parseParams(pl)...)
			}

			requiresAuth := false
			if sec, ok := op["security"]; ok {
				requiresAuth = securityNonEmpty(sec)
			} else if globalSecurity != nil {
				requiresAuth = securityNonEmpty(globalSecurity)
			}

			opID, _ := op["operationId"].(string)
			endpoints = append(endpoints, Endpoint{
				Path:         path,
				Method:       strings.ToUpper(method),
				Parameters:   params,
				RequiresAuth: requiresAuth,
				OperationID:  opID,
			})
		}
	}
	return &Spec{Endpoints: endpoints}, nil
}

func parseParams(raw []any) []Parameter {
	var out []Parameter
	for _, pRaw := range raw {
		p, ok := pRaw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := p["name"].(string)
		in, _ := p["in"].(string)
		required, _ := p["required"].(bool)
		if name == "" {
			continue
		}
		out = append(out, Parameter{Name: name, In: in, Required: required})
	}
	return out
}

// securityNonEmpty reports whether an OpenAPI `security` value actually
// requires a scheme. Per spec, `security: []` explicitly means "no auth
// required" for that operation, overriding any global requirement.
func securityNonEmpty(v any) bool {
	arr, ok := v.([]any)
	if !ok {
		return false
	}
	return len(arr) > 0
}

var pathParamPattern = regexp.MustCompile(`\{[^}]+\}`)

// FillPath substitutes every {param} placeholder in path with sample.
func FillPath(path, sample string) string {
	return pathParamPattern.ReplaceAllString(path, sample)
}

// IsIDLike reports whether a path parameter name looks like an object
// identifier (id, userId, accountId, ...) - the heuristic used to pick
// candidates for the BOLA probe.
func IsIDLike(name string) bool {
	n := strings.ToLower(name)
	return n == "id" || strings.HasSuffix(n, "id") || strings.HasSuffix(n, "_id")
}
