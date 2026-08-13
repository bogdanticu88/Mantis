package templates

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/bogdanticu88/Mantis/internal/dsl"
	"github.com/bogdanticu88/Mantis/internal/httpclient"
	"github.com/bogdanticu88/Mantis/internal/jsonpath"
)

type matchResult struct {
	Matched   bool
	MatchedOn []string
}

// evalMatchers evaluates spec's matcher list against resp, combining results
// per spec.MatchersCondition (default "and"). An empty matcher list is
// treated as an unconditional match - used for chain-only requests (e.g. a
// login step whose only purpose is to extract a session token).
func evalMatchers(spec RequestSpec, resp *httpclient.Response) (bool, []string, error) {
	if len(spec.Matchers) == 0 {
		return true, nil, nil
	}
	condition := strings.ToLower(spec.MatchersCondition)
	if condition == "" {
		condition = "and"
	}

	var matchedOn []string
	matchedCount := 0
	for _, m := range spec.Matchers {
		res, err := evalMatcher(m, resp)
		if err != nil {
			return false, nil, err
		}
		if res.Matched {
			matchedCount++
			matchedOn = append(matchedOn, res.MatchedOn...)
			if condition == "or" {
				return true, matchedOn, nil
			}
		} else if condition == "and" {
			return false, nil, nil
		}
	}
	if condition == "and" {
		return matchedCount == len(spec.Matchers), matchedOn, nil
	}
	return false, nil, nil
}

func evalMatcher(m Matcher, resp *httpclient.Response) (matchResult, error) {
	condition := strings.ToLower(m.Condition)
	if condition == "" {
		condition = "or"
	}

	switch strings.ToLower(m.Type) {
	case "status":
		for _, s := range m.Status {
			if resp.StatusCode == s {
				return finish(m, true, []string{fmt.Sprintf("status:%d", s)}), nil
			}
		}
		return finish(m, false, nil), nil

	case "word":
		part := partOf(m.Part, resp)
		var matchedOn []string
		for _, w := range m.Words {
			if strings.Contains(part, w) {
				matchedOn = append(matchedOn, w)
				if condition == "or" {
					return finish(m, true, matchedOn), nil
				}
			} else if condition == "and" {
				return finish(m, false, nil), nil
			}
		}
		matched := condition == "and" && len(m.Words) > 0 && len(matchedOn) == len(m.Words)
		return finish(m, matched, matchedOn), nil

	case "regex":
		part := partOf(m.Part, resp)
		var matchedOn []string
		for _, pattern := range m.Regex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return matchResult{}, fmt.Errorf("regex matcher %q: %w", pattern, err)
			}
			if re.MatchString(part) {
				matchedOn = append(matchedOn, pattern)
				if condition == "or" {
					return finish(m, true, matchedOn), nil
				}
			} else if condition == "and" {
				return finish(m, false, nil), nil
			}
		}
		matched := condition == "and" && len(m.Regex) > 0 && len(matchedOn) == len(m.Regex)
		return finish(m, matched, matchedOn), nil

	case "json":
		var data any
		if err := json.Unmarshal(resp.Body, &data); err != nil {
			return finish(m, false, nil), nil
		}
		v, ok := jsonpath.Get(data, m.Path)
		if !ok {
			return finish(m, false, nil), nil
		}
		if m.Value == "" {
			return finish(m, true, []string{m.Path}), nil
		}
		if fmt.Sprintf("%v", v) == m.Value {
			return finish(m, true, []string{m.Path + "=" + m.Value}), nil
		}
		return finish(m, false, nil), nil

	case "dsl":
		env := buildDSLEnv(resp)
		matched, err := dsl.EvalBool(m.DSL, env)
		if err != nil {
			return matchResult{}, fmt.Errorf("dsl matcher %q: %w", m.DSL, err)
		}
		return finish(m, matched, []string{m.DSL}), nil

	default:
		return matchResult{}, fmt.Errorf("unknown matcher type %q", m.Type)
	}
}

func finish(m Matcher, matched bool, on []string) matchResult {
	if m.Negative {
		matched = !matched
	}
	return matchResult{Matched: matched, MatchedOn: on}
}

func partOf(part string, resp *httpclient.Response) string {
	switch strings.ToLower(part) {
	case "header":
		return headerText(resp)
	case "all":
		return headerText(resp) + "\n" + string(resp.Body)
	default:
		return string(resp.Body)
	}
}

func headerText(resp *httpclient.Response) string {
	var b strings.Builder
	for k, v := range resp.Headers {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(strings.Join(v, ","))
		b.WriteString("\n")
	}
	return b.String()
}

func buildDSLEnv(resp *httpclient.Response) dsl.Env {
	funcs := dsl.DefaultFuncs()
	funcs["header"] = func(args ...any) (any, error) {
		if len(args) != 1 {
			return nil, fmt.Errorf("header(name) expects 1 arg")
		}
		name, _ := args[0].(string)
		return resp.Headers.Get(name), nil
	}
	return dsl.Env{
		Vars: map[string]any{
			"status_code":    int64(resp.StatusCode),
			"body":           string(resp.Body),
			"content_length": int64(len(resp.Body)),
			"url":            resp.Request.URL,
			"method":         resp.Request.Method,
		},
		Funcs: funcs,
	}
}
