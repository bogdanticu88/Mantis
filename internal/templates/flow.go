package templates

// flow.go implements the template flow engine: a small scripting language
// that controls which HTTP requests run and in what order, replacing the
// default sequential chain when the template's `flow` field is non-empty.
//
// Syntax reference:
//
//   http(N)            — execute request N (1-indexed from the requests list).
//                        Sets http<N>_status (int), http<N>_body (string), and
//                        http<N>_matched (bool) for use in later conditions.
//   if <expr>          — conditional block; <expr> uses the same DSL as matchers.
//   else               — optional alternative branch for the preceding if.
//   end                — closes an if block.
//   set name = <expr>  — evaluate <expr> and store the result in name.
//                        The value is available in later conditions and as a
//                        {{name}} placeholder in request rendering.
//   stop               — terminate the flow immediately, keeping any findings
//                        produced so far.
//   # comment          — lines starting with # are ignored.
//
// Example:
//
//   flow: |
//     http(1)
//     if http1_matched
//       http(2)
//       if http2_status == 200 && contains(http2_body, "admin")
//         http(3)
//       end
//     end

import (
	"context"
	"fmt"
	"strings"

	"github.com/bogdanticu88/Mantis/internal/dsl"
	"github.com/bogdanticu88/Mantis/internal/findings"
	"github.com/bogdanticu88/Mantis/internal/httpclient"
)

// --- AST node types ---

type flowNode interface{ isFlowNode() }

type httpCallNode struct{ n int }
type setVarNode struct{ name, expr string }
type stopNode struct{}
type ifBlockNode struct {
	cond  string
	then  []flowNode
	else_ []flowNode
}

func (httpCallNode) isFlowNode() {}
func (setVarNode) isFlowNode()   {}
func (stopNode) isFlowNode()     {}
func (ifBlockNode) isFlowNode()  {}

// --- Parser ---

// parseFlow parses a flow script into an executable AST.
func parseFlow(script string) ([]flowNode, error) {
	lines := splitFlowLines(script)
	nodes, pos, err := parseFlowBlock(lines, 0)
	if err != nil {
		return nil, err
	}
	for ; pos < len(lines); pos++ {
		if l := strings.TrimSpace(lines[pos]); l != "" && !strings.HasPrefix(l, "#") {
			return nil, fmt.Errorf("unexpected %q at line %d (missing 'end'?)", l, pos+1)
		}
	}
	return nodes, nil
}

func splitFlowLines(s string) []string {
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}

// parseFlowBlock parses statements until it hits "end", "else", or EOF.
// Returns the parsed nodes and the index of the next unconsumed line.
func parseFlowBlock(lines []string, pos int) ([]flowNode, int, error) {
	var nodes []flowNode
	for pos < len(lines) {
		line := strings.TrimSpace(lines[pos])
		if line == "" || strings.HasPrefix(line, "#") {
			pos++
			continue
		}
		if line == "end" || line == "else" {
			break
		}
		node, newPos, err := parseFlowStmt(lines, pos)
		if err != nil {
			return nil, newPos, err
		}
		nodes = append(nodes, node)
		pos = newPos
	}
	return nodes, pos, nil
}

func parseFlowStmt(lines []string, pos int) (flowNode, int, error) {
	line := strings.TrimSpace(lines[pos])

	switch {
	case line == "stop":
		return stopNode{}, pos + 1, nil

	case strings.HasPrefix(line, "http(") && strings.HasSuffix(line, ")"):
		inner := strings.TrimSpace(line[5 : len(line)-1])
		n, err := parseFlowInt(inner)
		if err != nil || n < 1 {
			return nil, pos, fmt.Errorf("line %d: http() requires a positive integer argument", pos+1)
		}
		return httpCallNode{n: n}, pos + 1, nil

	case strings.HasPrefix(line, "set "):
		rest := strings.TrimPrefix(line, "set ")
		idx := strings.Index(rest, "=")
		if idx < 0 {
			return nil, pos, fmt.Errorf("line %d: set requires '=', e.g.: set x = expr", pos+1)
		}
		name := strings.TrimSpace(rest[:idx])
		expr := strings.TrimSpace(rest[idx+1:])
		if name == "" || expr == "" {
			return nil, pos, fmt.Errorf("line %d: set requires a name and an expression", pos+1)
		}
		return setVarNode{name: name, expr: expr}, pos + 1, nil

	case strings.HasPrefix(line, "if "):
		cond := strings.TrimSpace(strings.TrimPrefix(line, "if "))
		if cond == "" {
			return nil, pos, fmt.Errorf("line %d: if requires a condition", pos+1)
		}
		thenNodes, nextPos, err := parseFlowBlock(lines, pos+1)
		if err != nil {
			return nil, nextPos, err
		}
		pos = nextPos

		var elseNodes []flowNode
		if pos < len(lines) && strings.TrimSpace(lines[pos]) == "else" {
			elseNodes, pos, err = parseFlowBlock(lines, pos+1)
			if err != nil {
				return nil, pos, err
			}
		}
		if pos >= len(lines) || strings.TrimSpace(lines[pos]) != "end" {
			return nil, pos, fmt.Errorf("if block is missing its closing 'end'")
		}
		return ifBlockNode{cond: cond, then: thenNodes, else_: elseNodes}, pos + 1, nil

	default:
		return nil, pos, fmt.Errorf("line %d: unknown flow statement: %q", pos+1, line)
	}
}

// parseFlowInt parses a non-negative integer from s. Returns an error if s
// contains any non-digit character.
func parseFlowInt(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("not an integer: %q", s)
		}
		n = n*10 + int(ch-'0')
	}
	return n, nil
}

// --- Executor ---

// flowRunner holds the mutable state for one flow script execution.
type flowRunner struct {
	ctx         context.Context
	client      *httpclient.Client
	redactor    *httpclient.Redactor
	tpl         *Template
	target      string
	environment string
	// vars is used for request rendering ({{placeholder}} substitution).
	// All values are strings.
	vars map[string]string
	// flowVars holds typed values (int64, bool, string) for DSL conditions.
	// It is seeded from vars and extended as http(N) calls complete.
	flowVars  map[string]any
	hook      ResponseHook
	exchanges []findings.HTTPExchange
	findings  []findings.Finding
	passive   []findings.Finding
}

func (fr *flowRunner) env() dsl.Env {
	return dsl.Env{Vars: fr.flowVars, Funcs: dsl.DefaultFuncs()}
}

// runBlock executes a slice of flow nodes in order, returning (stopped, err).
func (fr *flowRunner) runBlock(nodes []flowNode) (bool, error) {
	for _, node := range nodes {
		switch n := node.(type) {
		case httpCallNode:
			stopped, err := fr.runHTTP(n.n)
			if err != nil {
				return false, err
			}
			if stopped {
				return true, nil
			}

		case setVarNode:
			v, err := dsl.Eval(n.expr, fr.env())
			if err != nil {
				return false, fmt.Errorf("flow: set %s: %w", n.name, err)
			}
			fr.flowVars[n.name] = v
			fr.vars[n.name] = fmt.Sprintf("%v", v)

		case ifBlockNode:
			cond, err := dsl.EvalBool(n.cond, fr.env())
			if err != nil {
				return false, fmt.Errorf("flow: if %q: %w", n.cond, err)
			}
			branch := n.else_
			if cond {
				branch = n.then
			}
			if stopped, err := fr.runBlock(branch); err != nil || stopped {
				return stopped, err
			}

		case stopNode:
			return true, nil
		}
	}
	return false, nil
}

// runHTTP executes request N (1-indexed) and publishes response fields into
// the flow variable scope. A transport error is fatal; a non-matching response
// is not — the script decides what to do based on httpN_matched.
func (fr *flowRunner) runHTTP(n int) (bool, error) {
	if n < 1 || n > len(fr.tpl.Requests) {
		return false, fmt.Errorf("flow: http(%d): template has %d request(s)", n, len(fr.tpl.Requests))
	}
	spec := fr.tpl.Requests[n-1]
	prefix := fmt.Sprintf("http%d", n)

	for _, path := range spec.allPaths() {
		req := httpclient.Request{
			Method:  spec.Method,
			URL:     renderVars(joinURL(fr.target, path), fr.vars),
			Headers: renderHeaders(spec.Headers, fr.vars),
			Body:    []byte(renderVars(spec.Body, fr.vars)),
		}
		resp, err := fr.client.Do(fr.ctx, req)
		if err != nil {
			return false, fmt.Errorf("flow: http(%d): %w", n, err)
		}
		fr.exchanges = append(fr.exchanges, fr.redactor.Exchange(resp))
		if fr.hook != nil {
			fr.passive = append(fr.passive, fr.hook(resp, fr.target, fr.environment, path)...)
		}
		if err := runExtractors(spec, resp, fr.vars); err != nil {
			return false, fmt.Errorf("flow: http(%d): extractors: %w", n, err)
		}

		// Publish response fields for use in subsequent conditions and set statements.
		statusStr := fmt.Sprintf("%d", resp.StatusCode)
		bodyStr := string(resp.Body)
		fr.flowVars[prefix+"_status"] = int64(resp.StatusCode)
		fr.flowVars[prefix+"_body"] = bodyStr
		fr.vars[prefix+"_status"] = statusStr
		fr.vars[prefix+"_body"] = bodyStr

		matched, on, err := evalMatchers(spec, resp)
		if err != nil {
			return false, fmt.Errorf("flow: http(%d): matchers: %w", n, err)
		}
		fr.flowVars[prefix+"_matched"] = matched
		fr.vars[prefix+"_matched"] = fmt.Sprintf("%v", matched)

		if matched {
			fr.findings = append(fr.findings, newFinding(
				fr.tpl, fr.target, path, spec.Method, fr.environment, on, fr.exchanges, fr.vars,
			))
			if spec.StopAtFirstMatch {
				break
			}
		}
	}
	return false, nil
}

// executeFlowChain runs the pre-parsed flow script for one template invocation.
func executeFlowChain(
	ctx context.Context,
	client *httpclient.Client,
	redactor *httpclient.Redactor,
	tpl *Template,
	target, environment string,
	vars map[string]string,
	hook ResponseHook,
	nodes []flowNode,
) RunResult {
	// Seed the flow scope with all string vars so DSL conditions can reference
	// BaseURL, auth headers, extracted template variables, etc.
	flowVars := make(map[string]any, len(vars))
	for k, v := range vars {
		flowVars[k] = v
	}

	fr := &flowRunner{
		ctx:         ctx,
		client:      client,
		redactor:    redactor,
		tpl:         tpl,
		target:      target,
		environment: environment,
		vars:        vars,
		flowVars:    flowVars,
		hook:        hook,
	}

	if _, err := fr.runBlock(nodes); err != nil {
		return RunResult{Template: tpl, Target: target, Vars: vars, Error: err}
	}

	return RunResult{
		Template:        tpl,
		Target:          target,
		Matched:         len(fr.findings) > 0,
		Findings:        fr.findings,
		PassiveFindings: fr.passive,
		Vars:            vars,
	}
}
