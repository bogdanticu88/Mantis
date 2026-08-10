// Package dsl is the matcher/assertion expression language, e.g.
// `status_code == 200 && contains(body, "activeProfiles")`.
//
// I didn't want to pull in a third-party expression engine just for this,
// so expressions get parsed with go/parser as if they were ordinary Go
// expressions, then walked and evaluated against a small variable/function
// environment we control. Bonus: since only identifiers in Env.Vars and
// functions in Env.Funcs are reachable, there's no path from a template's
// DSL string to arbitrary Go code.
package dsl

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
)

// Func is a DSL-callable function. Errors abort evaluation of the whole
// expression (a matcher that errors is treated as not-matched, never as a
// silent false).
type Func func(args ...any) (any, error)

type Env struct {
	Vars  map[string]any
	Funcs map[string]Func
}

// DefaultFuncs returns the standard function set available to every matcher
// and assertion expression.
func DefaultFuncs() map[string]Func {
	return map[string]Func{
		"contains": func(args ...any) (any, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("contains(haystack, needle) expects 2 args")
			}
			return strings.Contains(toString(args[0]), toString(args[1])), nil
		},
		"starts_with": func(args ...any) (any, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("starts_with(s, prefix) expects 2 args")
			}
			return strings.HasPrefix(toString(args[0]), toString(args[1])), nil
		},
		"ends_with": func(args ...any) (any, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("ends_with(s, suffix) expects 2 args")
			}
			return strings.HasSuffix(toString(args[0]), toString(args[1])), nil
		},
		"len": func(args ...any) (any, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("len(s) expects 1 arg")
			}
			return int64(len(toString(args[0]))), nil
		},
		"regex": func(args ...any) (any, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("regex(pattern, s) expects 2 args")
			}
			re, err := regexp.Compile(toString(args[0]))
			if err != nil {
				return nil, fmt.Errorf("regex: invalid pattern: %w", err)
			}
			return re.MatchString(toString(args[1])), nil
		},
		"to_lower": func(args ...any) (any, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("to_lower(s) expects 1 arg")
			}
			return strings.ToLower(toString(args[0])), nil
		},
		"to_upper": func(args ...any) (any, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("to_upper(s) expects 1 arg")
			}
			return strings.ToUpper(toString(args[0])), nil
		},
	}
}

// Eval parses and evaluates expr against env.
func Eval(expr string, env Env) (any, error) {
	node, err := parser.ParseExpr(preprocessQuotes(expr))
	if err != nil {
		return nil, fmt.Errorf("dsl: parse error in %q: %w", expr, err)
	}
	return evalNode(node, env)
}

// preprocessQuotes rewrites 'single quoted' strings into Go double-quoted
// literals before we hand the expression to go/parser. Single quotes read
// more naturally for template authors, but Go's grammar reserves them for
// single-rune literals, so contains(body, 'foo') would otherwise blow up as
// soon as 'foo' has more than one character. Double-quoted and backtick
// (raw) literals pass through untouched.
func preprocessQuotes(expr string) string {
	runes := []rune(expr)
	var out strings.Builder
	for i := 0; i < len(runes); {
		switch runes[i] {
		case '"':
			out.WriteRune(runes[i])
			i++
			for i < len(runes) {
				out.WriteRune(runes[i])
				esc := runes[i] == '\\' && i+1 < len(runes)
				i++
				if esc {
					out.WriteRune(runes[i])
					i++
					continue
				}
				if runes[i-1] == '"' {
					break
				}
			}
		case '`':
			out.WriteRune(runes[i])
			i++
			for i < len(runes) {
				out.WriteRune(runes[i])
				i++
				if runes[i-1] == '`' {
					break
				}
			}
		case '\'':
			start := i
			i++
			var buf strings.Builder
			closed := false
			for i < len(runes) {
				if runes[i] == '\'' {
					closed = true
					break
				}
				buf.WriteRune(runes[i])
				i++
			}
			if closed {
				i++ // consume closing quote
				out.WriteString(strconv.Quote(buf.String()))
			} else {
				// No closing quote - almost certainly a typo. Emit the
				// fragment as-is rather than quietly turning it into a
				// valid-but-wrong expression; go/parser will raise a real
				// syntax error on the stray quote instead.
				out.WriteString(string(runes[start:]))
				i = len(runes)
			}
		default:
			out.WriteRune(runes[i])
			i++
		}
	}
	return out.String()
}

// EvalBool evaluates expr and requires the result to be a boolean.
func EvalBool(expr string, env Env) (bool, error) {
	v, err := Eval(expr, env)
	if err != nil {
		return false, err
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("dsl: expression %q did not evaluate to a boolean (got %T)", expr, v)
	}
	return b, nil
}

func evalNode(n ast.Expr, env Env) (any, error) {
	switch e := n.(type) {
	case *ast.ParenExpr:
		return evalNode(e.X, env)

	case *ast.Ident:
		switch e.Name {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
		v, ok := env.Vars[e.Name]
		if !ok {
			return nil, fmt.Errorf("dsl: undefined variable %q", e.Name)
		}
		return v, nil

	case *ast.BasicLit:
		switch e.Kind {
		case token.INT:
			i, err := strconv.ParseInt(e.Value, 0, 64)
			return i, err
		case token.FLOAT:
			f, err := strconv.ParseFloat(e.Value, 64)
			return f, err
		case token.STRING:
			s, err := strconv.Unquote(e.Value)
			return s, err
		default:
			return nil, fmt.Errorf("dsl: unsupported literal kind %v", e.Kind)
		}

	case *ast.UnaryExpr:
		v, err := evalNode(e.X, env)
		if err != nil {
			return nil, err
		}
		switch e.Op {
		case token.NOT:
			b, ok := v.(bool)
			if !ok {
				return nil, fmt.Errorf("dsl: ! requires a boolean operand")
			}
			return !b, nil
		case token.SUB:
			f, ok := toFloat(v)
			if !ok {
				return nil, fmt.Errorf("dsl: unary - requires a numeric operand")
			}
			return -f, nil
		}
		return nil, fmt.Errorf("dsl: unsupported unary operator %v", e.Op)

	case *ast.BinaryExpr:
		return evalBinary(e, env)

	case *ast.CallExpr:
		ident, ok := e.Fun.(*ast.Ident)
		if !ok {
			return nil, fmt.Errorf("dsl: unsupported call target")
		}
		fn, ok := env.Funcs[ident.Name]
		if !ok {
			return nil, fmt.Errorf("dsl: undefined function %q", ident.Name)
		}
		args := make([]any, 0, len(e.Args))
		for _, a := range e.Args {
			v, err := evalNode(a, env)
			if err != nil {
				return nil, err
			}
			args = append(args, v)
		}
		return fn(args...)

	default:
		return nil, fmt.Errorf("dsl: unsupported expression type %T", n)
	}
}

func evalBinary(e *ast.BinaryExpr, env Env) (any, error) {
	if e.Op == token.LAND || e.Op == token.LOR {
		l, err := evalNode(e.X, env)
		if err != nil {
			return nil, err
		}
		lb, ok := l.(bool)
		if !ok {
			return nil, fmt.Errorf("dsl: && / || require boolean operands")
		}
		if e.Op == token.LAND && !lb {
			return false, nil
		}
		if e.Op == token.LOR && lb {
			return true, nil
		}
		r, err := evalNode(e.Y, env)
		if err != nil {
			return nil, err
		}
		rb, ok := r.(bool)
		if !ok {
			return nil, fmt.Errorf("dsl: && / || require boolean operands")
		}
		return rb, nil
	}

	l, err := evalNode(e.X, env)
	if err != nil {
		return nil, err
	}
	r, err := evalNode(e.Y, env)
	if err != nil {
		return nil, err
	}

	switch e.Op {
	case token.EQL:
		return equal(l, r), nil
	case token.NEQ:
		return !equal(l, r), nil
	case token.LSS, token.LEQ, token.GTR, token.GEQ:
		lf, lok := toFloat(l)
		rf, rok := toFloat(r)
		if !lok || !rok {
			return nil, fmt.Errorf("dsl: %v requires numeric operands", e.Op)
		}
		switch e.Op {
		case token.LSS:
			return lf < rf, nil
		case token.LEQ:
			return lf <= rf, nil
		case token.GTR:
			return lf > rf, nil
		case token.GEQ:
			return lf >= rf, nil
		}
	case token.ADD:
		if ls, ok := l.(string); ok {
			return ls + toString(r), nil
		}
		lf, lok := toFloat(l)
		rf, rok := toFloat(r)
		if lok && rok {
			return lf + rf, nil
		}
		return nil, fmt.Errorf("dsl: + requires two strings or two numbers")
	}
	return nil, fmt.Errorf("dsl: unsupported operator %v", e.Op)
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case int64:
		return float64(t), true
	case int:
		return float64(t), true
	case float64:
		return t, true
	case string:
		f, err := strconv.ParseFloat(t, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

func equal(a, b any) bool {
	af, aok := toFloat(a)
	bf, bok := toFloat(b)
	if aok && bok {
		return af == bf
	}
	return toString(a) == toString(b)
}
