package dsl

import "testing"

func env() Env {
	return Env{
		Vars: map[string]any{
			"status_code":    int64(200),
			"body":           "hello world",
			"content_length": int64(11),
		},
		Funcs: DefaultFuncs(),
	}
}

func TestEvalBool(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want bool
	}{
		{"int equality", "status_code == 200", true},
		{"int equality false", "status_code == 404", false},
		{"single quoted string, this is what broke in production", "contains(body, 'world')", true},
		{"double quoted string", `contains(body, "world")`, true},
		{"and", "status_code == 200 && contains(body, 'hello')", true},
		{"and short-circuits on false", "status_code == 404 && contains(body, 'hello')", false},
		{"or", "status_code == 404 || contains(body, 'hello')", true},
		{"negation", "!contains(body, 'nope')", true},
		{"numeric comparison", "content_length > 5", true},
		{"numeric comparison false", "content_length > 100", false},
		{"starts_with", "starts_with(body, 'hello')", true},
		{"ends_with", "ends_with(body, 'world')", true},
		{"to_lower", "to_lower('HELLO') == 'hello'", true},
		{"len", "len(body) == 11", true},
		{"regex", "regex('^hello', body)", true},
		{"parens", "(status_code == 200) && (content_length == 11)", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := EvalBool(c.expr, env())
			if err != nil {
				t.Fatalf("EvalBool(%q) returned error: %v", c.expr, err)
			}
			if got != c.want {
				t.Errorf("EvalBool(%q) = %v, want %v", c.expr, got, c.want)
			}
		})
	}
}

func TestEvalBool_Errors(t *testing.T) {
	cases := []string{
		"undefined_var == 1",
		"undefined_func(body)",
		"status_code +",    // parse error
		`"just a string"`,  // not a bool
		"status_code == '", // unterminated single quote
	}
	for _, expr := range cases {
		t.Run(expr, func(t *testing.T) {
			if _, err := EvalBool(expr, env()); err == nil {
				t.Errorf("EvalBool(%q) expected an error, got nil", expr)
			}
		})
	}
}

// This is the exact bug found while testing against a live target: Go's own
// grammar treats 'x' as a rune literal, so any single-quoted string longer
// than one character used to blow up go/parser entirely. Locking this down
// so it can't come back.
func TestPreprocessQuotes(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`contains(body, 'foo')`, `contains(body, "foo")`},
		{`header('Set-Cookie')`, `header("Set-Cookie")`},
		{`a == 'x' && b == 'y'`, `a == "x" && b == "y"`},
		{`contains(body, "already double quoted")`, `contains(body, "already double quoted")`},
		{"regex(`[0-9]+\\.[0-9]+`, body)", "regex(`[0-9]+\\.[0-9]+`, body)"}, // backtick raw strings pass through untouched
	}
	for _, c := range cases {
		got := preprocessQuotes(c.in)
		if got != c.want {
			t.Errorf("preprocessQuotes(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEval_NonBoolResult(t *testing.T) {
	_, err := EvalBool("1 + 1", env())
	if err == nil {
		t.Fatal("expected an error evaluating a non-boolean expression as a matcher")
	}
}
