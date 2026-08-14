package templates

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bogdanticu88/Mantis/internal/httpclient"
)

// --- parser tests ---

func TestParseFlow_Valid(t *testing.T) {
	cases := map[string]string{
		"single http call": `http(1)`,
		"if/end":           "http(1)\nif http1_matched\n  http(2)\nend",
		"if/else/end":      "http(1)\nif http1_matched\n  http(2)\nelse\n  http(3)\nend",
		"set statement":    "set x = http1_status == 200\nhttp(1)",
		"stop":             "http(1)\nstop",
		"comments":         "# probe\nhttp(1)\n# done",
		"blank lines":      "\n\nhttp(1)\n\n",
		"nested if": `
http(1)
if http1_matched
  http(2)
  if http2_status == 200
    http(3)
  end
end`,
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseFlow(script); err != nil {
				t.Errorf("parseFlow(%q) returned unexpected error: %v", name, err)
			}
		})
	}
}

func TestParseFlow_Errors(t *testing.T) {
	cases := map[string]string{
		"missing end":       "http(1)\nif http1_matched\n  http(2)",
		"unknown statement": "foo(1)",
		"http zero":         "http(0)",
		"http non-integer":  "http(abc)",
		"set no equals":     "set x 42",
		"set no name":       "set  = 42",
		"set no expr":       "set x = ",
		"if no condition":   "if \n  http(1)\nend",
		"stray end":         "http(1)\nend",
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseFlow(script); err == nil {
				t.Errorf("parseFlow(%q): expected an error, got nil", name)
			}
		})
	}
}

// --- execution tests ---

func flowTestClient(t *testing.T) *httpclient.Client {
	t.Helper()
	c, err := httpclient.New(httpclient.Config{})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}
	return c
}

// TestRun_Flow_LinearExecution verifies that a flow with only http() calls in
// order behaves identically to a plain linear chain.
func TestRun_Flow_LinearExecution(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/probe" {
			w.Write([]byte("secret-data"))
		}
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "flow-linear",
		Info: Info{Name: "Flow Linear", Severity: "high"},
		Flow: "http(1)",
		Requests: []RequestSpec{{
			Method:   "GET",
			Path:     "/probe",
			Matchers: []Matcher{{Type: "word", Words: []string{"secret-data"}}},
		}},
	}

	result := Run(context.Background(), flowTestClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if !result.Matched {
		t.Error("expected the flow to produce a finding")
	}
	if len(result.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(result.Findings))
	}
}

// TestRun_Flow_ConditionalBranch verifies that the if/end block gates request
// execution on the outcome of a prior http() call.
func TestRun_Flow_ConditionalBranch(t *testing.T) {
	var step2Called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/probe":
			w.WriteHeader(http.StatusNotFound) // step1 does not match
		case "/exploit":
			step2Called = true
			w.Write([]byte("exploited"))
		}
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "flow-branch",
		Info: Info{Name: "Flow Branch", Severity: "high"},
		Flow: "http(1)\nif http1_matched\n  http(2)\nend",
		Requests: []RequestSpec{
			{Method: "GET", Path: "/probe", Matchers: []Matcher{{Type: "status", Status: []int{200}}}},
			{Method: "GET", Path: "/exploit", Matchers: []Matcher{{Type: "word", Words: []string{"exploited"}}}},
		},
	}

	result := Run(context.Background(), flowTestClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if step2Called {
		t.Error("step2 should not have run: step1 returned 404 so http1_matched is false")
	}
	if result.Matched {
		t.Error("expected no findings when the condition blocked step2")
	}
}

// TestRun_Flow_ConditionalBranchTaken verifies the matching path when the
// condition is true.
func TestRun_Flow_ConditionalBranchTaken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/probe":
			w.WriteHeader(http.StatusOK)
		case "/exploit":
			w.Write([]byte("exploited"))
		}
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "flow-branch-taken",
		Info: Info{Name: "Flow Branch Taken", Severity: "critical"},
		Flow: "http(1)\nif http1_matched\n  http(2)\nend",
		Requests: []RequestSpec{
			{Method: "GET", Path: "/probe", Matchers: []Matcher{{Type: "status", Status: []int{200}}}},
			{Method: "GET", Path: "/exploit", Matchers: []Matcher{{Type: "word", Words: []string{"exploited"}}}},
		},
	}

	result := Run(context.Background(), flowTestClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if !result.Matched {
		t.Error("expected a finding when probe matched and the branch ran exploit")
	}
}

// TestRun_Flow_ElseBranch verifies the else path.
func TestRun_Flow_ElseBranch(t *testing.T) {
	var elseCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/probe":
			w.WriteHeader(http.StatusNotFound)
		case "/fallback":
			elseCalled = true
			w.Write([]byte("fallback"))
		}
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "flow-else",
		Info: Info{Name: "Flow Else", Severity: "medium"},
		Flow: "http(1)\nif http1_matched\n  http(2)\nelse\n  http(3)\nend",
		Requests: []RequestSpec{
			{Method: "GET", Path: "/probe", Matchers: []Matcher{{Type: "status", Status: []int{200}}}},
			{Method: "GET", Path: "/branch-a", Matchers: []Matcher{{Type: "word", Words: []string{"branchA"}}}},
			{Method: "GET", Path: "/fallback", Matchers: []Matcher{{Type: "word", Words: []string{"fallback"}}}},
		},
	}

	result := Run(context.Background(), flowTestClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if !elseCalled {
		t.Error("expected the else branch to run when probe returned 404")
	}
	if !result.Matched {
		t.Error("expected the else branch finding to be returned")
	}
}

// TestRun_Flow_Stop verifies that a stop statement terminates the flow and
// findings collected before it are preserved.
func TestRun_Flow_Stop(t *testing.T) {
	var step2Called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/step1":
			w.Write([]byte("found"))
		case "/step2":
			step2Called = true
		}
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "flow-stop",
		Info: Info{Name: "Flow Stop", Severity: "high"},
		Flow: "http(1)\nstop\nhttp(2)",
		Requests: []RequestSpec{
			{Method: "GET", Path: "/step1", Matchers: []Matcher{{Type: "word", Words: []string{"found"}}}},
			{Method: "GET", Path: "/step2", Matchers: []Matcher{{Type: "status", Status: []int{200}}}},
		},
	}

	result := Run(context.Background(), flowTestClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if step2Called {
		t.Error("step2 should not run after a stop statement")
	}
	if !result.Matched {
		t.Error("finding from step1 should be preserved after stop")
	}
}

// TestRun_Flow_SetVar verifies that set stores a value and that it is
// accessible in subsequent conditions and request rendering.
func TestRun_Flow_SetVar(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/step1":
			w.WriteHeader(http.StatusOK)
		case "/step2":
			// The query param should equal the value we set.
			if r.URL.Query().Get("ok") == "true" {
				w.Write([]byte("matched"))
			}
		}
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "flow-set",
		Info: Info{Name: "Flow Set", Severity: "medium"},
		Flow: "http(1)\nset ok = http1_matched\nif ok\n  http(2)\nend",
		Requests: []RequestSpec{
			{Method: "GET", Path: "/step1", Matchers: []Matcher{{Type: "status", Status: []int{200}}}},
			{Method: "GET", Path: "/step2?ok={{ok}}", Matchers: []Matcher{{Type: "word", Words: []string{"matched"}}}},
		},
	}

	result := Run(context.Background(), flowTestClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if !result.Matched {
		t.Error("expected a finding: set ok = http1_matched should have been true and step2 should have matched")
	}
}

// TestRun_Flow_OutOfOrderExecution verifies that the flow can call requests
// in non-sequential order (the primary advantage over the linear chain).
func TestRun_Flow_OutOfOrderExecution(t *testing.T) {
	var order []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, r.URL.Path)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "flow-order",
		Info: Info{Name: "Flow Order", Severity: "info"},
		// Deliberately reverse order: 3, 1, 2.
		Flow: "http(3)\nhttp(1)\nhttp(2)",
		Requests: []RequestSpec{
			{Method: "GET", Path: "/req1"},
			{Method: "GET", Path: "/req2"},
			{Method: "GET", Path: "/req3"},
		},
	}

	Run(context.Background(), flowTestClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	want := []string{"/req3", "/req1", "/req2"}
	if len(order) != 3 {
		t.Fatalf("expected 3 requests, got %d: %v", len(order), order)
	}
	for i, p := range want {
		if order[i] != p {
			t.Errorf("request[%d] = %q, want %q", i, order[i], p)
		}
	}
}

// TestRun_Flow_StatusCondition verifies that the http<N>_status variable is
// available as an integer for numeric comparisons in if conditions.
func TestRun_Flow_StatusCondition(t *testing.T) {
	var step2Called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/probe":
			w.WriteHeader(http.StatusForbidden) // 403
		case "/step2":
			step2Called = true
		}
	}))
	defer srv.Close()

	tpl := &Template{
		ID:   "flow-status",
		Info: Info{Name: "Flow Status", Severity: "medium"},
		// Only escalate if we get a 403 (interesting, not 404).
		Flow: "http(1)\nif http1_status == 403\n  http(2)\nend",
		Requests: []RequestSpec{
			{Method: "GET", Path: "/probe"},
			{Method: "GET", Path: "/step2", Matchers: []Matcher{{Type: "status", Status: []int{200}}}},
		},
	}

	Run(context.Background(), flowTestClient(t), httpclient.NewRedactor(), tpl, srv.URL, "test", nil)
	if !step2Called {
		t.Error("expected step2 to run: probe returned 403 and the condition is http1_status == 403")
	}
}

// TestValidate_FlowSyntaxError verifies that Validate rejects templates with
// syntactically invalid flow scripts before any request is made.
func TestValidate_FlowSyntaxError(t *testing.T) {
	tpl := &Template{
		ID:   "bad-flow",
		Info: Info{Name: "Bad Flow", Severity: "low"},
		Flow: "http(1)\nif http1_matched\n  http(2)\n# missing end",
		Requests: []RequestSpec{
			{Method: "GET", Path: "/"},
		},
	}
	if err := tpl.Validate(); err == nil {
		t.Error("expected Validate() to fail on a flow script with a missing 'end'")
	}
}

// TestValidate_FlowValid verifies that a syntactically correct flow script
// passes validation.
func TestValidate_FlowValid(t *testing.T) {
	tpl := &Template{
		ID:   "good-flow",
		Info: Info{Name: "Good Flow", Severity: "high"},
		Flow: "http(1)\nif http1_matched\n  http(2)\nend",
		Requests: []RequestSpec{
			{Method: "GET", Path: "/probe"},
			{Method: "GET", Path: "/exploit", Matchers: []Matcher{{Type: "word", Words: []string{"vuln"}}}},
		},
	}
	if err := tpl.Validate(); err != nil {
		t.Errorf("expected a valid flow template to pass Validate(), got: %v", err)
	}
}
