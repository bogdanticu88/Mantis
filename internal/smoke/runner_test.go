package smoke

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bogdanticu88/Mantis/internal/httpclient"
)

func fakeResp(status int, body string) *httpclient.Response {
	return &httpclient.Response{StatusCode: status, Body: []byte(body)}
}

func TestEvalAssertion_Status(t *testing.T) {
	ok, _ := evalAssertion(Assertion{Status: 200}, fakeResp(200, ""), nil, false)
	if !ok {
		t.Error("status assertion should pass when status matches")
	}
	ok, reason := evalAssertion(Assertion{Status: 200}, fakeResp(404, ""), nil, false)
	if ok {
		t.Error("status assertion should fail on a status mismatch")
	}
	if reason == "" {
		t.Error("a failed assertion should explain why")
	}
}

func TestEvalAssertion_PathExistsAndEquals(t *testing.T) {
	var data any
	json.Unmarshal([]byte(`{"id": "pay_123", "currency": "EUR"}`), &data)
	r := fakeResp(201, "")

	ok, _ := evalAssertion(Assertion{Path: "$.id", Exists: true}, r, data, true)
	if !ok {
		t.Error("exists assertion should pass for a present field")
	}

	ok, _ = evalAssertion(Assertion{Path: "$.missing", Exists: true}, r, data, true)
	if ok {
		t.Error("exists assertion should fail for a missing field")
	}

	ok, _ = evalAssertion(Assertion{Path: "$.currency", Equals: "EUR"}, r, data, true)
	if !ok {
		t.Error("equals assertion should pass when the value matches")
	}

	ok, _ = evalAssertion(Assertion{Path: "$.currency", Equals: "USD"}, r, data, true)
	if ok {
		t.Error("equals assertion should fail when the value doesn't match")
	}
}

func TestEvalAssertion_PathOnNonJSONBody(t *testing.T) {
	ok, reason := evalAssertion(Assertion{Path: "$.id", Exists: true}, fakeResp(200, "not json"), nil, false)
	if ok {
		t.Error("path assertion against a non-JSON body should fail, not silently pass")
	}
	if reason == "" {
		t.Error("should explain that the body wasn't JSON")
	}
}

func TestEvalAssertion_DSL(t *testing.T) {
	r := fakeResp(200, "hello world")
	ok, _ := evalAssertion(Assertion{DSL: "status_code == 200 && contains(body, 'hello')"}, r, nil, false)
	if !ok {
		t.Error("dsl assertion should pass when the expression is true")
	}
	ok, _ = evalAssertion(Assertion{DSL: "status_code == 404"}, r, nil, false)
	if ok {
		t.Error("dsl assertion should fail when the expression is false")
	}
}

// Full end-to-end workflow: create, extract an id, use it in the next step,
// then a best-effort cleanup call that must fire regardless of outcome.
func TestRun_FullLifecycle(t *testing.T) {
	var cleanupCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/payments":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"id": "pay_123", "currency": "EUR"})
		case r.Method == "GET" && r.URL.Path == "/payments/pay_123":
			json.NewEncoder(w).Encode(map[string]string{"status": "settled"})
		case r.Method == "DELETE" && r.URL.Path == "/payments/pay_123":
			cleanupCalled = true
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	w := &Workflow{
		ID: "lifecycle",
		Steps: []Step{
			{
				ID:      "create",
				Request: StepRequest{Method: "POST", Path: "/payments"},
				Assertions: []Assertion{
					{Status: 201},
					{Path: "$.id", Exists: true},
				},
				Extract: []Extract{{Name: "payment_id", Path: "$.id"}},
			},
			{
				ID:      "retrieve",
				Request: StepRequest{Method: "GET", Path: "/payments/${payment_id}"},
				Assertions: []Assertion{
					{Path: "$.status", Equals: "settled"},
				},
			},
		},
		Cleanup: []StepRequest{{Method: "DELETE", Path: "/payments/${payment_id}"}},
	}

	client, err := httpclient.New(httpclient.Config{})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}

	result := Run(context.Background(), client, w, srv.URL, nil)
	if !result.Passed {
		var failures []string
		for _, s := range result.Steps {
			failures = append(failures, s.Failures...)
		}
		t.Fatalf("workflow did not pass: %v", failures)
	}
	if !cleanupCalled {
		t.Error("cleanup request should have fired")
	}
}

func TestRunAll_SkipsDependentsOfFailedWorkflow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	base := &Workflow{
		ID:    "base",
		Steps: []Step{{ID: "s1", Request: StepRequest{Method: "GET", Path: "/"}, Assertions: []Assertion{{Status: 200}}}},
	}
	dependent := &Workflow{
		ID:        "dependent",
		DependsOn: []string{"base"},
		Steps:     []Step{{ID: "s1", Request: StepRequest{Method: "GET", Path: "/"}}},
	}

	client, err := httpclient.New(httpclient.Config{})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}

	results := RunAll(context.Background(), client, []*Workflow{base, dependent}, srv.URL, nil)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].Passed {
		t.Error("base workflow should have failed (server returns 500, assertion wants 200)")
	}
	if !results[1].Skipped {
		t.Error("dependent workflow should have been skipped since its dependency failed")
	}
}
