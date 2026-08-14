package globalmatchers

import (
	"net/http"
	"testing"

	"github.com/bogdanticu88/Mantis/internal/httpclient"
)

func fakeResp(body string, headers map[string]string) *httpclient.Response {
	h := make(http.Header)
	for k, v := range headers {
		h.Set(k, v)
	}
	return &httpclient.Response{
		StatusCode: 200,
		Headers:    h,
		Body:       []byte(body),
		Request:    httpclient.Request{Method: "GET", URL: "http://example.com/"},
	}
}

func TestEvalAll_NoMatchers(t *testing.T) {
	resp := fakeResp("hello world", nil)
	got := EvalAll(nil, resp, "http://example.com", "test", "/")
	if len(got) != 0 {
		t.Errorf("expected no findings with nil matchers, got %d", len(got))
	}
}

func TestEvalAll_AWSKey(t *testing.T) {
	body := `{"key":"AKIAIOSFODNN7EXAMPLE","region":"us-east-1"}`
	resp := fakeResp(body, nil)
	got := EvalAll(Builtin, resp, "http://example.com", "test", "/api/config")
	found := false
	for _, f := range got {
		if f.ID == "MANTIS-GM-AWS-KEY" {
			found = true
			if f.Severity != "high" {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
			if len(f.Evidence.MatchedOn) == 0 {
				t.Error("expected at least one matched_on entry")
			}
		}
	}
	if !found {
		t.Error("expected MANTIS-GM-AWS-KEY finding for AWS key in response body")
	}
}

func TestEvalAll_SQLError(t *testing.T) {
	body := `You have an error in your SQL syntax near ''`
	resp := fakeResp(body, nil)
	got := EvalAll(Builtin, resp, "http://example.com", "test", "/search")
	found := false
	for _, f := range got {
		if f.ID == "MANTIS-GM-SQL-ERROR" {
			found = true
		}
	}
	if !found {
		t.Error("expected MANTIS-GM-SQL-ERROR finding for SQL error text in response")
	}
}

func TestEvalAll_PrivateKey(t *testing.T) {
	body := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCA..."
	resp := fakeResp(body, nil)
	got := EvalAll(Builtin, resp, "http://example.com", "test", "/cert")
	found := false
	for _, f := range got {
		if f.ID == "MANTIS-GM-PRIVATE-KEY" {
			found = true
			if f.Severity != "critical" {
				t.Errorf("expected critical severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected MANTIS-GM-PRIVATE-KEY finding for private key material in body")
	}
}

func TestEvalAll_CleanResponse(t *testing.T) {
	resp := fakeResp(`{"status":"ok"}`, nil)
	got := EvalAll(Builtin, resp, "http://example.com", "test", "/health")
	if len(got) != 0 {
		t.Errorf("expected no findings for clean response, got %d: %v", len(got), got)
	}
}

func TestEvalAll_FindingFields(t *testing.T) {
	body := `AKIAIOSFODNN7EXAMPLE`
	resp := fakeResp(body, nil)
	got := EvalAll(Builtin, resp, "http://example.com", "prod", "/api/keys")
	if len(got) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := got[0]
	if f.Target != "http://example.com" {
		t.Errorf("Target = %q, want http://example.com", f.Target)
	}
	if f.Environment != "prod" {
		t.Errorf("Environment = %q, want prod", f.Environment)
	}
	if f.Endpoint != "/api/keys" {
		t.Errorf("Endpoint = %q, want /api/keys", f.Endpoint)
	}
	if f.Confidence != 0.8 {
		t.Errorf("Confidence = %v, want 0.8", f.Confidence)
	}
	if f.CWE == "" {
		t.Error("CWE should not be empty")
	}
	if f.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}
