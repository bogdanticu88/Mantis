package templates

import "testing"

func TestRunExtractors_JSON(t *testing.T) {
	r := resp(200, `{"id": "pay_123", "nested": {"token": "abc"}}`, nil)
	vars := map[string]string{}
	spec := RequestSpec{Extractors: []Extractor{
		{Type: "json", Name: "payment_id", Path: "$.id"},
		{Type: "json", Name: "token", Path: "$.nested.token"},
		{Type: "json", Name: "missing", Path: "$.nope"},
	}}
	if err := runExtractors(spec, r, vars); err != nil {
		t.Fatalf("runExtractors: %v", err)
	}
	if vars["payment_id"] != "pay_123" {
		t.Errorf("payment_id = %q, want pay_123", vars["payment_id"])
	}
	if vars["token"] != "abc" {
		t.Errorf("token = %q, want abc", vars["token"])
	}
	if _, ok := vars["missing"]; ok {
		t.Error("extractor for a missing path should not set the variable at all")
	}
}

func TestRunExtractors_Regex(t *testing.T) {
	r := resp(200, `csrf_token=deadbeef1234; expires=soon`, nil)
	vars := map[string]string{}
	spec := RequestSpec{Extractors: []Extractor{
		{Type: "regex", Name: "csrf", Regex: `csrf_token=([a-f0-9]+)`, Group: 1},
		{Type: "regex", Name: "whole_match", Regex: `csrf_token=[a-f0-9]+`}, // group 0 (default)
	}}
	if err := runExtractors(spec, r, vars); err != nil {
		t.Fatalf("runExtractors: %v", err)
	}
	if vars["csrf"] != "deadbeef1234" {
		t.Errorf("csrf = %q, want deadbeef1234", vars["csrf"])
	}
	if vars["whole_match"] != "csrf_token=deadbeef1234" {
		t.Errorf("whole_match = %q", vars["whole_match"])
	}
}

func TestRunExtractors_Header(t *testing.T) {
	r := resp(200, "", map[string]string{"X-Session-Id": "sess-abc"})
	vars := map[string]string{}
	spec := RequestSpec{Extractors: []Extractor{{Type: "header", Name: "session", Header: "X-Session-Id"}}}
	if err := runExtractors(spec, r, vars); err != nil {
		t.Fatalf("runExtractors: %v", err)
	}
	if vars["session"] != "sess-abc" {
		t.Errorf("session = %q, want sess-abc", vars["session"])
	}
}

func TestRunExtractors_InvalidRegexIsAnError(t *testing.T) {
	r := resp(200, "anything", nil)
	spec := RequestSpec{Extractors: []Extractor{{Type: "regex", Name: "bad", Regex: "("}}}
	if err := runExtractors(spec, r, map[string]string{}); err == nil {
		t.Error("extractor with an invalid regex should return an error")
	}
}
