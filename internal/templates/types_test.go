package templates

import "testing"

func validTemplate() *Template {
	return &Template{
		ID:   "t1",
		Info: Info{Name: "Test", Severity: "high"},
		Requests: []RequestSpec{{
			Method:   "GET",
			Path:     "/",
			Matchers: []Matcher{{Type: "status", Status: []int{200}}},
		}},
	}
}

func TestValidate_Valid(t *testing.T) {
	if err := validTemplate().Validate(); err != nil {
		t.Errorf("valid template failed validation: %v", err)
	}
}

func TestValidate_Rejections(t *testing.T) {
	cases := map[string]func(*Template){
		"missing id":             func(tpl *Template) { tpl.ID = "" },
		"missing name":           func(tpl *Template) { tpl.Info.Name = "" },
		"invalid severity":       func(tpl *Template) { tpl.Info.Severity = "extremely-bad" },
		"no requests":            func(tpl *Template) { tpl.Requests = nil },
		"request missing method": func(tpl *Template) { tpl.Requests[0].Method = "" },
		"request missing path":   func(tpl *Template) { tpl.Requests[0].Path = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tpl := validTemplate()
			mutate(tpl)
			if err := tpl.Validate(); err == nil {
				t.Errorf("%s: expected Validate() to fail, got nil", name)
			}
		})
	}
}

func TestValidate_MatcherRejections(t *testing.T) {
	cases := map[string]Matcher{
		"status with no codes":  {Type: "status"},
		"word with no words":    {Type: "word"},
		"regex with no pattern": {Type: "regex"},
		"json with no path":     {Type: "json"},
		"dsl with no expr":      {Type: "dsl"},
		"unknown type":          {Type: "made-up-type"},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			tpl := validTemplate()
			tpl.Requests[0].Matchers = []Matcher{m}
			if err := tpl.Validate(); err == nil {
				t.Errorf("%s: expected Validate() to fail, got nil", name)
			}
		})
	}
}

func TestValidate_ExtractorRejections(t *testing.T) {
	cases := map[string]Extractor{
		"no name":               {Type: "json", Path: "$.a"},
		"json with no path":     {Type: "json", Name: "x"},
		"regex with no pattern": {Type: "regex", Name: "x"},
		"header with no name":   {Type: "header", Name: "x"},
		"unknown type":          {Type: "made-up-type", Name: "x"},
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			tpl := validTemplate()
			tpl.Requests[0].Extractors = []Extractor{e}
			if err := tpl.Validate(); err == nil {
				t.Errorf("%s: expected Validate() to fail, got nil", name)
			}
		})
	}
}
