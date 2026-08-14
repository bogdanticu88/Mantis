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
		"missing id":                 func(tpl *Template) { tpl.ID = "" },
		"missing name":               func(tpl *Template) { tpl.Info.Name = "" },
		"invalid severity":           func(tpl *Template) { tpl.Info.Severity = "extremely-bad" },
		"no requests":                func(tpl *Template) { tpl.Requests = nil },
		"request missing method":     func(tpl *Template) { tpl.Requests[0].Method = "" },
		"request missing path":       func(tpl *Template) { tpl.Requests[0].Path = "" },
		"request path and paths set": func(tpl *Template) { tpl.Requests[0].Paths = []string{"/a"} },
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

func TestValidate_PathsField(t *testing.T) {
	tpl := validTemplate()
	tpl.Requests[0].Path = ""
	tpl.Requests[0].Paths = []string{"/a", "/b", "/c"}
	if err := tpl.Validate(); err != nil {
		t.Errorf("template using paths instead of path should be valid: %v", err)
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

func TestValidate_PayloadFields(t *testing.T) {
	// Sniper with one set is valid.
	t.Run("sniper one set", func(t *testing.T) {
		tpl := validTemplate()
		tpl.Payloads = map[string][]string{"injection": {"'", "' OR 1=1--"}}
		if err := tpl.Validate(); err != nil {
			t.Errorf("sniper with one payload set should be valid: %v", err)
		}
	})

	// Pitchfork with multiple sets is valid.
	t.Run("pitchfork multiple sets", func(t *testing.T) {
		tpl := validTemplate()
		tpl.Attack = "pitchfork"
		tpl.Payloads = map[string][]string{
			"user": {"admin", "guest"},
			"pass": {"password", "letmein"},
		}
		if err := tpl.Validate(); err != nil {
			t.Errorf("pitchfork with multiple payload sets should be valid: %v", err)
		}
	})

	// Attack mode set without payloads is an error.
	t.Run("attack without payloads", func(t *testing.T) {
		tpl := validTemplate()
		tpl.Attack = "sniper"
		if err := tpl.Validate(); err == nil {
			t.Error("expected Validate() to fail when attack is set but no payloads are defined")
		}
	})

	// Sniper with multiple sets is an error.
	t.Run("sniper multiple sets", func(t *testing.T) {
		tpl := validTemplate()
		tpl.Payloads = map[string][]string{
			"set1": {"a"},
			"set2": {"b"},
		}
		if err := tpl.Validate(); err == nil {
			t.Error("expected Validate() to fail: sniper mode does not support multiple payload sets")
		}
	})

	// Unknown attack mode is an error (clusterbomb with hyphen is still wrong).
	t.Run("unknown attack mode", func(t *testing.T) {
		tpl := validTemplate()
		tpl.Attack = "cluster-bomb"
		tpl.Payloads = map[string][]string{"x": {"a"}}
		if err := tpl.Validate(); err == nil {
			t.Error("expected Validate() to fail on unknown attack mode")
		}
	})

	// Clusterbomb with multiple sets is valid.
	t.Run("clusterbomb multiple sets", func(t *testing.T) {
		tpl := validTemplate()
		tpl.Attack = "clusterbomb"
		tpl.Payloads = map[string][]string{
			"user": {"admin", "guest"},
			"pass": {"password", "letmein"},
		}
		if err := tpl.Validate(); err != nil {
			t.Errorf("clusterbomb with multiple payload sets should be valid: %v", err)
		}
	})

	// Clusterbomb with a single set is also valid (degenerate but not an error).
	t.Run("clusterbomb single set", func(t *testing.T) {
		tpl := validTemplate()
		tpl.Attack = "clusterbomb"
		tpl.Payloads = map[string][]string{"injection": {"'", "' OR 1=1--"}}
		if err := tpl.Validate(); err != nil {
			t.Errorf("clusterbomb with one payload set should be valid: %v", err)
		}
	})

	// Empty payload set is an error.
	t.Run("empty payload set", func(t *testing.T) {
		tpl := validTemplate()
		tpl.Payloads = map[string][]string{"injection": {}}
		if err := tpl.Validate(); err == nil {
			t.Error("expected Validate() to fail when a payload set has no values")
		}
	})
}

func TestValidate_TimingMatcher(t *testing.T) {
	tpl := validTemplate()
	tpl.Requests[0].Matchers = []Matcher{{Type: "timing", MinDurationMS: 5000}}
	if err := tpl.Validate(); err != nil {
		t.Errorf("timing matcher with duration_ms=5000 should be valid: %v", err)
	}

	tpl2 := validTemplate()
	tpl2.Requests[0].Matchers = []Matcher{{Type: "timing"}}
	if err := tpl2.Validate(); err == nil {
		t.Error("timing matcher without duration_ms should fail validation")
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
