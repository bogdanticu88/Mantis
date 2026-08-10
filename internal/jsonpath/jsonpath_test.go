package jsonpath

import (
	"encoding/json"
	"testing"
)

func parse(t *testing.T, raw string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("test setup: invalid JSON %q: %v", raw, err)
	}
	return v
}

func TestGet(t *testing.T) {
	data := parse(t, `{
		"activeProfiles": ["prod"],
		"data": {"items": [{"id": 1}, {"id": 2}]},
		"empty": null,
		"zero": 0
	}`)

	cases := []struct {
		path string
		want any
	}{
		{"$.activeProfiles", []any{"prod"}},
		{"activeProfiles", []any{"prod"}}, // leading $. is optional
		{"$.data.items[0].id", 1.0},       // encoding/json decodes numbers as float64
		{"$.data.items[1].id", 2.0},
		{"$", data}, // empty path returns the root
		{"$.zero", 0.0},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			got, ok := Get(data, c.path)
			if !ok {
				t.Fatalf("Get(%q) reported not found, expected a value", c.path)
			}
			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(c.want)
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("Get(%q) = %s, want %s", c.path, gotJSON, wantJSON)
			}
		})
	}
}

func TestGet_NotFound(t *testing.T) {
	data := parse(t, `{"a": {"b": 1}}`)

	cases := []string{
		"$.nope",
		"$.a.nope",
		"$.a.b.c",  // indexing into a scalar
		"$.a[0]",   // array index into an object
		"$.a.b[0]", // array index into a scalar
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			if _, ok := Get(data, path); ok {
				t.Errorf("Get(%q) reported found, expected not found", path)
			}
		})
	}
}

// null is present-but-nil - Exists should still be true for it, since the
// key genuinely resolved to a value (as opposed to not existing at all).
func TestGet_NullValueExists(t *testing.T) {
	data := parse(t, `{"a": null}`)
	v, ok := Get(data, "$.a")
	if !ok {
		t.Fatal("Get(\"$.a\") on a null value reported not found, want found with nil value")
	}
	if v != nil {
		t.Errorf("Get(\"$.a\") = %v, want nil", v)
	}
}

func TestExists(t *testing.T) {
	data := parse(t, `{"a": {"b": []}}`)
	if !Exists(data, "$.a.b") {
		t.Error("Exists(\"$.a.b\") = false, want true")
	}
	if Exists(data, "$.a.c") {
		t.Error("Exists(\"$.a.c\") = true, want false")
	}
}

func TestGet_ArrayIndexOutOfRange(t *testing.T) {
	data := parse(t, `{"items": [1, 2, 3]}`)
	if _, ok := Get(data, "$.items[10]"); ok {
		t.Error("Get with out-of-range index reported found, want not found")
	}
	if _, ok := Get(data, "$.items[-1]"); ok {
		t.Error("Get with negative index reported found, want not found")
	}
}
