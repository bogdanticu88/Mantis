package templates

import "testing"

func TestRenderVars(t *testing.T) {
	vars := map[string]string{"BaseURL": "https://example.com", "token": "abc123"}

	cases := []struct {
		in   string
		want string
	}{
		{"${BaseURL}/actuator/env", "https://example.com/actuator/env"},
		{"Bearer {{token}}", "Bearer abc123"},
		{"no placeholders here", "no placeholders here"},
		{"${BaseURL} and {{token}} together", "https://example.com and abc123 together"},
	}
	for _, c := range cases {
		if got := RenderVars(c.in, vars); got != c.want {
			t.Errorf("RenderVars(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Leaving an unresolved placeholder visible (rather than blanking it) is
// deliberate - a silently-empty value in a request is much harder to notice
// than a literal "${TYPO}" sitting in a failed request.
func TestRenderVars_UnresolvedLeftVisible(t *testing.T) {
	got := RenderVars("Bearer ${DOES_NOT_EXIST}", map[string]string{})
	want := "Bearer ${DOES_NOT_EXIST}"
	if got != want {
		t.Errorf("RenderVars with unknown var = %q, want %q", got, want)
	}
}

func TestJoinURL(t *testing.T) {
	cases := []struct{ base, path, want string }{
		{"https://example.com", "/actuator/env", "https://example.com/actuator/env"},
		{"https://example.com/", "/actuator/env", "https://example.com/actuator/env"},
		{"https://example.com", "actuator/env", "https://example.com/actuator/env"},
		{"https://example.com/", "actuator/env", "https://example.com/actuator/env"},
	}
	for _, c := range cases {
		if got := JoinURL(c.base, c.path); got != c.want {
			t.Errorf("JoinURL(%q, %q) = %q, want %q", c.base, c.path, got, c.want)
		}
	}
}
