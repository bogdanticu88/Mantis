package templates

import (
	"net/http"
	"testing"

	"github.com/bogdanticu88/Mantis/internal/httpclient"
)

func resp(status int, body string, headers map[string]string) *httpclient.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &httpclient.Response{
		Request:    httpclient.Request{Method: "GET", URL: "https://example.com/"},
		StatusCode: status,
		Headers:    h,
		Body:       []byte(body),
	}
}

func TestEvalMatcher_Status(t *testing.T) {
	r := resp(200, "", nil)

	got, err := evalMatcher(Matcher{Type: "status", Status: []int{200, 201}}, r)
	if err != nil || !got.Matched {
		t.Errorf("status matcher on 200 with [200,201] = %v, %v; want matched", got, err)
	}

	got, err = evalMatcher(Matcher{Type: "status", Status: []int{404}}, r)
	if err != nil || got.Matched {
		t.Errorf("status matcher on 200 with [404] = %v, %v; want not matched", got, err)
	}
}

func TestEvalMatcher_Word(t *testing.T) {
	r := resp(200, "activeProfiles and propertySources are both here", nil)

	// default condition is "or" - any one word is enough
	got, _ := evalMatcher(Matcher{Type: "word", Words: []string{"activeProfiles", "nope"}}, r)
	if !got.Matched {
		t.Error("word matcher (or, default) should match when one of two words is present")
	}

	// explicit "and" requires every word
	got, _ = evalMatcher(Matcher{Type: "word", Words: []string{"activeProfiles", "propertySources"}, Condition: "and"}, r)
	if !got.Matched {
		t.Error("word matcher (and) should match when all words are present")
	}

	got, _ = evalMatcher(Matcher{Type: "word", Words: []string{"activeProfiles", "nope"}, Condition: "and"}, r)
	if got.Matched {
		t.Error("word matcher (and) should not match when one word is missing")
	}
}

func TestEvalMatcher_Regex(t *testing.T) {
	r := resp(500, "SQL syntax error near line 12", nil)

	got, err := evalMatcher(Matcher{Type: "regex", Regex: []string{"SQL syntax.*error"}}, r)
	if err != nil || !got.Matched {
		t.Errorf("regex matcher should match SQL error text, got %v, %v", got, err)
	}

	_, err = evalMatcher(Matcher{Type: "regex", Regex: []string{"("}}, r) // invalid pattern
	if err == nil {
		t.Error("regex matcher with an invalid pattern should return an error, not silently fail")
	}
}

func TestEvalMatcher_WordPart(t *testing.T) {
	r := resp(200, "no secrets in the body", map[string]string{"X-Powered-By": "PHP/8.1.2"})

	got, _ := evalMatcher(Matcher{Type: "word", Words: []string{"PHP"}, Part: "body"}, r)
	if got.Matched {
		t.Error("body-scoped word matcher matched a word that's only in the headers")
	}

	got, _ = evalMatcher(Matcher{Type: "word", Words: []string{"PHP"}, Part: "header"}, r)
	if !got.Matched {
		t.Error("header-scoped word matcher should have found the word in X-Powered-By")
	}
}

func TestEvalMatcher_JSON(t *testing.T) {
	r := resp(200, `{"activeProfiles": ["prod"], "count": 3}`, nil)

	got, err := evalMatcher(Matcher{Type: "json", Path: "$.activeProfiles"}, r)
	if err != nil || !got.Matched {
		t.Errorf("json existence matcher on present path = %v, %v; want matched", got, err)
	}

	got, _ = evalMatcher(Matcher{Type: "json", Path: "$.missing"}, r)
	if got.Matched {
		t.Error("json existence matcher matched a path that isn't in the body")
	}

	got, _ = evalMatcher(Matcher{Type: "json", Path: "$.count", Value: "3"}, r)
	if !got.Matched {
		t.Error("json value matcher should match when the value equals the expected string")
	}

	got, _ = evalMatcher(Matcher{Type: "json", Path: "$.count", Value: "4"}, r)
	if got.Matched {
		t.Error("json value matcher should not match a wrong value")
	}
}

func TestEvalMatcher_JSON_NonJSONBody(t *testing.T) {
	// A json matcher against an HTML error page or similar should just not
	// match - it shouldn't be an error just because the body isn't JSON.
	r := resp(200, "<html>not json at all</html>", nil)
	got, err := evalMatcher(Matcher{Type: "json", Path: "$.anything"}, r)
	if err != nil {
		t.Errorf("json matcher against non-JSON body returned an error: %v", err)
	}
	if got.Matched {
		t.Error("json matcher against non-JSON body should not match")
	}
}

func TestEvalMatcher_DSL(t *testing.T) {
	r := resp(200, "hello", map[string]string{"Server": "nginx/1.18.0"})

	got, err := evalMatcher(Matcher{Type: "dsl", DSL: "status_code == 200 && contains(body, 'hello')"}, r)
	if err != nil || !got.Matched {
		t.Errorf("dsl matcher = %v, %v; want matched", got, err)
	}

	got, err = evalMatcher(Matcher{Type: "dsl", DSL: "regex('[0-9]+\\.[0-9]+', header('Server'))"}, r)
	if err != nil || !got.Matched {
		t.Errorf("dsl matcher with header() and a version regex = %v, %v; want matched", got, err)
	}
}

func TestEvalMatcher_Negative(t *testing.T) {
	// note: body deliberately doesn't contain the substring "actuator" at
	// all - earlier draft of this test used "no actuator here", which
	// still contains "actuator" and made the test wrong, not the code.
	r := resp(200, "nothing interesting in this response", nil)
	got, err := evalMatcher(Matcher{Type: "word", Words: []string{"actuator"}, Negative: true}, r)
	if err != nil || !got.Matched {
		t.Errorf("negative word matcher on absent word = %v, %v; want matched (absence confirmed)", got, err)
	}
}

func TestEvalMatcher_UnknownType(t *testing.T) {
	if _, err := evalMatcher(Matcher{Type: "nonsense"}, resp(200, "", nil)); err == nil {
		t.Error("unknown matcher type should return an error")
	}
}

func TestEvalMatchers_EmptyListAlwaysPasses(t *testing.T) {
	// This is what lets a request exist purely for chaining (e.g. a login
	// step whose only job is to extract a token).
	matched, _, err := evalMatchers(RequestSpec{}, resp(500, "", nil))
	if err != nil || !matched {
		t.Errorf("evalMatchers with no matchers = %v, %v; want unconditional match", matched, err)
	}
}

func TestEvalMatchers_DefaultConditionIsAnd(t *testing.T) {
	spec := RequestSpec{
		Matchers: []Matcher{
			{Type: "status", Status: []int{200}},
			{Type: "word", Words: []string{"nope-not-here"}},
		},
	}
	matched, _, err := evalMatchers(spec, resp(200, "hello", nil))
	if err != nil {
		t.Fatalf("evalMatchers: %v", err)
	}
	if matched {
		t.Error("default matchers-condition should be AND: one failing matcher should fail the whole request")
	}
}

func TestEvalMatchers_ExplicitOr(t *testing.T) {
	spec := RequestSpec{
		MatchersCondition: "or",
		Matchers: []Matcher{
			{Type: "status", Status: []int{999}}, // never matches
			{Type: "word", Words: []string{"hello"}},
		},
	}
	matched, _, err := evalMatchers(spec, resp(200, "hello", nil))
	if err != nil {
		t.Fatalf("evalMatchers: %v", err)
	}
	if !matched {
		t.Error("matchers-condition: or should match when at least one matcher matches")
	}
}
