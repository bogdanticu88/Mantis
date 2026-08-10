package httpclient

import (
	"strings"

	"mantis/internal/findings"
)

const redactedPlaceholder = "***REDACTED***"

// sensitiveHeaders is the default set of headers whose values are never
// written into evidence, reports, or logs.
var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"proxy-authorization": true,
}

// Redactor decides which header/body content must be scrubbed before an
// HTTP exchange is turned into persisted evidence. Secrets is an additional
// list of literal secret values (e.g. resolved ${MANTIS_TOKEN}) that get
// scrubbed wherever they appear, including inside bodies.
type Redactor struct {
	ExtraHeaders map[string]bool
	Secrets      []string
}

func NewRedactor(secrets ...string) *Redactor {
	nonEmpty := make([]string, 0, len(secrets))
	for _, s := range secrets {
		if strings.TrimSpace(s) != "" {
			nonEmpty = append(nonEmpty, s)
		}
	}
	return &Redactor{Secrets: nonEmpty}
}

func (r *Redactor) isSensitiveHeader(name string) bool {
	name = strings.ToLower(name)
	if sensitiveHeaders[name] {
		return true
	}
	return r.ExtraHeaders != nil && r.ExtraHeaders[name]
}

func (r *Redactor) scrubString(s string) string {
	for _, secret := range r.Secrets {
		if secret == "" {
			continue
		}
		s = strings.ReplaceAll(s, secret, redactedPlaceholder)
	}
	return s
}

func (r *Redactor) redactHeaders(h map[string][]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		val := strings.Join(v, ", ")
		if r.isSensitiveHeader(k) {
			out[k] = redactedPlaceholder
			continue
		}
		out[k] = r.scrubString(val)
	}
	return out
}

func (r *Redactor) redactRequestHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if r.isSensitiveHeader(k) {
			out[k] = redactedPlaceholder
			continue
		}
		out[k] = r.scrubString(v)
	}
	return out
}

// Exchange converts a Response (and its originating Request) into a
// findings.HTTPExchange with all sensitive data redacted. This is the only
// sanctioned path from a live HTTP exchange into anything that gets written
// to disk as a report or log line.
func (r *Redactor) Exchange(resp *Response) findings.HTTPExchange {
	return findings.HTTPExchange{
		Method:          resp.Request.Method,
		URL:             resp.Request.URL,
		RequestHeaders:  r.redactRequestHeaders(resp.Request.Headers),
		RequestBody:     r.scrubString(string(resp.Request.Body)),
		StatusCode:      resp.StatusCode,
		ResponseHeaders: r.redactHeaders(resp.Headers),
		ResponseBody:    r.scrubString(string(resp.Body)),
		DurationMS:      resp.Duration.Milliseconds(),
	}
}
