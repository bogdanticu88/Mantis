package api

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleSpec = `
openapi: 3.0.0
info:
  title: Test API
  version: "1.0"
security:
  - bearerAuth: []
paths:
  /health:
    get:
      operationId: health
      security: []
      responses:
        "200":
          description: ok
  /payments:
    post:
      operationId: createPayment
      responses:
        "201":
          description: created
  /payments/{id}:
    get:
      operationId: getPayment
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: ok
    delete:
      operationId: deletePayment
      responses:
        "204":
          description: deleted
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
`

func writeSpec(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openapi.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("writing temp spec: %v", err)
	}
	return path
}

func findEndpoint(spec *Spec, path, method string) (Endpoint, bool) {
	for _, ep := range spec.Endpoints {
		if ep.Path == path && ep.Method == method {
			return ep, true
		}
	}
	return Endpoint{}, false
}

func TestParseOpenAPI(t *testing.T) {
	spec, err := ParseOpenAPI(writeSpec(t, sampleSpec))
	if err != nil {
		t.Fatalf("ParseOpenAPI: %v", err)
	}
	if len(spec.Endpoints) != 4 {
		t.Fatalf("got %d endpoints, want 4", len(spec.Endpoints))
	}

	health, ok := findEndpoint(spec, "/health", "GET")
	if !ok {
		t.Fatal("missing /health GET endpoint")
	}
	if health.RequiresAuth {
		t.Error("/health declares security: [] (explicitly no auth) but RequiresAuth came back true")
	}

	create, ok := findEndpoint(spec, "/payments", "POST")
	if !ok {
		t.Fatal("missing /payments POST endpoint")
	}
	if !create.RequiresAuth {
		t.Error("/payments POST has no per-operation security, should inherit the global bearerAuth requirement")
	}

	get, ok := findEndpoint(spec, "/payments/{id}", "GET")
	if !ok {
		t.Fatal("missing /payments/{id} GET endpoint")
	}
	if len(get.Parameters) != 1 || get.Parameters[0].Name != "id" || get.Parameters[0].In != "path" {
		t.Errorf("parameters = %+v, want a single path parameter named id", get.Parameters)
	}
}

func TestParseOpenAPI_MissingFile(t *testing.T) {
	if _, err := ParseOpenAPI(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Error("expected an error reading a nonexistent spec file")
	}
}

func TestFillPath(t *testing.T) {
	cases := []struct{ path, sample, want string }{
		{"/payments/{id}", "42", "/payments/42"},
		{"/orgs/{orgId}/users/{userId}", "1", "/orgs/1/users/1"},
		{"/health", "1", "/health"},
	}
	for _, c := range cases {
		if got := FillPath(c.path, c.sample); got != c.want {
			t.Errorf("FillPath(%q, %q) = %q, want %q", c.path, c.sample, got, c.want)
		}
	}
}

func TestIsIDLike(t *testing.T) {
	cases := map[string]bool{
		"id":         true,
		"userId":     true,
		"account_id": true,
		"ID":         true,
		"category":   false,
		"name":       false,
	}
	for name, want := range cases {
		if got := IsIDLike(name); got != want {
			t.Errorf("IsIDLike(%q) = %v, want %v", name, got, want)
		}
	}
}
