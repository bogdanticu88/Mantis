# Mantis

A template-driven DAST and application validation tool, meant to run as a
step in a deployment pipeline rather than as a standalone scanner someone
kicks off by hand.

The idea: after every deploy, ask two things - did the app actually come up
working, and did this deploy introduce anything security-relevant. Smoke
tests answer the first. Templates, a crawler with passive checks, and some
OpenAPI-driven API tests answer the second. Everything feeds into one gate
decision with a real exit code, so it's usable as an actual pipeline step
and not just a report nobody reads.

Detection is deterministic on purpose - no model in the loop deciding
whether something's a finding. A template either matches or it doesn't.

## Status

v0.1. Go, single binary, two external dependencies (`gopkg.in/yaml.v3`,
`golang.org/x/net/html`). Everything else - the HTTP client, the
matcher/extractor engine, the DSL, the OpenAPI reader, SARIF/JUnit output -
is hand-rolled. Wanted to keep this light and not drag in a pile of
transitive dependencies for what are, individually, fairly small problems.

## Build

```
go build -o mantis.exe ./cmd/mantis
```

## Commands

```
mantis scan <target> [--templates-dir dir] [--fail-on level] [--report format]
mantis dast <target> [--templates-dir dir] [--fail-on level] [--report format]
mantis smoke --target <url> [--workflows-dir dir]
mantis api scan --target <url> --openapi <file> [--destructive]
mantis validate --environment <name> [--environments-file file] [--report format]
mantis templates list|validate|test
```

Every scan/dast/smoke/api/validate command accepts:
`--environment`, `--environments-file`, `--fail-on critical|high|medium|low|any`,
`--report` (comma-separated: `json,sarif,junit,html,azdo`), `--output <path>`
(exact path, only valid with a single file-based format), `--output-dir <dir>`
(where multiple formats land at their conventional filenames — e.g.
`mantis-report.junit.xml`, `mantis-report.sarif`), `--insecure-skip-verify`,
`--timeout`. Flags can go before or after the positional target — both
`mantis scan --fail-on high <target>` and `mantis scan <target> --fail-on high`
work.

`validate` is the CI/CD gate command: it runs smoke tests, passive DAST, active
DAST and (optionally) API tests according to the target environment's policy,
then makes a single pass/fail decision and sets the process exit code
accordingly (`0` = pass, `1` = fail). That's what you wire into a pipeline step.
Before running any checks, every command does one baseline reachability
request to the target; if that fails outright (DNS, connection refused,
timeout), the command exits with an operational error instead of silently
running zero checks and reporting a clean pass.

### Azure DevOps

The `azdo` report format streams Azure Pipelines
[logging commands](https://learn.microsoft.com/azure/devops/pipelines/scripts/logging-commands)
directly to stdout during the run — findings become real entries in the
pipeline's Issues panel (errors for critical/high, warnings for
medium/low/info), and the task is explicitly marked failed via
`task.complete result=Failed` when the gate doesn't pass. No marketplace
extension needed; unlike the other formats, `azdo` is only meaningful printed
live to the console, never written to a file. Combine it with `junit` (for
the pipeline's Tests tab via `PublishTestResults@2`) and `sarif`/`html` (for
artifact publishing) in one `--report` value — see
`ci/azure-pipelines.example.yml` for a complete, tested step block.

## Environments

`environments.yaml` (see `environments.example.yaml`) maps environment names to
a base URL, a `security_level` (`aggressive` / `standard` / `passive`) and
optional authentication. Security level controls what Mantis is allowed to do:

| Level      | Smoke | Passive DAST | Active DAST | Destructive |
|------------|:-----:|:-------------:|:-----------:|:-----------:|
| aggressive |  Yes  |      Yes      |     Yes     |     Yes     |
| standard   |  Yes  |      Yes      |     Yes     |      No     |
| passive    |  Yes  |      Yes      |      No     |      No     |

Any environment name that isn't found, or has no recognized `security_level`,
resolves to `passive` — the safest policy. Production should always be
`passive` unless you have a specific reason and explicit sign-off to do
otherwise.

## Templates

Templates live under `templates-community/` (22 shipped — headers, CORS,
cookies, directory listing, `.git`/`.env`/`.DS_Store` exposure, actuator,
swagger, debug endpoints, open redirect, path traversal, reflected XSS,
SQL injection, AWS + Azure instance-metadata SSRF probes, CRLF injection,
auth-bypass headers, TRACE method, stack-trace disclosure, GraphQL
introspection). See `mantis templates list`.

The two SSRF templates (`ssrf-aws-imds-probe`, `ssrf-azure-imds-probe`) are
illustrative — they use a generic `url` query parameter, which won't match
most real apps' actual URL-fetching endpoint/param name, so treat them as a
starting point to adapt rather than turnkey coverage. The Azure one has a
sharper caveat: IMDS rejects requests without a `Metadata: true` header, so a
blind fetch-only SSRF primitive (one that can't set headers) will get a 400
from Azure's own default protection even when the SSRF itself is real — a
non-match there is not proof of absence.

Template schema (YAML): `id`, `info` (name/severity/tags/description/
remediation/cwe/owasp), optional `variables`, and a `requests` chain. Each
request has `method`, `path`, optional `headers`/`body`, `matchers` and
`extractors`.

Matchers: `status`, `word`, `regex`, `json` (JSONPath-lite, e.g. `$.a.b[0]`),
and `dsl` — a boolean expression language (`status_code == 200 &&
contains(body, "foo")`, functions: `contains`, `starts_with`, `ends_with`,
`len`, `regex`, `to_lower`, `to_upper`, `header(name)`). DSL strings use
single quotes (`header('Server')`) — they're rewritten to valid Go string
literals before evaluation, since the DSL is parsed with `go/parser` for a
real expression grammar at zero extra dependency cost.

Extractors (`json`, `regex`, `header`) pull a named variable out of a
response for use in later requests in the chain (`${name}` / `{{name}}`
placeholders in path/headers/body).

Test a single template: `mantis templates test --template <file> --target <url>`.

## Smoke tests

Workflows live under `smoke/` (see `smoke/payments-lifecycle.yaml`): an
ordered list of `steps`, each with a `request`, `assertions` (`status`,
`path` + `exists`/`equals`, or a raw `dsl` expression) and optional
`extract`. `cleanup` requests always run last, best-effort. Workflows can
`depends_on` other workflows by id; a workflow is skipped (not failed) if its
dependency didn't pass.

## API testing

`mantis api scan --target <url> --openapi <file>` reads an OpenAPI 3 (or
Swagger 2) spec and runs four generated checks: missing authentication,
undeclared HTTP method acceptance, a BOLA heuristic (flagged at reduced
confidence — it needs manual confirmation with a second user's credentials
to actually prove broken object-level authorization), and sensitive-looking
keys (password/token/ssn/etc.) in response bodies. State-changing probes
only run with `--destructive`, and only if the environment's policy also
allows it.

## Evidence and secrets

Every finding carries the request/response exchange(s) that produced it.
Sensitive headers (`Authorization`, `Cookie`, etc.) and any resolved secret
values (tokens, passwords) are redacted before a finding is ever constructed
— see `internal/httpclient/redact.go`. Secrets never reach a report or log
line.

## What's not here yet

No dedicated attack modules for per-parameter fuzzing - active coverage
right now comes from the root-relative exposure/config templates plus the
four API checks, not a full sweep across every discovered form field.
GraphQL support doesn't go past a raw introspection template. No WebSocket
testing, no browser-based crawling, no drift comparison across
environments yet (comparing the same finding between dev/test/acc/prod
would be genuinely useful and isn't built). Azure DevOps gets a native
reporter (`--report azdo`); GitHub/GitLab still only get file-based
SARIF/JUnit, no PR annotations.

The core logic packages (dsl, gate, jsonpath, findings, environments,
templates, httpclient, the dast passive checks, smoke assertions, the
OpenAPI reader, all five reporters) have a `go test` suite - run with
`go test ./...`. `cmd/mantis` itself doesn't yet; it's still verified by
actually running each command against a local fixture server rather than
by unit tests. The API package's missing-auth/method-abuse/BOLA checks and
the DAST crawler are also untested directly, since they need more scaffolding
(a fake OpenAPI-backed server, an HTML-serving one) than was worth setting
up for this pass - worth doing before this goes much further.
