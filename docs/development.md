# Development

## Layout

| Path | Contents |
|---|---|
| `cmd/` | Entry points: `shauth`, `shauth-migrate`, `shauth-gateway`, `shauth-healthcheck`, `shauth-validator`. |
| `internal/app/` | HTTP handlers, templates, the JSON API, and the token hook. `operations.go` holds every administrative state change. |
| `internal/identity/` | PostgreSQL store: accounts, sessions, invitations, apps, audit. |
| `internal/gateway/` | The relying-party gateway and its own migrations. |
| `internal/config/` | Environment parsing and validation. |
| `internal/github/`, `internal/mailer/`, `internal/monitoring/`, `internal/observe/` | GitHub API, SES invitations, monitoring sources, logging and request metrics. |
| `migrations/` | Shauth's PostgreSQL schema. |
| `validator/` | The Playwright script the validator runs for each check. |
| `scripts/` | The integration stack, browser tests, and CI contract checks. |
| `third_party/hydra-v26.2.0/` | Ory Hydra patches. |
| `terraform/` | The Amazon ECS module. |

## Tests

Requirements:

- Go, at the version in `go.mod`;
- Docker with Compose;
- Node.js with `npm ci`;
- `jq`.

| Command | What it covers |
|---|---|
| `go test ./...` | Unit tests. |
| `go vet ./... && go vet -tags acceptance ./...` | Both build tags. |
| `npm run test:validator` | The validator's own unit tests. |
| `./scripts/test-stack.sh` | The whole system. |
| `./scripts/check-container-publication.sh` | Workflow, image-retention and process-bound contracts. |
| `terraform -chdir=terraform test` | Terraform module tests. |

`test-stack.sh` builds the image and starts PostgreSQL, Hydra and Shauth with
Compose, then:

- runs the acceptance-tagged Go tests against them;
- runs three gateways as relying parties;
- runs every Playwright journey in Chromium, covering sign-in, SSO, global
  logout from each relying party, administration, and the browser validator.

It installs Chromium on demand, and it must pass before a change merges.

| Variable | Default | Effect |
|---|---|---|
| `SHAUTH_HOST_PORT` | `8080` | Host port for Shauth. |
| `SHAUTH_STACK_BUDGET_SECONDS` | `720` | Hard deadline for the whole run. When it passes, the script prints diagnostics and stops everything. |
| `SHAUTH_STACK_FOCUS` | | `logout-correlation` or `browser-global-logout` runs only that part. |

Tests use real PostgreSQL, Hydra and Chromium. There are no mocks of the
identity provider or of HTTP responses; see [AGENTS.md](../AGENTS.md).

## CI

| Event | Workflow | Jobs |
|---|---|---|
| Pull request | `ci.yml` | The integration stack and unit tests; Terraform formatting, validation and tests; a Trivy scan of the Terraform for high and critical findings; the validator image on both architectures. |
| Push to `main` | `publish.yml` | Builds, verifies, publishes and prunes the images. |

Every job sets `timeout-minutes` of 15 or less, and
`scripts/check-workflow-timeouts.sh` enforces it.
