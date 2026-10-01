# Shauth

Shauth is an OpenID Connect identity provider for a group of web applications.
One sign-in to Shauth signs a person in to every registered application, and
signing out of any one of them signs them out of all of them.

- **Sign-in sources:** GitHub, an optional single Microsoft Entra ID tenant, and
  local accounts created by an administrator or by invitation.
- **Issuer:** [Ory Hydra](https://www.ory.sh/hydra/) v26.2.0, with two patches
  (see [`third_party/hydra-v26.2.0`](third_party/hydra-v26.2.0/README.md)),
  issues and revokes every OAuth token. Shauth serves Hydra's public endpoints
  from its own origin.
- **State:** accounts, browser sessions, invitations, access rules and the audit
  log live in PostgreSQL.
- **Administration:** a server-rendered HTMX interface, plus a JSON API with
  separate read and write credentials.
- **App checks:** a Chromium validator signs in to each registered application
  and out again, and reports whether single sign-on and global logout really
  work.

Applications integrate only with Shauth's OIDC issuer, never with GitHub or
Entra ID directly. An application that cannot speak OIDC itself can sit behind
the bundled [relying-party gateway](docs/gateway.md).

## Images

`ghcr.io/e6qu/shauth:<sha12>` contains:

| Binary | Purpose |
|---|---|
| `/shauth` | The identity service and administration interface. |
| `/hydra` | The patched Ory Hydra. |
| `/shauth-migrate` | Applies Shauth's PostgreSQL migrations. |
| `/shauth-gateway` | OIDC gateway for an application without its own OIDC client. |
| `/shauth-healthcheck` | Container health probe. |

`ghcr.io/e6qu/shauth-validator:<sha12>` is the browser validator
(`Dockerfile.validator`, `validator/`).

Both are multi-architecture (amd64, arm64) and tagged only by the 12-character
commit. There is no `latest` tag.

## Quick start

```sh
go test ./...                                   # unit tests
./scripts/test-stack.sh                         # whole stack plus every browser test
SHAUTH_HOST_PORT=18080 ./scripts/test-stack.sh  # if port 8080 is taken
```

See [docs/development.md](docs/development.md) for requirements and details.

## Documentation

| Page | Contents |
|---|---|
| [Architecture](docs/architecture.md) | Sign-in, sessions, tokens, logout and access rules. |
| [Integrating an application](docs/integrating-apps.md) | What an application registers and implements, and how Shauth checks it. |
| [Relying-party gateway](docs/gateway.md) | Putting an application without OIDC support behind Shauth. |
| [API](docs/api.md) | The JSON administration, catalog and observability endpoints. |
| [Operations](docs/operations.md) | Configuration, monitoring sources, images and deployment. |
| [Development](docs/development.md) | Repository layout, tests and CI. |
| [Terraform module](terraform/README.md) | An Amazon ECS deployment of Shauth. |
| [Agent guidelines](AGENTS.md) | Rules for anyone, human or agent, changing this repository. |
