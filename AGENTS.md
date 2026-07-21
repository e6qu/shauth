# Shauth agent guidelines

`CLAUDE.md` is a symlink to this file. Edit `AGENTS.md` only.

## Product boundary

Shauth is a deployment-neutral identity service. It provides standard OpenID
Connect (OIDC), upstream GitHub and optional Microsoft Entra ID authentication,
local accounts and invitations, session administration, and a first-party HTMX
administration interface. Integrations are expressed as documented HTTPS/OIDC
coordinates and versioned contracts. Shauth must not know about Amazon ECS,
Terraform, a particular cloud provider, or how a relying party is deployed.

## Evidence and freshness

- Remote Git state is authoritative. Fetch `origin/main` and the active pull
  request ref before inspecting or editing, and rebase the branch on the newest
  `origin/main` before pushing.
- Diagnose from an exact failing test, log, HTTP exchange, or browser flow.
  Never guess from a stale worktree or cached pull-request state.
- Run the complete relevant repository gate. A unit test or health endpoint is
  not evidence that an interactive login/logout flow works.

## Identity and session contract

- Use standard OIDC discovery, authorization-code flow with PKCE where
  applicable, exact issuer/audience validation, and confidential-client
  authentication. Do not invent app-specific authentication protocols.
- One Shauth browser login must provide single sign-on to every registered app.
- Logout initiated by any relying party must revoke the Shauth session and all
  correlated relying-party sessions, then return to that initiating app's
  registered local signed-out page. Cover front-channel and signed back-channel
  logout, replay rejection, provider-initiated logout, direct entry, catalog
  entry, and fail-closed re-entry.
- Authentication and authorization always fail closed. Never expose an
  application because a token, session store, identity provider, or logout
  endpoint is unavailable.
- Sessions, refresh-token families, users, roles, and revocation state live in
  PostgreSQL. Tests must use the real PostgreSQL and Ory Hydra integrations, not
  in-memory replacements or canned HTTP responses.
- Secrets come from runtime secret injection and must never be logged, committed,
  returned to browsers, or reused across unrelated security boundaries.

## No stubs, fakes, mocks, or fallbacks

Every implementation and test performs real work. Do not add mock identity
providers, fake HTTP responses, hardcoded users or metrics, synthetic success
paths, in-memory production fallbacks, silent degraded modes, or placeholders.
If a required dependency is unavailable, fail clearly and repair the dependency.

## External dependencies

Announce any proposed new external library, image, hosted service, proxy, or
runtime before introducing it. Explain its purpose and security/operational
boundary, and wait for user approval when the choice changes architecture or
trust. Shauth and its relying parties use first-party OIDC integration; do not
introduce an authentication proxy such as `oauth2-proxy`.

## User interface

- Reuse the existing HTMX components and design tokens instead of adding bespoke
  one-off markup.
- Every page supports light and dark modes, keyboard operation, visible focus,
  semantic HTML, ARIA where semantics alone are insufficient, and WCAG AA
  contrast.
- Browser tests exercise real rendered pages and interactive behavior, including
  signed-in identity, user/session administration, app catalog navigation,
  monitoring, direct and catalog login, and global logout from every relying
  party.

## Boy Scout rule

Never dismiss a failure as pre-existing or unrelated. A symptom can share
credentials, session state, wire formats, deployment coordinates, or lifecycle
assumptions with the current change even when that relationship is initially
hidden. Investigate it and fix it in the active branch. If a real external
boundary makes an immediate repair impossible, record concrete evidence and the
required repair in the project's existing tracking documentation and tell the
user; never use tracking as a substitute for investigation.

CI failures, test failures, warnings, broken UI, inaccurate documentation,
deployment drift, observability gaps, and storage/operational hygiene are all
part of the same product. Fix the underlying problem. Never bypass hooks, narrow
tests to avoid a failure, or use `--no-verify`.

## Pull requests

- Keep one active branch and one pull request. Add related fixes, tests, and
  documentation to it rather than opening an anemic follow-up.
- Write timeless, outcome-focused commit messages and pull-request descriptions.
- Never merge a pull request. The user decides and performs merges.

## Bounded automation

- Every GitHub Actions job must declare `timeout-minutes` as a literal integer
  no greater than 15. `scripts/check-workflow-timeouts.sh` enforces this for
  every workflow; run its fixture contract and the checker before changing CI.
- Local integration scripts must bound every child-process wait, print useful
  diagnostics at the deadline, send TERM, and escalate to KILL after a short
  grace period. A CI job timeout is the final safety boundary, not a substitute
  for correctly bounded processes and cleanup.
