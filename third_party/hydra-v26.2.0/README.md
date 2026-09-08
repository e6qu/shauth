# Ory Hydra v26.2.0 provider patch

Shauth uses Ory Hydra v26.2.0 commit
`0b84568fffccf151dc5e6c7955fdfb738555bf4b`. The container build downloads
that exact source archive and verifies SHA-256
`7ceaae3299780959e8390925732629931f63f20300464d2822d49628eeb3332e`
before applying `logout-token-exp.patch` and `no-sentinel-error-log.patch`.

The Docker build then pins security-fixed versions of vulnerable transitive Go
modules before compiling Hydra. These pins are part of the reproducible image
build and must be retained until a newer upstream Hydra release supersedes
v26.2.0.

The patch adds the required `exp` claim to every OpenID Connect Back-Channel
Logout Token, with a two-minute lifetime from `iat`. It is the minimal portion
of the upstream fix proposed in
<https://github.com/ory/hydra/pull/4073>, adapted to the released v26.2.0
source. Shauth can remove the patch after an official Hydra release includes
the standards fix and passes the repository's multi-relying-party logout test.

`no-sentinel-error-log.patch` stops Hydra logging its own control flow as an
error. `HandleOAuth2AuthorizationRequest` returns `ErrAbortOAuth2Request` when
it has sent the browser to the login or consent UI, which is every sign-in that
starts without a session, and v26.2.0 logged each one as
`level=error msg="An error occurred" error="the OAuth 2.0 Authorization request
must be aborted"`. On the shared dev environment that was about 1,800 error
lines per few hours, most of them the SSO validator's own probes, drowning real
errors in any log sweep. It is the handler half of upstream commit
`917d39a74a09` ("fix: don't log sentinel error in Hydra", 2026-05-21), which
also renames the sentinel; the rename is not needed to stop the logging and is
left to the next Hydra release.

Ory Hydra is licensed under Apache License 2.0. Its upstream `LICENSE` file is
copied into the final container image next to the patched binary.
