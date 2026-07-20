# Ory Hydra v26.2.0 provider patch

Shauth uses Ory Hydra v26.2.0 commit
`0b84568fffccf151dc5e6c7955fdfb738555bf4b`. The container build downloads
that exact source archive and verifies SHA-256
`7ceaae3299780959e8390925732629931f63f20300464d2822d49628eeb3332e`
before applying `logout-token-exp.patch`.

The patch adds the required `exp` claim to every OpenID Connect Back-Channel
Logout Token, with a two-minute lifetime from `iat`. It is the minimal portion
of the upstream fix proposed in
<https://github.com/ory/hydra/pull/4073>, adapted to the released v26.2.0
source. Shauth can remove the patch after an official Hydra release includes
the standards fix and passes the repository's multi-relying-party logout test.

Ory Hydra is licensed under Apache License 2.0. Its upstream `LICENSE` file is
copied into the final container image next to the patched binary.
