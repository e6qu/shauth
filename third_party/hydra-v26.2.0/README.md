# Ory Hydra v26.2.0 patches

The image builds Ory Hydra from commit
`0b84568fffccf151dc5e6c7955fdfb738555bf4b`. The source archive is checked
against SHA-256
`7ceaae3299780959e8390925732629931f63f20300464d2822d49628eeb3332e`, then these
patches are applied:

| Patch | Change | Upstream |
|---|---|---|
| `logout-token-exp.patch` | Adds the `exp` claim, two minutes after `iat`, to back-channel logout tokens, as Back-Channel Logout 1.0 Errata 1 requires. | [ory/hydra#4073](https://github.com/ory/hydra/pull/4073) |
| `no-sentinel-error-log.patch` | Stops logging an error each time the login or consent redirect aborts an authorization request. That redirect is normal control flow, not an error. | The handler half of commit `917d39a74a09`. |

The `Dockerfile` also pins patched versions of vulnerable transitive Go
modules before it compiles Hydra.

Two legacy dependencies have no fixed release on their existing major version.
After resolving the module graph, the build vendors it and applies these
backports without changing module identities:

| Patch | Change | Upstream evidence |
|---|---|---|
| `go-jose-v3-security.patch` | Bounds RSA modulus size and prime consistency before validation; rejects private parameters in JWS/JWE headers; initializes general JWS unprotected headers before sanitizing. | [GHSA-mgcc-cww5-fp2q](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q), adapted from [a0111f8](https://github.com/go-jose/go-jose/commit/a0111f82742fa92bceec9ede40845e73319e6230). |
| `pgproto3-v2-security.patch` | Rejects negative, non-null DataRow field lengths before slicing. | [jackc/pgx#2507](https://github.com/jackc/pgx/issues/2507); v2 is end-of-life, while v5 already contains the guard. |

Both patches include regression tests that fail against the original modules.
The image build runs them against the vendored code before linking Hydra.
Dependency scanners still see the original module versions, so their advisory
findings require this patch evidence; do not globally ignore the advisories.
The JOSE backport limits parsed RSA keys to 4096 bits, matching upstream's fix.
Migrate to maintained dependency majors when Hydra supports them, then remove
these backports only after the full real integration suite passes.

Drop each patch, and the module pins, once a Hydra release includes the fix
and `./scripts/test-stack.sh` passes without it.

Ory Hydra is Apache-2.0. Its `LICENSE` is copied into the image at
`/licenses/hydra/LICENSE`.
