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

Drop each patch, and the module pins, once a Hydra release includes the fix
and `./scripts/test-stack.sh` passes without it.

Ory Hydra is Apache-2.0. Its `LICENSE` is copied into the image at
`/licenses/hydra/LICENSE`.
