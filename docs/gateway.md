# Relying-party gateway

`/shauth-gateway` puts an application that has no OIDC client of its own behind
Shauth. It is a first-party OIDC relying party, not a generic authentication
proxy. It signs people in with Shauth, keeps its sessions in its own PostgreSQL
database, and forwards authenticated requests to the application with the
verified identity in headers.

## What it does

- Discovers the issuer and runs the authorization code flow with PKCE. It
  verifies each ID token's signature, issuer, audience, expiry, nonce, subject
  and `sid`.
- Stores opaque sessions in PostgreSQL. Applying its own migrations is the
  first thing it does at start-up, and it refuses to start if it cannot.
- Proxies every other request to `OIDC_GATEWAY_UPSTREAM_URL` and adds these
  headers:
  - `X-Forwarded-Subject`
  - `X-Forwarded-User`
  - `X-Forwarded-Preferred-Username`
  - `X-Forwarded-Email`
  - `X-Forwarded-Role`
- Removes any client-supplied copy of those headers, in any spelling, and the
  inbound `Authorization` header.
- Leaves the upstream application's own Content Security Policy and
  `X-Frame-Options` in place. Gateway-owned `/auth/` pages deny framing,
  except the front-channel logout page, which only the issuer may frame.

## Routes

| Route | Purpose |
|---|---|
| `GET /auth/login` | Start sign-in. |
| `GET /auth/callback` | OIDC redirect URI. |
| `GET /auth/session` | The signed-in user as JSON, for the application's UI. |
| `POST /auth/logout` | Global logout through Shauth. |
| `GET /auth/shauth/logout/complete` | Logout bridge (the client's only post-logout redirect URI). |
| `GET /auth/signed-out` | Signed-out page, with **Sign in with Shauth**. |
| `GET /auth/validation` | Validation page for Shauth's browser checks. Anonymous visitors are sent to `/auth/signed-out`. |
| `GET /auth/frontchannel-logout` | Front-channel logout URI. |
| `POST /auth/backchannel-logout` | Back-channel logout URI. Rejects replayed tokens. |
| `GET /auth/healthz` | `200` while the session store is reachable, `503` otherwise. |

Health is tied to the session store because without it the gateway can neither
admit nor refuse anyone. A load balancer using this URL therefore drains the
gateway during a database outage, which fails closed.

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `OIDC_GATEWAY_ISSUER` | yes | Shauth's public URL. |
| `OIDC_GATEWAY_PUBLIC_URL` | yes | The application's public origin, with no path. |
| `OIDC_GATEWAY_UPSTREAM_URL` | yes | Where authenticated requests go. |
| `OIDC_GATEWAY_POST_LOGOUT_URL` | yes | Exactly `<public URL>/auth/shauth/logout/complete`. |
| `OIDC_GATEWAY_CLIENT_ID`, `OIDC_GATEWAY_CLIENT_SECRET` | yes | The application's Shauth client. The secret must be at least 32 characters. |
| `OIDC_GATEWAY_COOKIE_SECRET` | yes | At least 32 characters. |
| `DATABASE_URL` | yes | The gateway's own database. Never Shauth's. |
| `APPLICATION_RELEASE_REVISION` | yes | Immutable commit or `sha256:` digest, shown on the validation page. |
| `OIDC_GATEWAY_LISTEN_ADDRESS` | no | Default `:4180`. |
| `OIDC_GATEWAY_SESSION_MAX_AGE` | no | `5m` to `720h`. Default `8h`. |
| `OIDC_GATEWAY_ALLOW_INSECURE_COOKIE` | no | `true` allows plain HTTP, and only for loopback URLs. |

Register the client as described in
[Integrating an application](integrating-apps.md). For a gateway app, use these
values:

| Client field | Value |
|---|---|
| Redirect URI | `<public URL>/auth/callback` |
| Back-channel logout URI | `<public URL>/auth/backchannel-logout` |
| Front-channel logout URI | `<public URL>/auth/frontchannel-logout` |

| Catalog field | Value |
|---|---|
| `health_url` | `<public URL>/auth/healthz` |
| `validation_url` | `<public URL>/auth/validation` |
| `signed_out_url` | `<public URL>/auth/signed-out` |

The application's own UI must still expose `data-shauth-user` and
`data-shauth-sign-out` on its launch page. `/auth/session` provides the user
and `POST /auth/logout` signs out.
