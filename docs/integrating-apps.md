# Integrating an application

An application, or relying party, signs people in through Shauth with standard
OIDC. To appear in Shauth's app catalog it must also publish a few pages that
let Shauth prove sign-in and global logout work.

Every coordinate below must use the application's own origin (one scheme, host
and port). Use HTTPS in production.

## 1. Register an OIDC client

Register it under **Admin → OAuth clients**, through `POST /internal/oidc-clients`,
or with `SHAUTH_BOOTSTRAP_APPS_JSON`.

| Field | Value |
|---|---|
| `client_id`, `client_secret` | A confidential client. The secret is write-only: Shauth never shows it again. Store the same value in the application's own secret store. |
| `redirect_uris` | Exact callback URLs. |
| `post_logout_redirect_uris` | For a catalog app, exactly one value: `https://<app>/auth/shauth/logout/complete`. |
| `frontchannel_logout_uri` and/or `backchannel_logout_uri` | At least one. Back-channel is preferred. |

The application then:

- discovers the issuer from `https://<shauth>/.well-known/openid-configuration`;
- uses the authorization code flow with PKCE and the default `query` response
  mode (`form_post` is not offered, because Shauth's content policy forbids the
  page it needs);
- validates the issuer, audience, signature, expiry and nonce of each ID token;
- verifies access tokens, which are JWTs, against the published keys;
- keeps the ID token's `sid` so a logout notification can end the right local
  sessions.

Claims: `sub`, `preferred_username`, `email`, `email_verified`, `role`
(`admin` or `developer`).

## 2. Handle logout

**Signing out.** Clear the local session, then send the browser to:

```
https://<shauth>/oauth2/sessions/logout
    ?id_token_hint=<id token>
    &post_logout_redirect_uri=https://<app>/auth/shauth/logout/complete
```

Use a navigation, not a cross-origin POST. If the local session has already
expired and there is no ID token, send the browser to
`https://<shauth>/logout?client_id=<client>` instead.

**Logout bridge.** `GET /auth/shauth/logout/complete` on the app redirects to
`https://<shauth>/oauth/logout/complete`, keeping the query string. Shauth then
redirects once to the app's `signed_out_url`.

**Notifications**

- On a signed back-channel logout token, validate it (including `exp`, and
  reject replays), then end every local session with that `sid`.
- On a front-channel request, check `iss` and `sid` and do the same.
- Both must be idempotent.

## 3. Register the app in the catalog

Register it under **Admin → Apps** or through `POST /internal/apps`. The OIDC
client must already exist.

| Field | Requirement |
|---|---|
| `slug`, `name`, `description` | Display and addressing. |
| `oidc_client_id` | The client from step 1. |
| `launch_url` | The normal signed-in UI. It must show the user as `data-shauth-user="<username>"` and offer a real logout control marked `data-shauth-sign-out`. |
| `health_url` | Answers 2xx while the application can serve requests. Shauth polls it. |
| `validation_url` | An authenticated page showing `data-testid` fields `validation-username`, `validation-email`, `validation-role` and `validation-release`. |
| `signed_out_url` | A page that survives reloads and offers an accessible **Sign in with Shauth** control. |
| `release_revision` | The deployed commit (12–64 lowercase hex characters) or a `sha256:` digest. Moving labels such as `main` are rejected. |
| `monitoring_url` | Optional. An [observation source](operations.md#monitoring-sources), read server-side with `monitoring_token`. |

The [gateway](gateway.md) implements all of these pages for an application
behind it.

## 4. Browser validation

Shauth queues two real Chromium checks when an app is registered and whenever
its release, coordinates or OIDC client change:

- **catalog:** enters through Shauth's Apps page;
- **direct:** enters through the app's `launch_url`.

Each check, in order:

1. Signs in and confirms the identity on the app's pages.
2. Opens a second application, the *witness*, through silent SSO.
3. Signs out from the app and checks that both applications and Shauth are
   signed out and that the browser lands on `signed_out_url`.
4. Probes the logout bridge with hostile and replayed requests.
5. Signs in again and signs out from Shauth.
6. Checks that the account can still sign in afterwards.

A deployment without a second registered app on a different origin always
reports red, because global logout cannot be proven with one application.

Results are 🟢 Passed, 🔴 Failed or 🟡 Ongoing, per direction, on the Apps and
admin pages and through the [API](api.md#applications). Any signed-in user can
re-run them.

**Queue limits**

- At most three checks run at once.
- An app is never a target and a witness at the same time.
- A repeated request joins the run already queued or running.

**The validator's identity**

- It signs in as a dedicated, non-administrative account with no password and
  no federated login.
- It uses its bearer token (`SHAUTH_VALIDATOR_TOKEN`) to mint single-use,
  short-lived browser bootstrap links. Shauth stores only their hashes.
- Neither credential is ever sent to an application.

## Bootstrap configuration

`SHAUTH_BOOTSTRAP_APPS_JSON` registers clients and catalog entries at start-up.
It is idempotent, and it never takes over a slug or client that an
administrator created. It is a JSON array of the fields above plus the client
fields:

```json
[{
  "slug": "example-app",
  "name": "Example app",
  "description": "What the application is for.",
  "oidc_client_id": "example-app",
  "oidc_client_secret": "<at least 32 characters>",
  "redirect_uris": ["https://app.example.com/auth/callback"],
  "post_logout_redirect_uris": ["https://app.example.com/auth/shauth/logout/complete"],
  "backchannel_logout_uri": "https://app.example.com/auth/backchannel-logout",
  "launch_url": "https://app.example.com/",
  "health_url": "https://app.example.com/auth/healthz",
  "validation_url": "https://app.example.com/auth/validation",
  "signed_out_url": "https://app.example.com/auth/signed-out",
  "release_revision": "0123456789ab"
}]
```

Shauth refuses to start if an entry breaks any of the rules above, or if the
stored client no longer matches it.
