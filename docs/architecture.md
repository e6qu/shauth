# Architecture

```
browser ──HTTPS──▶ Shauth ──▶ PostgreSQL (accounts, sessions, audit)
                     │
                     ├──▶ Ory Hydra admin API (private)
                     └──▶ Ory Hydra public API, served at Shauth's origin
                              └──▶ PostgreSQL (Hydra's own database)
```

Shauth is the only public entry point. It proxies Hydra's public OIDC
endpoints (`/.well-known/*`, `/oauth2/*`, `/userinfo`), so the issuer is
Shauth's public URL. Hydra's admin API is never published. Hydra asks Shauth
for every login, consent and logout decision, and calls Shauth's token hook
before it issues any token.

## Signing in

1. An application sends the browser to `/oauth2/auth` (authorization code flow
   with PKCE).
2. Hydra hands the login challenge to Shauth. If the browser already has a
   Shauth session, Shauth accepts the challenge without asking again; this is
   the single sign-on.
3. Otherwise the person signs in with GitHub, Entra ID or a local password.
4. Applications registered in Shauth's catalog are trusted and skip consent.
   Any other client gets a consent page that lists each requested permission
   in plain words. Denying it returns `access_denied`.

**Upstream providers**

- GitHub is the only GitHub OAuth callback (`/oauth/github/callback`). Each
  application has its own Shauth client, never a GitHub one.
- GitHub and Entra ID requests use PKCE (S256) and a state cookie. Entra ID
  also uses a nonce, and its ID token is verified for signature, issuer,
  audience, tenant and nonce.
- Cancelling at the provider returns the person to the sign-in page with
  their destination kept.
- An Entra ID identity links to an existing account by email only when both
  addresses are verified. Otherwise the sign-in is refused.

**Email verification:** `email_verified` in tokens and UserInfo always comes
from the stored identity.

- Local accounts are attested by an administrator.
- GitHub accounts use GitHub's primary verified address.
- Entra ID addresses count as verified only when the ID token carries a
  verified `email` claim.

**Passwords**

- Ten failures for one username, or fifty from one address, within fifteen
  minutes block further password attempts until those failures age out.
- Unknown, disabled and password-less accounts take as long to refuse as a
  wrong password, so timing does not reveal which usernames exist.

**Re-authentication:** Shauth honours `prompt=login` and `max_age`. Signing in
again replaces the browser's previous Shauth session. Signing in as a different
account also ends the previous account's application sessions.

## Access rules

There are two roles, `admin` and `developer`. A local account's role is set by
an administrator. A GitHub account's role comes from access rules, which are
evaluated at every GitHub sign-in:

- A rule matches a GitHub team, an organization, or one user.
- A user rule is bound to the account's numeric GitHub ID, so a renamed or
  re-registered login never matches it.
- Only accepted organization memberships count.
- An `admin` rule beats a `developer` rule.
- No matching rule means no access.

Rules change in three ways:

- When a sign-in finds an account no longer admitted, or no longer an
  administrator, its sessions and tokens are revoked.
- Deleting a rule revokes the sessions of every account it could have
  admitted. Each of those accounts is evaluated again at its next sign-in.
- `GITHUB_ADMIN_TEAM` and `GITHUB_DEVELOPER_TEAM` seed the first two rules.
  After that, rules are edited in the interface.

## Sessions and tokens

| Layer | Owner | Default lifetime |
|---|---|---|
| Shauth browser session | PostgreSQL | 30 days absolute, 12 hours idle |
| OIDC single sign-on session | Hydra | 30 days |
| Access token (JWT) | Hydra | 15 minutes |
| ID token | Hydra | 15 minutes |
| Refresh token | Hydra | 30 days |

Administrators change these on the session policy page or through the API.
Shauth applies the token lifetimes to every Hydra client.

**Token hook.** Before Hydra issues any token, refreshes included, it calls
`POST /internal/hydra/token-hook`. Shauth reads the account again. If Shauth
cannot answer, Hydra issues nothing.

- A disabled or deleted account gets no token.
- A token whose Shauth sign-in session has ended gets no token.
- New tokens carry the account's current role and email.
- Client-credentials tokens, which act for the client rather than a person,
  pass unchanged.

**JWT access tokens.** Relying parties verify access tokens against Hydra's
published keys without calling back. So an issued token stays valid until it
expires, even after a revocation. An application that must react sooner
listens for back-channel logout, which every revocation sends.

**GitHub roles.** A role that depends on GitHub membership is re-checked at the
next GitHub sign-in. Shauth does not keep the person's GitHub token.

## Logout

Every logout ends the Shauth browser session and every correlated application
session.

| Started by | Path |
|---|---|
| An application, with an ID token | Browser goes to `/oauth2/sessions/logout?id_token_hint=…&post_logout_redirect_uri=<the app's logout bridge>`. |
| An application whose own session already ended | Browser goes to `/logout?client_id=<client>`. Shauth asks for confirmation, then returns to that app's signed-out page. If no one is signed in, it returns straight away. |
| A person in Shauth | The sign-out button (a same-origin POST). |
| An administrator | Ending one session, all of an account's sessions, or disabling the account. |

In each case Shauth revokes the correlated Hydra login sessions by `sid`, and
Hydra notifies every application session that shared them:

- signed back-channel logout tokens, which Shauth's patch gives an `exp` claim;
- front-channel logout requests, where the client registered a front-channel
  URI.

Then Shauth deletes the remaining login and consent state, which revokes the
refresh tokens.

Application-initiated logout returns to the application through its logout
bridge (`/auth/shauth/logout/complete` on the app's origin). The bridge passes
back to Shauth's one-time `/oauth/logout/complete`, which redirects to the
app's registered signed-out page. A logout that cannot reach Hydra is recorded
and retried. `GET /api/v1/logout-grants` lists outstanding ones.

## One implementation per operation

Every administrative state change lives once, in
`internal/app/operations.go`. The browser handlers and the JSON API both parse
input, call that operation, and render its result. Validation, audit records
and safety rules therefore apply to both. For example, neither will let an
administrator disable their own account.

## Browser interface

- Pages are server-rendered with embedded HTMX 2.0.8, served from Shauth's
  origin with Subresource Integrity. There are no third-party asset hosts.
- Every form works without JavaScript and carries its CSRF token from the
  server.
- Every page supports light and dark themes and keyboard operation, and lays
  out from 320 px wide upwards.
- A form rejection marks the offending field and is announced to assistive
  technology.
- Every page footer shows the build revision and the time the deployment
  started.

## Pages

Every state-changing form posts to the URL shown in the right-hand column. All
forms carry a CSRF token.

| Page | Who | Form actions |
|---|---|---|
| `/` | Everyone | |
| `/login`, `/logout`, `/signed-out` | Everyone | `POST /login`, `POST /logout` |
| `/accept-invitation` | Invitees | `POST /accept-invitation` |
| `/account` | Signed in | `POST /account/sessions/{id}/revoke` |
| `/apps` | Signed in | `POST /apps/{id}/validate`. `/apps/{id}/validation` is the live status fragment. |
| `/admin` | Admins | |
| `/admin/users`, `/admin/users/{id}` | Admins | `POST /admin/users`, `/admin/users/{id}/disable`, `/admin/users/{id}/enable`, `/admin/users/{id}/sessions/revoke`. `/admin/users/{id}/sessions` redirects to the account page. |
| `/admin/sessions` | Admins | `POST /admin/sessions/{id}/revoke` |
| `/admin/invitations` | Admins | `POST /admin/invitations`, `/admin/invitations/{id}/revoke` |
| `/admin/clients` | Admins | `POST /admin/clients`, `/admin/clients/{id}/delete` |
| `/admin/apps`, `/admin/apps/{slug}` | Admins | `POST /admin/apps`, `/admin/apps/{id}/delete` |
| `/admin/github` | Admins | `POST /admin/github`, `/admin/github/{id}/delete` |
| `/admin/connectors` | Admins | |
| `/admin/session-policy` | Admins | `POST /admin/session-policy` |
| `/admin/audit`, `/admin/logs`, `/monitoring` | Admins | |

Hydra and the upstream providers use these:

| Route | Purpose |
|---|---|
| `/oauth/login`, `/oauth/consent`, `/oauth/logout`, `/oauth/error` | Hydra's login, consent, logout and error URLs. `POST /oauth/consent` records a consent decision. |
| `/oauth/logout/complete` | One-time return from an application's logout bridge. |
| `/oauth/github`, `/oauth/github/callback` | GitHub sign-in. |
| `/oauth/entra`, `/oauth/entra/callback` | Microsoft Entra ID sign-in. |
| `/validator/bootstrap` | Exchanges a validator bootstrap link for a browser session. |
