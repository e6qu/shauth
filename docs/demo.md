# Public website and interactive demo

The [Shauth website](https://e6qu.github.io/shauth/) brings together the product
presentation, a clickable administration demo, component stories, and the
maintained documentation. Everything is a static file served by GitHub Pages.

| Path under `/shauth/` | Content |
|---|---|
| `/` | Product presentation and real public interface captures. |
| `/demo/` | Interactive UI with synthetic users, invitations, apps, and sessions. |
| `/storybook/` | Storybook with the shared UI components, states, and theme controls. |
| `/docs/` | Searchable documentation generated from this repository's Markdown. |
| `/openapi.json` | OpenAPI 3.1 contract for the implemented administration and internal APIs. |

## Try the demo

Start as Morgan Lee, a synthetic administrator. Open Atlas Docs and Orbit
Board to explore a shared session, then sign out from either sample application.
Both lose access until you start another demo session. You can also add users,
change sample roles, disable accounts, create and revoke invitations, end
sessions, and inspect the resulting audit record.

All changes stay in local storage in your browser. **Reset demo** restores the
original sample data. The demo never sends email, issues tokens, requests
credentials, or contacts a live Shauth service. Its session simulation explains
the product; the real integration tests remain the evidence for OIDC and logout
correctness. Synthetic data is confined to this explicitly requested public demo
and Storybook examples; it is not a production fallback or integration fixture.

## Build and verify

Use Node.js 24 and install the website tooling separately from the application's
browser-test dependencies:

```sh
npm ci
npm ci --prefix website
npx playwright install chromium
npm run build:pages
npm run test:pages
```

The build writes `.pages/` using an explicit public-file allowlist. It verifies
the shared assets and OpenAPI contract, renders documentation, and builds
Storybook. Website dependencies never enter the validator container image.
Serve `.pages/` with any static HTTP server. All navigation and assets work
under the GitHub Pages `/shauth/` project path.

The browser gate uses actual built files and exercises theme changes,
keyboard access, mobile layouts, demo mutations and persistence, shared-session
logout and reset, documentation search and links, and interactive Storybook
stories. It rejects unexpected browser errors and external demo requests.
Set `PAGES_SCREENSHOT_DIR` to an existing directory outside `.pages/` to save
screenshots for visual review.

## Publication

The **GitHub Pages** workflow builds and tests pull requests. It deploys only
from `main`, or from the branch named in the repository variable
`PAGES_DEPLOY_BRANCH` when that variable is set. Configure **Settings → Pages →
Source** to **GitHub Actions**. The initial publication uses
`ci/image-pin-freshness` through that variable, without merging the pull request.
After the maintainer merges, remove the variable to deploy from `main`.

Deployments upload only `.pages/`. Never add credentials, environment files,
browser storage state, deployment exports, or private captures to `website/`.
Documentation source links identify the exact built revision in CI.

## Shared appearance and component development

The website uses Shauth's existing CSS components, design tokens, icons,
favicon, and theme control. Refresh their generated copies when the application
changes:

```sh
node scripts/sync-pages-assets.mjs
node scripts/sync-pages-assets.mjs --check
npm run storybook
```

`website/components.js` supplies the demo and Storybook's common component
renderers. The website's additional CSS handles presentation, navigation, and
responsive layout. No external fonts, analytics, JavaScript CDN, or image
service is loaded by the presentation, demo, or documentation.

Storybook 10.6.9 ships a prebundled preview runtime of approximately 863 kB
minified (241 kB gzip), exceeding Vite's 500 kB advisory. Its upstream runtime
cannot be split further by this site's story configuration. The warning remains
visible; story modules are approximately 1–2 kB each. Reassess this upstream
bundle when upgrading Storybook. Node 26 additionally reports Storybook's
upstream `module.register()` deprecation; the website CI uses supported Node 24.

## Interface captures

Refresh the presentation's real screenshots from a running Shauth deployment:

```sh
SHAUTH_DEMO_URL=https://your-shauth-origin node scripts/capture-pages.mjs
```

The script opens fresh, unauthenticated browser contexts, verifies the expected
public headings and empty username, and captures the real sign-in and signed-out
cards in both color schemes. It never logs in or changes rendered content.
Capture dates and dimensions live in `website/assets/captures.json`; inspect the
images before committing them.

## API contract

The [OpenAPI document](../openapi.json) describes the explicit API and health
routes registered by the application. It keeps administration read/write,
validator, catalog, token-hook, reset, and browser-session credentials distinct.
It does not contain deployment addresses or secrets. Use the actual deployment's
origin when configuring a client, and OIDC discovery for standard provider
endpoints.

```sh
npm run test:openapi
```

Validation checks OpenAPI 3.1 structure, local references, exact registered route
coverage, unique operations, path parameters, credential boundaries, and secret
fields. Update the contract whenever a handler changes.
