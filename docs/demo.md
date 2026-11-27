# Public demo

The [Shauth product tour](https://e6qu.github.io/shauth/) is served by GitHub
Pages from `docs/index.html`. It explains the product and shows captures of the
real, publicly accessible sign-in and signed-out screens. It has no backend,
credentials, invented accounts, simulated authentication, or live monitoring
claims. Images are archival interface captures, not interactive forms.

## Publication

Configure GitHub Pages to deploy from a branch, with `/docs` as the source
folder. `docs/.nojekyll` serves the HTML and assets directly. All local asset
links are relative, so the page works under the `/shauth/` project path.

The initial publication uses the `ci/image-pin-freshness` branch so
the demo can be published without merging the pull request. After the pull
request is merged by the maintainer, change **Settings → Pages → Branch** to
`main`, keeping `/docs`. There is no separate generated publishing branch.

Only public documentation and the demo assets live in this directory. Never
put environment files, browser storage state, deployment exports, private
screenshots, or credentials under `docs/`.

## Shared appearance

The tour uses Shauth's existing CSS components, design tokens, favicon, and
theme control. Refresh their generated copies when the application changes:

```sh
node scripts/sync-pages-assets.mjs
node scripts/sync-pages-assets.mjs --check
```

`demo-assets/tour.css` adds the presentation layout. It does not replace the
application's theme colors or component definitions. No external fonts,
analytics, JavaScript CDN, or image service is loaded by the page.

## Interface captures

Use a real running Shauth deployment to refresh the screenshots:

```sh
SHAUTH_DEMO_URL=https://your-shauth-origin node scripts/capture-pages.mjs
```

The script opens fresh, unauthenticated browser contexts, verifies the expected
public page headings, checks that no username is filled in, and captures the
actual page card in both color schemes. It does not log in or change rendered
content. Capture time and dimensions are recorded in
`demo-assets/captures.json`; inspect the images before committing them.

## Verification

```sh
node scripts/sync-pages-assets.mjs --check
node scripts/test-pages.mjs
```

The browser check serves the real files under `/shauth/` and exercises theme
changes and persistence, interface selection, keyboard access, a browser with
JavaScript disabled, and light/dark layouts from 320 to 1440 pixels wide. It
rejects asset failures, horizontal overflow, browser errors, credential forms,
and requests to third-party services. It uses the repository's existing
Playwright dependency and runs in the **Public demo page** CI job.

For visual review, set `PAGES_SCREENSHOT_DIR` to an existing directory outside
the published documentation. The browser check saves desktop and mobile views
there. These checks verify the public tour; the full stack and live browser
validator remain the evidence for real authentication and logout behavior.
