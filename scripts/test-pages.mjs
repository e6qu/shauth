// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { chromium } from 'playwright';

const docs = new URL('../.pages/', import.meta.url);
const types = { html: 'text/html', css: 'text/css', js: 'application/javascript', png: 'image/png', svg: 'image/svg+xml', json: 'application/json' };
const server = createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  if (!pathname.startsWith('/shauth/')) { res.writeHead(404).end(); return; }
  const requested = pathname.slice('/shauth/'.length);
  const relative = requested.endsWith('/') || !requested ? `${requested}index.html` : requested;
  const url = new URL(relative, docs);
  if (!url.href.startsWith(docs.href)) { res.writeHead(403).end(); return; }
  try {
    const body = await readFile(url);
    res.writeHead(200, { 'Content-Type': types[relative.split('.').pop()] || 'text/plain' });
    res.end(body);
  } catch { res.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const deadline = setTimeout(() => { console.error('Pages browser checks exceeded 150 seconds'); process.exit(1); }, 150000);
const origin = `http://127.0.0.1:${server.address().port}`;
let browser;
try {
  browser = await chromium.launch({ headless: true, timeout: 20000 });
  const problems = [];
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, colorScheme: 'light' });
  page.setDefaultTimeout(10000);
  page.on('pageerror', error => problems.push(error.message));
  page.on('requestfailed', request => problems.push(`${request.url()}: ${request.failure()?.errorText}`));
  page.on('response', response => { if (response.status() >= 400) problems.push(`${response.status()} ${response.url()}`); });
  page.on('request', request => assert.equal(new URL(request.url()).origin, origin, 'The tour must not contact an identity provider or third-party asset host'));
  await page.goto(`${origin}/shauth/`, { waitUntil: 'networkidle' });
  assert.equal(await page.locator('h1').count(), 1);
  assert.equal(await page.locator('form, input, iframe').count(), 0, 'The static tour must not collect credentials or embed live administration');
  await page.keyboard.press('Tab');
  assert.equal(await page.locator(':focus').innerText(), 'Skip to content');
  await page.keyboard.press('Enter');
  assert.equal(new URL(page.url()).hash, '#main-content');
  await page.getByRole('button', { name: 'Signed-out screen', exact: true }).focus();
  await page.keyboard.press('Enter');
  await page.locator('#screen-image[src$="signedout-light.png"]').waitFor();
  await page.locator('#screen-image').evaluate(image => image.decode());
  assert.equal(await page.getByRole('button', { name: 'Signed-out screen', exact: true }).getAttribute('aria-pressed'), 'true');
  assert.match(await page.locator('#screen-caption').innerText(), /A clear place to finish/);
  await page.locator('#theme-toggle').click(); // system -> light
  await page.locator('#theme-toggle').click(); // light -> dark
  await page.locator('#screen-image[src$="signedout-dark.png"]').waitFor();
  await page.locator('#screen-image').evaluate(image => image.decode());
  await page.reload({ waitUntil: 'networkidle' });
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
  await page.locator('#screen-image[src$="signin-dark.png"]').waitFor();
  await page.locator('#screen-image').evaluate(image => image.decode());
  await page.locator('#theme-toggle').click(); // dark -> system
  await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' });
  await page.locator('#screen-image[src$="signin-light.png"]').waitFor();
  await page.locator('#screen-image').evaluate(image => image.decode());
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.locator('#screen-image[src$="signin-dark.png"]').waitFor();
  await page.locator('#screen-image').evaluate(image => image.decode());

  for (const theme of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme: theme });
    await page.locator('#screen-image').evaluate(image => image.decode());
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 1000 });
      for (const screen of ['Sign-in screen', 'Signed-out screen']) {
        await page.getByRole('button', { name: screen, exact: true }).click();
        await page.locator('#screen-image').evaluate(image => image.decode());
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Horizontal overflow: ${width}px ${theme} ${screen}`);
      }
    }
  }
  if (process.env.PAGES_SCREENSHOT_DIR) {
    await page.getByRole('button', { name: 'Sign-in screen', exact: true }).click();
    for (const theme of ['light', 'dark']) {
      await page.emulateMedia({ colorScheme: theme });
      await page.locator('#screen-image').evaluate(image => image.decode());
      await page.screenshot({ path: `${process.env.PAGES_SCREENSHOT_DIR}/pages-${theme}.png`, fullPage: true });
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: `${process.env.PAGES_SCREENSHOT_DIR}/pages-mobile.png`, fullPage: true });
  }
  await checkDemo(page, origin);
  await checkDocs(page, origin);
  await checkStorybook(page, origin);
  const specification = await (await page.request.get(`${origin}/shauth/openapi.json`)).json();
  assert.equal(specification.openapi, '3.1.0');
  assert.ok(Object.keys(specification.paths).length >= 40);
  const withoutJS = await browser.newPage({ javaScriptEnabled: false, colorScheme: 'dark' });
  await withoutJS.goto(`${origin}/shauth/`, { waitUntil: 'networkidle' });
  assert.equal(await withoutJS.locator('.tour-screen-controls').isVisible(), false);
  assert.match(await withoutJS.locator('#screen-image').evaluate(image => image.currentSrc), /signin-dark\.png$/);
  assert.ok(await withoutJS.locator('a[href="docs/integrating-apps.html"]').count() > 0);
  assert.deepEqual(problems, []);
  console.log('Pages: presentation, demo mutations/persistence/logout/reset, docs/search/links, Storybook interactions, OpenAPI, keyboard, themes, no-JS, and responsive project-subpath checks passed');
} finally {
  clearTimeout(deadline);
  if (browser) await browser.close();
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}

async function snapshot(page, name) {
  if (process.env.PAGES_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.PAGES_SCREENSHOT_DIR}/${name}.png`, fullPage: true });
}
async function fit(page, label) {
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Horizontal overflow: ${label}`);
}
async function checkDemo(page, origin) {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto(`${origin}/shauth/demo/`, { waitUntil: 'networkidle' });
  await page.getByRole('heading', { name: 'Apps', exact: true }).waitFor();
  const nav = page.getByRole('navigation', { name: 'Demo administration' });
  const modal = page.getByRole('dialog');
  const saved = () => page.evaluate(() => JSON.parse(localStorage.getItem('shauth-public-demo-v1')));
  await snapshot(page, 'demo-apps');
  await nav.getByRole('link', { name: 'Users', exact: true }).click();
  await page.getByRole('button', { name: 'Add demo user', exact: true }).click();
  await modal.getByLabel('Name', { exact: true }).fill('Taylor Demo');
  await modal.getByLabel('Username', { exact: true }).fill('taylor');
  await modal.getByLabel('Email', { exact: true }).fill('taylor@example.test');
  await modal.getByRole('button', { name: 'Add user', exact: true }).click();
  await page.getByText('Taylor Demo', { exact: true }).waitFor();
  await page.reload({ waitUntil: 'networkidle' });
  assert.equal((await saved()).users.filter(u => u.username === 'taylor').length, 1);
  await page.getByLabel('Find a user').fill('Taylor');
  assert.equal(await page.locator('tbody tr').count(), 1);
  await page.getByLabel('Role for Taylor Demo').selectOption('admin');
  assert.equal((await saved()).users.find(u => u.username === 'taylor').role, 'admin');
  await page.getByLabel('Find a user').fill('not-present');
  await page.getByRole('heading', { name: 'No users match' }).waitFor();
  await page.getByLabel('Find a user').fill('');
  await page.getByRole('button', { name: 'Disable Sam Rivera', exact: true }).click();
  await modal.getByRole('button', { name: 'Disable user', exact: true }).click();
  assert.equal((await saved()).sessions.find(s => s.userId === 'sam').active, false);
  await page.getByRole('button', { name: 'Enable Sam Rivera', exact: true }).click();
  await modal.getByRole('button', { name: 'Enable user', exact: true }).click();
  assert.equal((await saved()).sessions.find(s => s.userId === 'sam').active, false, 'Enabling must not revive an ended session');
  await snapshot(page, 'demo-users');
  await nav.getByRole('link', { name: 'Invitations', exact: true }).click();
  await page.getByRole('button', { name: 'Create invitation', exact: true }).click();
  await modal.getByLabel('Email', { exact: true }).fill('casey@example.test');
  await modal.getByRole('button', { name: 'Create invitation', exact: true }).click();
  await page.getByRole('button', { name: 'Revoke invitation for casey@example.test', exact: true }).click();
  await modal.getByRole('button', { name: 'Revoke invitation', exact: true }).click();
  assert.equal((await saved()).invitations.find(i => i.email === 'casey@example.test').status, 'revoked');
  await nav.getByRole('link', { name: 'Sessions', exact: true }).click();
  await page.getByRole('button', { name: 'End session for Alex Chen in Safari · macOS', exact: true }).click();
  await modal.getByRole('button', { name: 'End session', exact: true }).click();
  assert.equal((await saved()).sessions.find(s => s.userId === 'alex').active, false);
  await nav.getByRole('link', { name: 'Apps', exact: true }).click();
  await page.locator('[data-action="open-app"][data-id="atlas"]').click();
  await page.getByRole('heading', { name: 'Signed in as Morgan Lee' }).waitFor();
  await page.getByRole('link', { name: 'Open another app' }).click();
  await page.locator('[data-action="open-app"][data-id="orbit"]').click();
  assert.deepEqual((await saved()).sessions.find(s => s.id === 'this-browser').apps, ['atlas', 'orbit']);
  await page.getByRole('button', { name: 'Sign out of all apps', exact: true }).click();
  await modal.getByRole('button', { name: 'Sign out of all apps', exact: true }).click();
  await page.getByRole('heading', { name: 'You are signed out' }).waitFor();
  await page.goto(`${origin}/shauth/demo/#/app/atlas`);
  await page.getByRole('heading', { name: 'You are signed out' }).waitFor();
  assert.deepEqual((await saved()).sessions.find(s => s.id === 'this-browser').apps, []);
  await page.getByRole('button', { name: 'Start a new demo session' }).click();
  await page.getByRole('heading', { name: 'Apps', exact: true }).waitFor();
  assert.ok((await saved()).users.some(u => u.username === 'taylor'));
  await nav.getByRole('link', { name: 'Audit record', exact: true }).click();
  await page.getByText('Global logout', { exact: true }).waitFor();
  for (const theme of ['light', 'dark']) {
    await page.evaluate(value => { document.documentElement.dataset.theme = value; localStorage.setItem('shauth-theme', value); }, theme);
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 1000 });
      for (const name of ['Apps', 'Users', 'Invitations', 'Sessions', 'Audit record']) {
        await nav.getByRole('link', { name, exact: true }).click();
        await fit(page, `demo ${name} ${width} ${theme}`);
      }
    }
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await nav.getByRole('link', { name: 'Users', exact: true }).click();
  await snapshot(page, 'demo-mobile');
  await page.getByRole('button', { name: 'Reset demo', exact: true }).click();
  await modal.getByRole('button', { name: 'Cancel', exact: true }).click();
  assert.ok((await saved()).users.some(u => u.username === 'taylor'));
  await page.getByRole('button', { name: 'Reset demo', exact: true }).click();
  await modal.getByRole('button', { name: 'Reset demo', exact: true }).click();
  assert.equal((await saved()).users.length, 4);
  assert.equal((await saved()).sessions.filter(s => s.active).length, 3);
  await page.evaluate(() => localStorage.setItem('shauth-public-demo-v1', '{broken'));
  await page.reload({ waitUntil: 'networkidle' });
  await page.getByRole('heading', { name: 'Reset saved demo data' }).waitFor();
  await page.getByRole('button', { name: 'Reset demo data', exact: true }).click();
  await modal.getByRole('button', { name: 'Reset demo', exact: true }).click();
  await page.getByRole('heading', { name: 'Apps', exact: true }).waitFor();
}

async function checkDocs(page, origin) {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto(`${origin}/shauth/docs/`, { waitUntil: 'networkidle' });
  const search = page.getByRole('searchbox', { name: 'Search documentation' });
  await search.fill('logout');
  await page.locator('#docs-search-results a').first().waitFor();
  await search.press('ArrowDown');
  assert.ok(await page.locator('#docs-search-results a:focus').count());
  await page.keyboard.press('Enter');
  await page.waitForURL(/\.html#/);
  await snapshot(page, 'docs-desktop');
  const links = new Set();
  const documents = await page.getByRole('navigation', { name: 'Documentation pages' }).locator('a').evaluateAll(nodes => nodes.map(n => n.href).filter(h => h.endsWith('.html')));
  for (const url of documents) {
    await page.goto(url, { waitUntil: 'networkidle' });
    assert.equal(await page.locator('h1').count(), 1);
    for (const link of await page.locator('a').evaluateAll(nodes => nodes.map(n => n.href))) if (link.startsWith(`${origin}/shauth/`)) links.add(link);
    for (const theme of ['light', 'dark']) {
      await page.evaluate(value => document.documentElement.dataset.theme = value, theme);
      await page.setViewportSize({ width: 375, height: 844 });
      await fit(page, `docs ${url} ${theme}`);
    }
  }
  for (const link of links) {
    const response = await page.request.get(link);
    assert.equal(response.status(), 200, `Documentation link: ${link}`);
    const anchor = new URL(link).hash.slice(1);
    if (anchor) assert.ok((await response.text()).includes(`id="${decodeURIComponent(anchor)}"`), `Missing anchor: ${link}`);
  }
  await snapshot(page, 'docs-mobile');
}

async function checkStorybook(page, origin) {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto(`${origin}/shauth/storybook/?path=/story/components-button--primary`, { waitUntil: 'networkidle' });
  const preview = page.frameLocator('#storybook-preview-iframe');
  await preview.getByRole('button', { name: 'Add user', exact: true }).click();
  await preview.getByText('Button activated 1 time.', { exact: true }).waitFor();
  await snapshot(page, 'storybook-desktop');
  await page.goto(`${origin}/shauth/storybook/iframe.html?id=components-form-fields--invitation&viewMode=story&globals=theme:dark`, { waitUntil: 'networkidle' });
  await page.getByLabel('Email address').fill('story@example.test');
  await page.getByLabel('Role', { exact: true }).selectOption('admin');
  await page.getByRole('button', { name: 'Preview invitation' }).click();
  await page.getByText('Demo invitation: story@example.test as admin. No email was sent.', { exact: true }).waitFor();
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
  assert.equal(await page.getByRole('link', { name: 'Demo', exact: true }).getAttribute('href'), '../demo/');
  await page.setViewportSize({ width: 375, height: 844 });
  await fit(page, 'Storybook invitation mobile');
  await snapshot(page, 'storybook-mobile');
}
