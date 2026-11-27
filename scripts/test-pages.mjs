// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { chromium } from 'playwright';

const docs = new URL('../docs/', import.meta.url);
const types = { html: 'text/html', css: 'text/css', js: 'application/javascript', png: 'image/png', svg: 'image/svg+xml', json: 'application/json' };
const server = createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  if (!pathname.startsWith('/shauth/')) { res.writeHead(404).end(); return; }
  const relative = pathname.slice('/shauth/'.length) || 'index.html';
  const url = new URL(relative, docs);
  if (!url.href.startsWith(docs.href)) { res.writeHead(403).end(); return; }
  try {
    const body = await readFile(url);
    res.writeHead(200, { 'Content-Type': types[relative.split('.').pop()] || 'text/plain' });
    res.end(body);
  } catch { res.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
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
  assert.equal(await page.getByRole('button', { name: 'Signed-out screen', exact: true }).getAttribute('aria-pressed'), 'true');
  assert.match(await page.locator('#screen-caption').innerText(), /A clear place to finish/);
  await page.locator('#theme-toggle').click(); // system -> light
  await page.locator('#theme-toggle').click(); // light -> dark
  await page.locator('#screen-image[src$="signedout-dark.png"]').waitFor();
  await page.reload({ waitUntil: 'networkidle' });
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
  await page.locator('#screen-image[src$="signin-dark.png"]').waitFor();
  await page.locator('#theme-toggle').click(); // dark -> system
  await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' });
  await page.locator('#screen-image[src$="signin-light.png"]').waitFor();
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.locator('#screen-image[src$="signin-dark.png"]').waitFor();

  for (const theme of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme: theme });
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
  const withoutJS = await browser.newPage({ javaScriptEnabled: false, colorScheme: 'dark' });
  await withoutJS.goto(`${origin}/shauth/`, { waitUntil: 'networkidle' });
  assert.equal(await withoutJS.locator('.tour-screen-controls').isVisible(), false);
  assert.match(await withoutJS.locator('#screen-image').evaluate(image => image.currentSrc), /signin-dark\.png$/);
  assert.ok(await withoutJS.locator('a[href$="/docs/integrating-apps.md"]').count() > 0);
  assert.deepEqual(problems, []);
  console.log('Pages: theme, screenshot controls, keyboard navigation, no-JS, project subpath, and 16 responsive views passed');
} finally {
  if (browser) await browser.close();
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
