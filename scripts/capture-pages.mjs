// SPDX-License-Identifier: AGPL-3.0-or-later
import { chromium } from 'playwright';
import { writeFile } from 'node:fs/promises';

const origin = new URL(process.env.SHAUTH_DEMO_URL);
if (origin.protocol !== 'https:' || origin.username || origin.password) throw new Error('SHAUTH_DEMO_URL must be an HTTPS origin without credentials');
const browser = await chromium.launch({ headless: true, timeout: 20000 });
const captures = [];
try {
  for (const theme of ['light', 'dark']) {
    const context = await browser.newContext({ viewport: { width: 1280, height: 1000 }, colorScheme: theme, deviceScaleFactor: 1 });
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    for (const [screen, path, title] of [['signin', '/login', 'Sign in to Shauth'], ['signedout', '/signed-out', 'You are signed out']]) {
      const response = await page.goto(new URL(path, origin).href, { waitUntil: 'networkidle', timeout: 20000 });
      if (response.status() !== 200 || await page.locator('h1').innerText() !== title) throw new Error(`Unexpected public ${screen} screen`);
      if (await page.locator('input[name="username"]').count() && await page.locator('input[name="username"]').inputValue()) throw new Error('Capture contains a username');
      const card = page.locator('main > .card');
      await card.screenshot({ path: new URL(`../website/assets/${screen}-${theme}.png`, import.meta.url).pathname, animations: 'disabled' });
      const box = await card.boundingBox();
      captures.push({ file: `${screen}-${theme}.png`, width: Math.ceil(box.width), height: Math.ceil(box.height) });
    }
    await context.close();
  }
  await writeFile(new URL('../website/assets/captures.json', import.meta.url), `${JSON.stringify({ captured_at: new Date().toISOString(), kind: 'Public, unauthenticated Shauth pages; no altered content or seeded accounts.', captures }, null, 2)}\n`);
} finally { await browser.close(); }
console.log('Captured four real public interface views');
