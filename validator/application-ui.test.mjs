// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";

import { chromium } from "playwright";
import { applicationSignOutControl, assertApplicationIdentity } from "./application-ui.mjs";
import { waitForApplicationReady } from "./readiness.mjs";

test("application validation uses the real streaming launch UI and reveals its Shauth logout control", { timeout: 15_000 }, async () => {
  let logoutRequests = 0;
  const server = http.createServer((request, response) => {
    if (request.url === "/events") {
      response.writeHead(200, { "cache-control": "no-cache", "content-type": "text/event-stream" });
      response.flushHeaders();
      response.write("event: ready\ndata: connected\n\n");
      return;
    }
    if (request.url === "/logout" && request.method === "POST") {
      logoutRequests += 1;
      response.writeHead(303, { location: "/signed-out" });
      response.end();
      return;
    }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    if (request.url === "/signed-out") {
      response.end("<!doctype html><title>Signed out</title><main>Signed out</main>");
      return;
    }
    response.end(`<!doctype html><html lang="en"><title>Application</title><body><details><summary data-shauth-user="validator">validator</summary><form method="post" action="/logout"><button data-shauth-sign-out>Sign out</button></form></details><script>
      const events = new EventSource("/events");
      events.addEventListener("ready", () => { document.body.dataset.stream = "open"; });
    </script></body></html>`);
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  const origin = `http://127.0.0.1:${address.port}`;
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto(origin, { waitUntil: "domcontentloaded" });
    await waitForApplicationReady(page, origin, "streaming application was not ready", 2_000);
    await page.locator('body[data-stream="open"]').waitFor({ state: "visible", timeout: 2_000 });
    await assertApplicationIdentity(page, "validator", "streaming-app");
    const signOut = await applicationSignOutControl(page, "validator", "streaming-app");
    await signOut.click();
    await page.waitForURL(`${origin}/signed-out`);
    assert.equal(logoutRequests, 1);
  } finally {
    if (browser) await browser.close();
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("application identity marker must carry the exact Shauth username", { timeout: 15_000 }, async () => {
  const server = http.createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end('<!doctype html><summary data-shauth-user="someone-else">validator</summary>');
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${address.port}`);
    await assert.rejects(assertApplicationIdentity(page, "validator", "application"), /did not expose/);
  } finally {
    if (browser) await browser.close();
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
