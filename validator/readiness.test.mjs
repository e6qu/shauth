// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";

import { chromium } from "playwright";
import { waitForApplicationReady } from "./readiness.mjs";

test("application readiness accepts a rendered page with an active Server-Sent Events stream", { timeout: 15_000 }, async () => {
  let activeStreams = 0;
  const server = http.createServer((request, response) => {
    if (request.url === "/events") {
      activeStreams += 1;
      response.writeHead(200, {
        "cache-control": "no-cache",
        "content-type": "text/event-stream",
      });
      response.flushHeaders();
      response.write("event: ready\ndata: connected\n\n");
      request.once("close", () => { activeStreams -= 1; });
      return;
    }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(`<!doctype html><html lang="en"><body><main>Streaming application</main><script>
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
    assert.equal(activeStreams, 1);
  } finally {
    if (browser) await browser.close();
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("application readiness refuses an error document on the application's origin", { timeout: 15_000 }, async () => {
  const server = http.createServer((_request, response) => {
    response.writeHead(429, { "content-type": "text/html; charset=utf-8", "retry-after": "3" });
    response.end("<!doctype html><title>Too many requests</title><body><main>Too many requests</main></body>");
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
    await page.goto(`${origin}/callback`, { waitUntil: "domcontentloaded" });
    await assert.rejects(
      waitForApplicationReady(page, origin, "application was not ready", 2_000),
      { message: `application was not ready; application answered HTTP 429 at ${origin}/callback` },
    );
  } finally {
    if (browser) await browser.close();
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
