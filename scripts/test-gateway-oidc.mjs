// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import http from "node:http";
import { chromium } from "playwright";

const password = process.env.SHAUTH_BOOTSTRAP_ADMIN_PASSWORD;
assert.ok(password, "SHAUTH_BOOTSTRAP_ADMIN_PASSWORD is required");

let resolveIdentity;
const identity = new Promise((resolve) => { resolveIdentity = resolve; });
const upstream = http.createServer((request, response) => {
  resolveIdentity({
    subject: request.headers["x-forwarded-subject"],
    username: request.headers["x-forwarded-preferred-username"],
    email: request.headers["x-forwarded-email"],
    role: request.headers["x-forwarded-role"],
    authorization: request.headers.authorization,
  });
  response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  response.end("<!doctype html><html lang=en><title>Protected application</title><h1>Protected application</h1><form method=post action=/auth/logout><button>Sign out</button></form></html>");
});
await new Promise((resolve, reject) => {
  upstream.once("error", reject);
  upstream.listen(5557, "127.0.0.1", resolve);
});

const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  const browserErrors = [];
  const navigationTrace = [];
  page.on("request", (request) => {
    if (request.isNavigationRequest()) navigationTrace.push(`request ${request.method()} ${sanitizeURL(request.url())}`);
  });
  page.on("response", (response) => {
    if (response.request().isNavigationRequest()) navigationTrace.push(`response ${response.status()} ${sanitizeURL(response.url())}`);
  });
  page.on("console", (message) => {
    if (message.type() === "error") browserErrors.push(message.text());
  });
  page.on("pageerror", (error) => browserErrors.push(error.message));
  page.on("requestfailed", (request) => browserErrors.push(`${request.url()}: ${request.failure()?.errorText ?? "request failed"}`));

  await page.goto("http://localhost:5556/");
  await page.locator("#username").fill("admin");
  await page.locator("#password").fill(password);
  await page.getByRole("button", { name: "Sign in with password" }).click();
  await page.waitForURL("http://localhost:5556/");
  await assertSession(context, 200);

  const sessionResponse = await context.request.get("http://localhost:5556/auth/session");
  const session = await sessionResponse.json();
  const protectedResponse = await context.request.get("http://localhost:5556/");
  assert.match(protectedResponse.headers()["content-security-policy"], /form-action 'self' http:\/\/localhost:8080/);
  assert.deepEqual(await identity, {
    subject: session.subject,
    username: "admin",
    email: "admin@localhost.test",
    role: "admin",
    authorization: undefined,
  });
  await page.getByRole("button", { name: "Sign out" }).click();
  await waitForURL(page, "http://localhost:5556/auth/signed-out", navigationTrace, browserErrors);
  await page.getByRole("heading", { name: "Signed out" }).waitFor();
  await assertSession(context, 401);
  await page.goto("http://localhost:8080/apps");
  await page.waitForURL((url) => url.origin === "http://localhost:8080" && url.pathname === "/login");
  assert.deepEqual(browserErrors, []);
} finally {
  await browser.close();
  await new Promise((resolve) => upstream.close(resolve));
}

async function waitForURL(page, expected, trace, errors) {
  const deadline = Date.now() + 30_000;
  while (page.url() !== expected && Date.now() < deadline) {
    await page.waitForTimeout(100);
  }
  assert.equal(page.url(), expected, [...trace, ...errors.map((error) => `browser error ${error}`)].join("\n"));
}

function sanitizeURL(value) {
  const parsed = new URL(value);
  return `${parsed.origin}${parsed.pathname}`;
}

async function assertSession(context, expectedStatus) {
  const response = await context.request.get("http://localhost:5556/auth/session");
  assert.equal(response.status(), expectedStatus);
  if (expectedStatus === 200) {
    const session = await response.json();
    assert.deepEqual(session, {
      subject: session.subject,
      username: "admin",
      email: "admin@localhost.test",
      role: "admin",
    });
  }
}
