// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";

import { chromium } from "playwright";
import { boundedFailureWithLatestTrace, credentialRequestViolation, installCredentialBoundary, redactCredentialMaterial } from "./security.mjs";

const username = "ordinary-user";
const password = "ordinary-user-secret";
const csrf = "a".repeat(64);
const formHeaders = { "content-type": "application/x-www-form-urlencoded", origin: "https://auth.example.test" };

function loginBody(overrides = {}, additions = []) {
  const fields = new URLSearchParams({ _csrf: csrf, next: "/apps", username, password, ...overrides });
  for (const [name, value] of additions) fields.append(name, value);
  return fields.toString();
}

function violation(request) {
  return credentialRequestViolation(request, "https://auth.example.test", username, password);
}

test("allows credentials only in the canonical Shauth login POST", () => {
  assert.equal(violation({ method: "POST", url: "https://auth.example.test/login", headers: formHeaders, body: loginBody() }), "");
});

test("rejects non-canonical Shauth login requests", () => {
  const requests = {
    "mutated form action": { method: "POST", url: "https://app.example.test/login", headers: formHeaders, body: loginBody() },
    "query on form action": { method: "POST", url: "https://auth.example.test/login?destination=app", headers: formHeaders, body: loginBody() },
    "cross-origin request header": { method: "POST", url: "https://auth.example.test/login", headers: { ...formHeaders, origin: "https://app.example.test" }, body: loginBody() },
    "authorization header": { method: "POST", url: "https://auth.example.test/login", headers: { ...formHeaders, authorization: `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}` }, body: loginBody() },
    "wrong media type": { method: "POST", url: "https://auth.example.test/login", headers: { ...formHeaders, "content-type": "text/plain" }, body: loginBody() },
    "missing CSRF field": { method: "POST", url: "https://auth.example.test/login", headers: formHeaders, body: new URLSearchParams({ next: "/apps", username, password }).toString() },
    "invalid CSRF field": { method: "POST", url: "https://auth.example.test/login", headers: formHeaders, body: loginBody({ _csrf: "not-a-token" }) },
    "duplicate username": { method: "POST", url: "https://auth.example.test/login", headers: formHeaders, body: loginBody({}, [["username", username]]) },
    "duplicate password": { method: "POST", url: "https://auth.example.test/login", headers: formHeaders, body: loginBody({}, [["password", password]]) },
    "unexpected field": { method: "POST", url: "https://auth.example.test/login", headers: formHeaders, body: loginBody({}, [["redirect_uri", "https://app.example.test/callback"]]) },
    "absolute next": { method: "POST", url: "https://auth.example.test/login", headers: formHeaders, body: loginBody({ next: "https://app.example.test/" }) },
    "scheme-relative next": { method: "POST", url: "https://auth.example.test/login", headers: formHeaders, body: loginBody({ next: "//app.example.test/" }) },
    "backslash next": { method: "POST", url: "https://auth.example.test/login", headers: formHeaders, body: loginBody({ next: "/\\app.example.test" }) },
    "credential-bearing next": { method: "POST", url: "https://auth.example.test/login", headers: formHeaders, body: loginBody({ next: `/?account=${encodeURIComponent(username)}` }) },
  };
  for (const [name, request] of Object.entries(requests)) {
    assert.notEqual(violation(request), "", name);
  }
});

test("detects recursively URL- and Base64-encoded credential exfiltration", () => {
  const encoded = Buffer.from(encodeURIComponent(Buffer.from(password).toString("base64"))).toString("base64url");
  assert.notEqual(violation({ method: "POST", url: "https://app.example.test/collect", headers: { "content-type": "text/plain" }, body: encoded }), "");
  const redacted = redactCredentialMaterial(`failure=${encoded}`, [password]);
  assert.equal(redacted.includes(password), false);
  assert.equal(redacted.includes(encoded), false);
  assert.match(redacted, /\[redacted\]/);
});

test("ignores requests without validation credential material", () => {
  assert.equal(violation({ method: "GET", url: "https://app.example.test/", headers: { accept: "text/html" }, body: "" }), "");
});

test("bounded failure diagnostics retain the newest complete trace events", () => {
  const events = Array.from({ length: 80 }, (_, index) => `response 200 https://app.example.test/noisy-${String(index).padStart(2, "0")}`);
  events.push("request POST https://app.example.test/auth/logout");
  events.push("response 500 https://app.example.test/auth/logout");
  const failure = boundedFailureWithLatestTrace("sharecrop sign out did not complete", events, 1000);
  assert.ok(failure.length <= 1000);
  assert.doesNotMatch(failure, /noisy-00/);
  assert.match(failure, /request POST https:\/\/app\.example\.test\/auth\/logout/);
  assert.match(failure, /response 500 https:\/\/app\.example\.test\/auth\/logout$/);
});

async function listen(handler) {
  const server = http.createServer(handler);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  return { server, origin: `http://127.0.0.1:${address.port}` };
}

async function close(server) {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

test("Chromium sends the canonical form only to Shauth and aborts application exfiltration", { timeout: 30_000 }, async () => {
  let loginPosts = 0;
  const provider = await listen((request, response) => {
    if (request.method === "GET") {
      response.setHeader("content-type", "text/html");
      response.end(`<form method="post" action="/login"><input name="_csrf" value="${csrf}"><input name="next" value="/apps"><label>Username<input name="username"></label><label>Password<input name="password" type="password"></label><button>Sign in with password</button></form>`);
      return;
    }
    loginPosts += 1;
    response.statusCode = 204;
    response.end();
  });
  let applicationPosts = 0;
  const application = await listen((request, response) => {
    if (request.method === "POST") applicationPosts += 1;
    response.setHeader("content-type", "text/html");
    response.end("application");
  });
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext();
    const violations = [];
    await installCredentialBoundary(context, provider.origin, username, password, (value) => violations.push(value));
    const page = await context.newPage();
    await page.goto(`${provider.origin}/login`);
    await page.getByLabel("Username").fill(username);
    await page.getByLabel("Password").fill(password);
    await page.getByRole("button").click();
    assert.equal(loginPosts, 1);
    assert.deepEqual(violations, []);

    await page.goto(application.origin);
    const encoded = Buffer.from(encodeURIComponent(Buffer.from(password).toString("base64"))).toString("base64url");
    await page.evaluate(async ({ encoded }) => {
      await fetch("/collect", { method: "POST", body: encoded }).catch(() => {});
    }, { encoded });
    assert.equal(applicationPosts, 0);
    assert.equal(violations.length, 1);
    await context.close();
  } finally {
    await browser.close();
    await close(provider.server);
    await close(application.server);
  }
});

test("Chromium consumes a fragment bootstrap once and never sends its token to an application", { timeout: 30_000 }, async () => {
  const bootstrapToken = "b".repeat(64);
  let providerGETExposedToken = false;
  let providerBootstrapPosts = 0;
  const provider = await listen((request, response) => {
    if (request.method === "GET") {
      providerGETExposedToken ||= request.url.includes(bootstrapToken);
      if (request.url === "/done") {
        response.setHeader("content-type", "text/html");
        response.end("bootstrap complete");
        return;
      }
      response.setHeader("cache-control", "no-store");
      response.setHeader("referrer-policy", "no-referrer");
      response.setHeader("content-type", "text/html");
      response.end(`<form id="bootstrap" method="post" action="/validator/bootstrap"><input name="_csrf" value="${csrf}"><input id="token" name="token"></form><script>const token=location.hash.slice(1);history.replaceState(null,"",location.pathname);document.getElementById("token").value=token;document.getElementById("bootstrap").requestSubmit()</script>`);
      return;
    }
    providerBootstrapPosts += 1;
    response.statusCode = 303;
    response.setHeader("location", "/done");
    response.end();
  });
  let applicationPosts = 0;
  const application = await listen((request, response) => {
    if (request.method === "POST") applicationPosts += 1;
    response.setHeader("content-type", "text/html");
    response.end("application");
  });
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext();
    const violations = [];
    await installCredentialBoundary(context, provider.origin, "", "", (value) => violations.push(value), [bootstrapToken]);
    const page = await context.newPage();
    await page.goto(`${provider.origin}/validator/bootstrap#${bootstrapToken}`);
    for (let attempt = 0; attempt < 100 && providerBootstrapPosts === 0; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(providerBootstrapPosts, 1);
    assert.equal(providerGETExposedToken, false);
    assert.deepEqual(violations, []);

    await page.goto(application.origin);
    const encoded = Buffer.from(encodeURIComponent(Buffer.from(bootstrapToken).toString("base64"))).toString("base64url");
    await page.evaluate(async ({ encoded }) => {
      await fetch("/collect", { method: "POST", body: encoded }).catch(() => {});
    }, { encoded });
    assert.equal(applicationPosts, 0);
    assert.equal(violations.length, 1);
    await context.close();
  } finally {
    await browser.close();
    await close(provider.server);
    await close(application.server);
  }
});
