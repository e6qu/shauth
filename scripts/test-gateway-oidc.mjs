// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import http from "node:http";
import { chromium } from "playwright";

const password = process.env.SHAUTH_BOOTSTRAP_ADMIN_PASSWORD;
const primaryDatabase = process.env.SHAUTH_GATEWAY_PRIMARY_DATABASE;
const secondaryDatabase = process.env.SHAUTH_GATEWAY_SECONDARY_DATABASE;
assert.ok(password, "SHAUTH_BOOTSTRAP_ADMIN_PASSWORD is required");
assert.match(primaryDatabase ?? "", /^[a-z][a-z0-9_]+$/, "SHAUTH_GATEWAY_PRIMARY_DATABASE is required");
assert.match(secondaryDatabase ?? "", /^[a-z][a-z0-9_]+$/, "SHAUTH_GATEWAY_SECONDARY_DATABASE is required");
assert.notEqual(primaryDatabase, secondaryDatabase, "gateway relying parties must use distinct databases");

const primary = await createUpstream(5557, "Primary application");
const secondary = await createUpstream(5559, "Secondary application");

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
  await assertSession(context, "http://localhost:5556", 200);

  const sessionResponse = await context.request.get("http://localhost:5556/auth/session");
  const session = await sessionResponse.json();
  const protectedResponse = await context.request.get("http://localhost:5556/");
  assert.equal(protectedResponse.headers()["content-security-policy"], "default-src 'self'; frame-ancestors 'self'");
  assert.equal(protectedResponse.headers()["x-frame-options"], "SAMEORIGIN");
  const gatewayResponse = await context.request.get("http://localhost:5556/auth/session");
  assert.match(gatewayResponse.headers()["content-security-policy"], /form-action 'self' http:\/\/localhost:8080/);
  assert.equal(gatewayResponse.headers()["x-frame-options"], "DENY");
  assert.deepEqual(await primary.identity, {
    subject: session.subject,
    username: "admin",
    email: "admin@localhost.test",
    role: "admin",
    authorization: undefined,
  });

  const providerSessionID = queryGateway(primaryDatabase, "SELECT provider_session_id FROM oidc_gateway_sessions WHERE client_id='gateway-integration' AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1");
  assert.ok(providerSessionID, "gateway session did not persist its provider session identifier");

  const rejectedFrontchannel = await context.request.get(`http://localhost:5556/auth/frontchannel-logout?iss=${encodeURIComponent("https://attacker.example")}&sid=${encodeURIComponent(providerSessionID)}`);
  assert.equal(rejectedFrontchannel.status(), 200);
  await assertSession(context, "http://localhost:5556", 200);

  const providerContext = await browser.newContext();
  try {
    const acceptedFrontchannel = await providerContext.request.get(`http://localhost:5556/auth/frontchannel-logout?iss=${encodeURIComponent("http://localhost:8080")}&sid=${encodeURIComponent(providerSessionID)}`);
    assert.equal(acceptedFrontchannel.status(), 200);
  } finally {
    await providerContext.close();
  }
  await assertSession(context, "http://localhost:5556", 401);

  await page.goto("http://localhost:5556/");
  await page.waitForURL("http://localhost:5556/");
  await assertSession(context, "http://localhost:5556", 200);

  // A second relying party uses the already authenticated Shauth session.
  // Reaching its upstream without another credential form proves browser SSO,
  // while the distinct PostgreSQL session proves the relying parties do not
  // accidentally share their own cookies.
  await page.goto("http://localhost:5558/");
  await page.waitForURL("http://localhost:5558/");
  await page.getByRole("heading", { name: "Secondary application" }).waitFor();
  await assertSession(context, "http://localhost:5558", 200);
  assert.deepEqual(await secondary.identity, {
    subject: session.subject,
    username: "admin",
    email: "admin@localhost.test",
    role: "admin",
    authorization: undefined,
  });
  assert.equal(queryGateway(primaryDatabase, "SELECT string_agg(DISTINCT client_id, ',' ORDER BY client_id) FROM oidc_gateway_sessions WHERE revoked_at IS NULL"), "gateway-integration");
  assert.equal(queryGateway(secondaryDatabase, "SELECT string_agg(DISTINCT client_id, ',' ORDER BY client_id) FROM oidc_gateway_sessions WHERE revoked_at IS NULL"), "gateway-secondary");

  await page.goto("http://localhost:5556/");
  await page.waitForURL("http://localhost:5556/");
  await page.getByRole("button", { name: "Sign out" }).click();
  await waitForURL(page, "http://localhost:5556/auth/signed-out", navigationTrace, browserErrors);
  await page.getByRole("heading", { name: "Signed out" }).waitFor();
  await assertSession(context, "http://localhost:5556", 401);
  await assertSession(context, "http://localhost:5558", 401);
  let primaryLogoutTokens = "0";
  let secondaryLogoutTokens = "0";
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const logoutQuery = "SELECT count(*) FROM oidc_gateway_logout_tokens WHERE expires_at > now() + interval '30 seconds' AND expires_at <= now() + interval '2 minutes'";
    primaryLogoutTokens = queryGateway(primaryDatabase, logoutQuery);
    secondaryLogoutTokens = queryGateway(secondaryDatabase, logoutQuery);
    if (primaryLogoutTokens === "1" && secondaryLogoutTokens === "1") break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.equal(primaryLogoutTokens, "1", "primary relying party must validate its provider logout token");
  assert.equal(secondaryLogoutTokens, "1", "secondary relying party must validate its provider logout token");
  assert.equal(queryGateway(primaryDatabase, "SELECT count(*) FROM oidc_gateway_sessions WHERE revoked_at IS NULL"), "0");
  assert.equal(queryGateway(secondaryDatabase, "SELECT count(*) FROM oidc_gateway_sessions WHERE revoked_at IS NULL"), "0");
  const noLocalSessionLogout = await context.request.post("http://localhost:5556/auth/logout", {
    headers: { origin: "http://localhost:5556" },
    maxRedirects: 0,
  });
  assert.equal(noLocalSessionLogout.status(), 303);
  const noLocalSessionTarget = new URL(noLocalSessionLogout.headers().location);
  assert.equal(noLocalSessionTarget.origin, "http://localhost:8080");
  assert.equal(noLocalSessionTarget.pathname, "/oauth2/sessions/logout");
  assert.equal(noLocalSessionTarget.searchParams.get("client_id"), "gateway-integration");
  assert.equal(noLocalSessionTarget.searchParams.get("post_logout_redirect_uri"), "http://localhost:5556/auth/signed-out");
  assert.equal(noLocalSessionTarget.searchParams.has("id_token_hint"), false);
  await page.goto("http://localhost:8080/apps");
  await page.waitForURL((url) => url.origin === "http://localhost:8080" && url.pathname === "/login");
  assert.deepEqual(browserErrors, []);
} finally {
  await browser.close();
  await Promise.all([closeServer(primary.server), closeServer(secondary.server)]);
}

async function createUpstream(port, title) {
  let resolveIdentity;
  const identity = new Promise((resolve) => { resolveIdentity = resolve; });
  const server = http.createServer((request, response) => {
    resolveIdentity({
      subject: request.headers["x-forwarded-subject"],
      username: request.headers["x-forwarded-preferred-username"],
      email: request.headers["x-forwarded-email"],
      role: request.headers["x-forwarded-role"],
      authorization: request.headers.authorization,
    });
    response.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
      "x-frame-options": "SAMEORIGIN",
    });
    response.end(`<!doctype html><html lang=en><title>${title}</title><h1>${title}</h1><form method=post action=/auth/logout><button>Sign out</button></form></html>`);
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
  return { server, identity };
}

function queryGateway(database, query) {
  return execFileSync(
    "docker",
    ["compose", "exec", "-T", "postgres", "psql", "-U", "shauth", "-d", database, "-Atc", query],
    { encoding: "utf8" },
  ).trim();
}

function closeServer(server) {
  return new Promise((resolve) => server.close(resolve));
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

async function assertSession(context, applicationOrigin, expectedStatus) {
  const response = await context.request.get(`${applicationOrigin}/auth/session`);
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
