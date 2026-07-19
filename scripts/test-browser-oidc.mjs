// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { chromium } from "playwright";

const issuer = "http://localhost:8080";
const callbackURL = "http://localhost:5555/callback";
const clientID = "shauth-integration-client";
const clientSecret = process.env.SHAUTH_OIDC_CLIENT_SECRET;
const password = process.env.SHAUTH_BOOTSTRAP_ADMIN_PASSWORD;

assert.ok(clientSecret, "SHAUTH_OIDC_CLIENT_SECRET is required");
assert.ok(password, "SHAUTH_BOOTSTRAP_ADMIN_PASSWORD is required");

const state = crypto.randomBytes(32).toString("hex");
let resolveCallback;
let rejectCallback;
const callback = new Promise((resolve, reject) => {
  resolveCallback = resolve;
  rejectCallback = reject;
});

const server = http.createServer(async (request, response) => {
  try {
    const callbackRequest = new URL(request.url, callbackURL);
    assert.equal(callbackRequest.pathname, "/callback");
    assert.equal(callbackRequest.searchParams.get("state"), state);
    const code = callbackRequest.searchParams.get("code");
    assert.ok(code, "OIDC callback omitted the authorization code");

    const tokenResponse = await fetch(`${issuer}/oauth2/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: callbackURL,
        client_id: clientID,
        client_secret: clientSecret,
      }),
    });
    assert.equal(tokenResponse.status, 200, `token exchange returned HTTP ${tokenResponse.status}`);
    const tokens = await tokenResponse.json();
    assert.ok(tokens.access_token, "token exchange omitted the access token");
    assert.ok(tokens.id_token, "token exchange omitted the ID token");
    const idTokenPayload = JSON.parse(Buffer.from(tokens.id_token.split(".")[1], "base64url"));
    assert.ok(idTokenPayload.sid, "ID token omitted the correlated provider session ID");

    const userInfoResponse = await fetch(`${issuer}/userinfo`, {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    assert.equal(userInfoResponse.status, 200, `UserInfo returned HTTP ${userInfoResponse.status}`);
    const user = await userInfoResponse.json();
    assert.equal(user.preferred_username, "admin");
    assert.equal(user.email, "admin@localhost.test");
    assert.equal(user.role, "admin");

    response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    response.end("OIDC browser flow completed");
    resolveCallback();
  } catch (error) {
    response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
    response.end("OIDC browser flow failed");
    rejectCallback(error);
  }
});

await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(5555, "127.0.0.1", resolve);
});

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  const browserErrors = [];
  const browserAssets = [];
  const htmxRequests = [];
  page.on("request", (request) => {
    if (["script", "stylesheet", "image", "font", "media"].includes(request.resourceType())) {
      browserAssets.push(request.url());
    }
    if (request.method() === "POST" && request.url() === `${issuer}/admin/users`) {
      htmxRequests.push(request.headers()["hx-request"]);
    }
  });
  page.on("console", (message) => {
    if (message.type() === "error") browserErrors.push(message.text());
  });
  page.on("pageerror", (error) => browserErrors.push(error.message));
  page.on("requestfailed", (request) => browserErrors.push(`${request.url()}: ${request.failure()?.errorText ?? "request failed"}`));

  const authorizationURL = new URL("/oauth2/auth", issuer);
  authorizationURL.search = new URLSearchParams({
    client_id: clientID,
    response_type: "code",
    scope: "openid profile email offline_access",
    redirect_uri: callbackURL,
    state,
  });
  await page.goto(authorizationURL.toString());
  await page.locator("#username").fill("admin");
  await page.locator("#password").fill(password);
  await page.getByRole("button", { name: "Sign in with password" }).click();
  await Promise.race([
    callback,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`OIDC browser callback timed out: ${browserErrors.join("; ")}`)), 30_000)),
  ]);
  await page.getByText("OIDC browser flow completed").waitFor();

  const username = `htmx-${crypto.randomBytes(6).toString("hex")}`;
  await page.goto(`${issuer}/admin/users`);
  await page.locator("#new-username").fill(username);
  await page.locator("#new-email").fill(`${username}@localhost.test`);
  await page.locator("#new-password").fill(crypto.randomBytes(24).toString("base64url"));
  await page.getByRole("button", { name: "Create local user" }).click();
  await page.locator("#users").getByRole("link", { name: username }).waitFor();
  assert.equal(page.url(), `${issuer}/admin/users`);
  assert.deepEqual(htmxRequests, ["true"]);
  assert.deepEqual([...new Set(browserAssets)].sort(), [
    `${issuer}/assets/htmx-2.0.8.min.js`,
    `${issuer}/assets/theme.js`,
  ]);
  assert.deepEqual(browserErrors, []);
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}
