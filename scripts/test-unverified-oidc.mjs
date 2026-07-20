// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { chromium } from "playwright";
import { isStrictOIDCIdentity } from "./oidc-claims.mjs";

const issuer = "http://localhost:8080";
const hydraAdmin = "http://localhost:4445";
const callbackURL = "http://localhost:5555/callback";
const clientID = "shauth-integration-client";
const clientSecret = process.env.SHAUTH_OIDC_CLIENT_SECRET;
const username = "unverified-oidc";
const email = "unverified-oidc@localhost.test";
const password = process.env.SHAUTH_UNVERIFIED_USER_PASSWORD;

assert.ok(clientSecret, "SHAUTH_OIDC_CLIENT_SECRET is required");
assert.ok(password, "SHAUTH_UNVERIFIED_USER_PASSWORD is required");

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

    const idTokenClaims = JSON.parse(Buffer.from(tokens.id_token.split(".")[1], "base64url"));
    assert.equal(idTokenClaims.preferred_username, username);
    assert.equal(idTokenClaims.email, email);
    assert.equal(idTokenClaims.email_verified, false, "ID token elevated an unverified email");
    assert.equal(idTokenClaims.role, "developer");
    assert.equal(isStrictOIDCIdentity(idTokenClaims), false, "strict relying-party gate accepted an unverified identity");

    const introspectionResponse = await fetch(`${hydraAdmin}/admin/oauth2/introspect`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: tokens.access_token }),
    });
    assert.equal(introspectionResponse.status, 200, `access-token introspection returned HTTP ${introspectionResponse.status}`);
    const introspection = await introspectionResponse.json();
    assert.equal(introspection.active, true, "issued access token was not active");
    assert.equal(introspection.ext?.email_verified, false, "access token elevated an unverified email");
    assert.equal(isStrictOIDCIdentity(introspection.ext), false, "strict relying-party gate accepted unverified access-token claims");

    const userInfoResponse = await fetch(`${issuer}/userinfo`, {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    assert.equal(userInfoResponse.status, 200, `UserInfo returned HTTP ${userInfoResponse.status}`);
    const userInfo = await userInfoResponse.json();
    assert.equal(userInfo.email_verified, false, "UserInfo elevated an unverified email");
    assert.equal(isStrictOIDCIdentity(userInfo), false, "strict relying-party gate accepted unverified UserInfo claims");

    response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    response.end("Unverified OIDC browser flow was rejected by the strict identity contract");
    resolveCallback();
  } catch (error) {
    response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
    response.end("Unverified OIDC browser flow failed");
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
  const authorizationURL = new URL("/oauth2/auth", issuer);
  authorizationURL.search = new URLSearchParams({
    client_id: clientID,
    response_type: "code",
    scope: "openid profile email",
    redirect_uri: callbackURL,
    state,
  });
  await page.goto(authorizationURL.toString());
  await page.locator("#username").fill(username);
  await page.locator("#password").fill(password);
  await page.getByRole("button", { name: "Sign in with password" }).click();
  await Promise.race([
    callback,
    new Promise((_, reject) => setTimeout(() => reject(new Error("unverified OIDC browser callback timed out")), 30_000)),
  ]);
  await page.getByText("Unverified OIDC browser flow was rejected by the strict identity contract").waitFor();
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}
