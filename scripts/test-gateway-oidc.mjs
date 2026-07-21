// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import http from "node:http";
import path from "node:path";
import { chromium } from "playwright";
import { applicationSignOutControl } from "../validator/application-ui.mjs";

const password = process.env.SHAUTH_BOOTSTRAP_ADMIN_PASSWORD;
const primaryDatabase = process.env.SHAUTH_GATEWAY_PRIMARY_DATABASE;
const secondaryDatabase = process.env.SHAUTH_GATEWAY_SECONDARY_DATABASE;
const tertiaryDatabase = process.env.SHAUTH_GATEWAY_TERTIARY_DATABASE;
const validatorCoordinationDirectory = process.env.SHAUTH_VALIDATOR_COORDINATION_DIR;
const testFocus = process.env.SHAUTH_GATEWAY_TEST_FOCUS ?? "";
assert.ok(password, "SHAUTH_BOOTSTRAP_ADMIN_PASSWORD is required");
assert.match(primaryDatabase ?? "", /^[a-z][a-z0-9_]+$/, "SHAUTH_GATEWAY_PRIMARY_DATABASE is required");
assert.match(secondaryDatabase ?? "", /^[a-z][a-z0-9_]+$/, "SHAUTH_GATEWAY_SECONDARY_DATABASE is required");
assert.match(tertiaryDatabase ?? "", /^[a-z][a-z0-9_]+$/, "SHAUTH_GATEWAY_TERTIARY_DATABASE is required");
assert.equal(new Set([primaryDatabase, secondaryDatabase, tertiaryDatabase]).size, 3, "gateway relying parties must use distinct databases");

const primary = await createUpstream(5557, "Primary application", "222222222222");
const secondary = await createUpstream(5559, "Secondary application", "333333333333");
const tertiary = await createUpstream(5561, "Tertiary application", "444444444444");

if (validatorCoordinationDirectory) {
  writeFileSync(path.join(validatorCoordinationDirectory, "ready"), "", { mode: 0o600 });
  await waitForFile(path.join(validatorCoordinationDirectory, "run-gateway-matrix"), 360_000);
}
primary.resetIdentity();
secondary.resetIdentity();
tertiary.resetIdentity();
const logoutTokenBaselines = {
  [primaryDatabase]: countLogoutTokens(primaryDatabase),
  [secondaryDatabase]: countLogoutTokens(secondaryDatabase),
  [tertiaryDatabase]: countLogoutTokens(tertiaryDatabase),
};

const browser = await chromium.launch({ headless: true });
if (testFocus === "logout-correlation") {
  try {
    await exerciseLogoutCorrelationFailure(browser, primaryDatabase);
    await exerciseCorrelationCreationFailure(browser, primaryDatabase);
  } finally {
    await browser.close();
    await Promise.all([closeServer(primary.server), closeServer(secondary.server), closeServer(tertiary.server)]);
  }
} else {
try {
  const context = await browser.newContext();
  await context.route("**/*", async (route) => route.continue());
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

  const anonymousValidation = await gatewayRequest(context, "GET", "http://gateway-integration.localhost:5556/auth/validation", { maxRedirects: 0 });
  assert.equal(anonymousValidation.status(), 303);
  assert.equal(anonymousValidation.headers().location, "/auth/signed-out");

  await page.goto("http://gateway-integration.localhost:5556/");
  await page.locator("#username").fill("admin");
  await page.locator("#password").fill(password);
  await page.getByRole("button", { name: "Sign in with password" }).click();
  await page.waitForURL("http://gateway-integration.localhost:5556/");
  await assertSession(context, "http://gateway-integration.localhost:5556", 200);

  const sessionResponse = await gatewayRequest(context, "GET", "http://gateway-integration.localhost:5556/auth/session");
  const session = await sessionResponse.json();
  const protectedResponse = await gatewayRequest(context, "GET", "http://gateway-integration.localhost:5556/");
  assert.equal(protectedResponse.headers()["content-security-policy"], "default-src 'self'; frame-ancestors 'self'");
  assert.equal(protectedResponse.headers()["x-frame-options"], "SAMEORIGIN");
  const gatewayResponse = await gatewayRequest(context, "GET", "http://gateway-integration.localhost:5556/auth/session");
  assert.match(gatewayResponse.headers()["content-security-policy"], /form-action 'self' http:\/\/localhost:8080/);
  assert.equal(gatewayResponse.headers()["x-frame-options"], "DENY");
  assert.ok(primary.identity(), "primary upstream did not observe the administrator request");
  assert.deepEqual(primary.identity(), {
    subject: session.subject,
    username: "admin",
    email: "admin@localhost.test",
    role: "admin",
    authorization: undefined,
  });
  await page.goto("http://gateway-integration.localhost:5556/auth/validation");
  assert.equal(await page.getByTestId("validation-username").textContent(), "admin");
  assert.equal(await page.getByTestId("validation-email").textContent(), "admin@localhost.test");
  assert.equal(await page.getByTestId("validation-role").textContent(), "admin");
  assert.equal(await page.getByTestId("validation-release").textContent(), "222222222222");
  await page.goto("http://gateway-integration.localhost:5556/");
  await applicationSignOutControl(page, "admin", "primary application");

  const providerSessionID = queryGateway(primaryDatabase, "SELECT provider_session_id FROM oidc_gateway_sessions WHERE client_id='gateway-integration' AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1");
  assert.ok(providerSessionID, "gateway session did not persist its provider session identifier");

  const rejectedFrontchannel = await gatewayRequest(context, "GET", `http://gateway-integration.localhost:5556/auth/frontchannel-logout?iss=${encodeURIComponent("https://attacker.example")}&sid=${encodeURIComponent(providerSessionID)}`);
  assert.equal(rejectedFrontchannel.status(), 200);
  await assertSession(context, "http://gateway-integration.localhost:5556", 200);

  const providerContext = await browser.newContext();
  try {
    const terminatedProviderSession = await providerContext.request.delete(`http://localhost:4445/admin/oauth2/auth/sessions/login?sid=${encodeURIComponent(providerSessionID)}`);
    assert.equal(terminatedProviderSession.status(), 204);
    const acceptedFrontchannel = await gatewayRequest(providerContext, "GET", `http://gateway-integration.localhost:5556/auth/frontchannel-logout?iss=${encodeURIComponent("http://localhost:8080")}&sid=${encodeURIComponent(providerSessionID)}`);
    assert.equal(acceptedFrontchannel.status(), 200);
  } finally {
    await providerContext.close();
  }
  await assertSession(context, "http://gateway-integration.localhost:5556", 401);

  await page.goto("http://gateway-integration.localhost:5556/");
  await page.waitForURL("http://gateway-integration.localhost:5556/auth/signed-out");
  const frontchannelSignIn = page.getByRole("link", { name: "Sign in with Shauth", exact: true });
  assert.equal(await frontchannelSignIn.getAttribute("href"), "/auth/login");
  await frontchannelSignIn.click();
  await page.waitForURL("http://gateway-integration.localhost:5556/");
  await assertSession(context, "http://gateway-integration.localhost:5556", 200);
  const replacementProviderSessionID = queryGateway(primaryDatabase, "SELECT provider_session_id FROM oidc_gateway_sessions WHERE client_id='gateway-integration' AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1");
  assert.notEqual(replacementProviderSessionID, providerSessionID, "front-channel logout reused a tombstoned provider session");

  // Two more relying parties use the already authenticated Shauth session.
  // Reaching their upstreams without another credential form proves browser
  // SSO, while distinct PostgreSQL sessions prove the relying parties do not
  // accidentally share their own cookies.
  await page.goto("http://gateway-secondary.localhost:5558/");
  await page.waitForURL("http://gateway-secondary.localhost:5558/");
  await page.getByRole("heading", { name: "Secondary application" }).waitFor();
  await assertSession(context, "http://gateway-secondary.localhost:5558", 200);
  assert.ok(secondary.identity(), "secondary upstream did not observe the administrator request");
  assert.deepEqual(secondary.identity(), {
    subject: session.subject,
    username: "admin",
    email: "admin@localhost.test",
    role: "admin",
    authorization: undefined,
  });
  await page.goto("http://gateway-tertiary.localhost:5560/");
  await page.waitForURL("http://gateway-tertiary.localhost:5560/");
  await page.getByRole("heading", { name: "Tertiary application" }).waitFor();
  await assertSession(context, "http://gateway-tertiary.localhost:5560", 200);
  assert.ok(tertiary.identity(), "tertiary upstream did not observe the administrator request");
  assert.deepEqual(tertiary.identity(), {
    subject: session.subject,
    username: "admin",
    email: "admin@localhost.test",
    role: "admin",
    authorization: undefined,
  });
  assert.equal(queryGateway(primaryDatabase, "SELECT string_agg(DISTINCT client_id, ',' ORDER BY client_id) FROM oidc_gateway_sessions WHERE revoked_at IS NULL"), "gateway-integration");
  assert.equal(queryGateway(secondaryDatabase, "SELECT string_agg(DISTINCT client_id, ',' ORDER BY client_id) FROM oidc_gateway_sessions WHERE revoked_at IS NULL"), "gateway-secondary");
  assert.equal(queryGateway(tertiaryDatabase, "SELECT string_agg(DISTINCT client_id, ',' ORDER BY client_id) FROM oidc_gateway_sessions WHERE revoked_at IS NULL"), "gateway-tertiary");

  const activeProviderSessions = [
    providerSessionID,
    queryGateway(secondaryDatabase, "SELECT provider_session_id FROM oidc_gateway_sessions WHERE client_id='gateway-secondary' AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1"),
    queryGateway(tertiaryDatabase, "SELECT provider_session_id FROM oidc_gateway_sessions WHERE client_id='gateway-tertiary' AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1"),
  ];
  for (const [index, activeProviderSession] of activeProviderSessions.entries()) {
    assert.equal(queryShauth(`SELECT count(*) FROM hydra_login_sessions WHERE hydra_session_id='${activeProviderSession}'`), "1", `Shauth did not correlate active Ory Hydra session ${index + 1}`);
  }

  // A second browser owns an independent Shauth session, Hydra login session,
  // and relying-party session for the same identity. Global logout must revoke
  // this remote browser through targeted Hydra back-channel delivery while the
  // current browser continues through Hydra's public front/back-channel flow.
  const remoteContext = await browser.newContext();
  const remotePage = await remoteContext.newPage();
  await remotePage.goto("http://localhost:8080/login");
  await remotePage.locator("#username").fill("admin");
  await remotePage.locator("#password").fill(password);
  await remotePage.getByRole("button", { name: "Sign in with password" }).click();
  await remotePage.waitForURL("http://localhost:8080/");
  await remotePage.goto("http://gateway-integration.localhost:5556/");
  await remotePage.waitForURL("http://gateway-integration.localhost:5556/");
  await assertSession(remoteContext, "http://gateway-integration.localhost:5556", 200);
  const remoteProviderSessionID = queryGateway(primaryDatabase, `SELECT provider_session_id FROM oidc_gateway_sessions WHERE client_id='gateway-integration' AND provider_session_id<>'${providerSessionID}' AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1`);
  assert.ok(remoteProviderSessionID, "the second browser did not receive an independent Ory Hydra login session");
  queryShauth(`INSERT INTO refresh_tokens (id,session_id,family_id,token_hash,issued_at,expires_at)
    SELECT '00000000-0000-4000-8000-000000000099'::uuid,id,refresh_family_id,decode(repeat('ab',32),'hex'),now(),now()+interval '1 hour'
    FROM sessions WHERE user_id='${session.subject}'::uuid AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1`);

  const correlatedProviderSession = queryShauth(`SELECT browser_session_id::text FROM hydra_login_sessions WHERE hydra_session_id='${providerSessionID}'`);
  assert.ok(correlatedProviderSession, "Shauth must persist Ory Hydra's provider session ID");
  assert.notEqual(correlatedProviderSession, providerSessionID, "Shauth must not mistake its own browser-session ID for Ory Hydra's provider session ID");
  // Hydra normally reuses one sid across clients. Associate the second real
  // browser's independently issued sid with this Shauth browser to reproduce a
  // browser that accumulated provider sessions across Hydra rotations.
  queryShauth(`UPDATE hydra_login_sessions SET browser_session_id='${correlatedProviderSession}'::uuid WHERE hydra_session_id='${remoteProviderSessionID}'`);
  assert.ok(Number(queryShauth(`SELECT count(*) FROM hydra_login_sessions WHERE browser_session_id='${correlatedProviderSession}'::uuid`)) > 1, "the public logout witness must cover multiple Hydra IDs correlated to one Shauth browser");

  // Provider-initiated logout starts at Shauth rather than either relying
  // party. It must still notify all three independently persisted RP sessions.
  await page.goto("http://localhost:8080/logout");
  const providerLogoutTraceStart = navigationTrace.length;
  const [providerLogoutSubmit] = await Promise.all([
    page.waitForResponse((response) => response.url() === "http://localhost:8080/logout" && response.request().method() === "POST"),
    page.getByRole("button", { name: "Sign out of all apps" }).click(),
  ]);
  assert.equal(providerLogoutSubmit.status(), 303);
  assert.equal(providerLogoutSubmit.headers().location, "/oauth2/sessions/logout");
  assert.equal(providerLogoutSubmit.request().isNavigationRequest(), true, "Shauth logout form must use a document navigation");
  await waitForURL(page, "http://localhost:8080/signed-out", navigationTrace, browserErrors);
  const providerLogoutTrace = navigationTrace.slice(providerLogoutTraceStart);
  for (const expected of [
    "request GET http://localhost:8080/oauth2/sessions/logout",
    "request GET http://localhost:8080/oauth/logout",
  ]) {
    assert.ok(providerLogoutTrace.includes(expected), `provider logout skipped ${expected}:\n${providerLogoutTrace.join("\n")}`);
  }
  await page.getByRole("heading", { name: "You are signed out" }).waitFor();
  let providerSignInControl = page.getByRole("link", { name: "Sign in to Shauth" });
  assert.equal(await providerSignInControl.getAttribute("href"), "/login");
  await page.reload();
  await page.getByRole("heading", { name: "You are signed out" }).waitFor();
  providerSignInControl = page.getByRole("link", { name: "Sign in to Shauth" });
  assert.equal(await providerSignInControl.getAttribute("href"), "/login");
  await waitForLogoutTokenCount(primaryDatabase, logoutTokenBaselines[primaryDatabase] + 3);
  await waitForLogoutTokenCount(secondaryDatabase, logoutTokenBaselines[secondaryDatabase]);
  await waitForLogoutTokenCount(tertiaryDatabase, logoutTokenBaselines[tertiaryDatabase] + 1);
  await waitForSessionStatus(context, "http://gateway-integration.localhost:5556", 401);
  await waitForSessionStatus(context, "http://gateway-secondary.localhost:5558", 401);
  await waitForSessionStatus(context, "http://gateway-tertiary.localhost:5560", 401);
  assert.equal(queryGateway(primaryDatabase, "SELECT count(*) FROM oidc_gateway_sessions WHERE revoked_at IS NULL"), "0");
  assert.equal(queryGateway(secondaryDatabase, "SELECT count(*) FROM oidc_gateway_sessions WHERE revoked_at IS NULL"), "0");
  assert.equal(queryGateway(tertiaryDatabase, "SELECT count(*) FROM oidc_gateway_sessions WHERE revoked_at IS NULL"), "0");
  assert.equal(queryShauth(`SELECT count(*) FROM sessions WHERE user_id='${session.subject}'::uuid AND revoked_at IS NULL`), "0", "provider logout must revoke every Shauth browser session for the user");
  assert.equal(queryShauth("SELECT count(*) FROM refresh_tokens WHERE id='00000000-0000-4000-8000-000000000099'::uuid AND revoked_at IS NOT NULL"), "1", "provider logout must revoke refresh-token families with their Shauth sessions");
  await waitForSessionStatus(remoteContext, "http://gateway-integration.localhost:5556", 401);
  await remotePage.goto("http://localhost:8080/apps");
  await remotePage.waitForURL((url) => url.origin === "http://localhost:8080" && url.pathname === "/login");
  await remoteContext.close();

  await providerSignInControl.click();
  await page.locator("#username").fill("admin");
  await page.locator("#password").fill(password);
  await page.getByRole("button", { name: "Sign in with password" }).click();
  await page.waitForURL("http://localhost:8080/");
  await signInFromLocalTerminal(page, "http://gateway-integration.localhost:5556");
  await assertSession(context, "http://gateway-integration.localhost:5556", 200);
  await signInFromLocalTerminal(page, "http://gateway-secondary.localhost:5558");
  await assertSession(context, "http://gateway-secondary.localhost:5558", 200);
  await signInFromLocalTerminal(page, "http://gateway-tertiary.localhost:5560");
  await assertSession(context, "http://gateway-tertiary.localhost:5560", 200);

  await page.goto("http://gateway-integration.localhost:5556/");
  await page.waitForURL("http://gateway-integration.localhost:5556/");
  await (await applicationSignOutControl(page, "admin", "primary application")).click();
  await waitForURL(page, "http://gateway-integration.localhost:5556/auth/signed-out", navigationTrace, browserErrors);
  await page.getByRole("heading", { name: "Signed out" }).waitFor();
  let signInControl = page.getByRole("link", { name: "Sign in with Shauth" });
  assert.equal(await signInControl.getAttribute("href"), "/auth/login", "signed-out sign-in control must use the application-local login starter");
  await page.reload();
  await page.getByRole("heading", { name: "Signed out" }).waitFor();
  signInControl = page.getByRole("link", { name: "Sign in with Shauth" });
  assert.equal(await signInControl.getAttribute("href"), "/auth/login", "reloaded signed-out page must preserve the application-local sign-in control");
  const injectedBridge = await gatewayRequest(context, "GET", "http://gateway-integration.localhost:5556/auth/shauth/logout/complete?next=https%3A%2F%2Fattacker.example&redirect_uri=https%3A%2F%2Fattacker.example", { maxRedirects: 0 });
  assert.equal(injectedBridge.status(), 303);
  assert.equal(injectedBridge.headers().location, "http://localhost:8080/oauth/logout/complete");
  const replayPage = await context.newPage();
  await replayPage.goto("http://localhost:8080/oauth/logout/complete?next=https%3A%2F%2Fattacker.example");
  await replayPage.waitForURL("http://localhost:8080/signed-out");
  await replayPage.getByRole("link", { name: "Sign in to Shauth" }).waitFor();
  await replayPage.close();
  await assertSession(context, "http://gateway-integration.localhost:5556", 401);
  await waitForLogoutTokenCount(primaryDatabase, logoutTokenBaselines[primaryDatabase] + 4);
  await waitForLogoutTokenCount(secondaryDatabase, logoutTokenBaselines[secondaryDatabase]);
  await waitForLogoutTokenCount(tertiaryDatabase, logoutTokenBaselines[tertiaryDatabase] + 2);
  await waitForSessionStatus(context, "http://gateway-secondary.localhost:5558", 401);
  await waitForSessionStatus(context, "http://gateway-tertiary.localhost:5560", 401);
  assert.equal(queryGateway(primaryDatabase, "SELECT count(*) FROM oidc_gateway_sessions WHERE revoked_at IS NULL"), "0");
  assert.equal(queryGateway(secondaryDatabase, "SELECT count(*) FROM oidc_gateway_sessions WHERE revoked_at IS NULL"), "0");
  assert.equal(queryGateway(tertiaryDatabase, "SELECT count(*) FROM oidc_gateway_sessions WHERE revoked_at IS NULL"), "0");
  const noLocalSessionLogout = await gatewayRequest(context, "POST", "http://gateway-integration.localhost:5556/auth/logout", {
    headers: { origin: "http://gateway-integration.localhost:5556" },
    maxRedirects: 0,
  });
  assert.equal(noLocalSessionLogout.status(), 303);
  const noLocalSessionTarget = new URL(noLocalSessionLogout.headers().location);
  assert.equal(noLocalSessionTarget.origin, "http://localhost:8080");
  assert.equal(noLocalSessionTarget.pathname, "/oauth2/sessions/logout");
  assert.equal(noLocalSessionTarget.searchParams.get("client_id"), "gateway-integration");
  assert.equal(noLocalSessionTarget.searchParams.get("post_logout_redirect_uri"), "http://gateway-integration.localhost:5556/auth/shauth/logout/complete");
  assert.equal(noLocalSessionTarget.searchParams.has("id_token_hint"), false);
  const signInTraceStart = navigationTrace.length;
  await signInControl.click();
  await page.waitForURL((url) => url.origin === "http://localhost:8080" && url.pathname === "/login");
  assert.ok(
    navigationTrace.slice(signInTraceStart).includes("request GET http://gateway-integration.localhost:5556/auth/login"),
    `signed-out sign-in control bypassed the application-local login starter:\n${navigationTrace.slice(signInTraceStart).join("\n")}`,
  );
  await page.goto("http://localhost:8080/apps");
  await page.waitForURL((url) => url.origin === "http://localhost:8080" && url.pathname === "/login");
  assert.deepEqual(browserErrors, []);

  // A Shauth-only browser has no relying-party ID token or Hydra login cookie.
  // Provider logout must still revoke the local session and land durably on
  // Shauth's signed-out page rather than failing or silently signing back in.
  const providerOnlyContext = await browser.newContext();
  const providerOnlyWitnessContext = await browser.newContext();
  try {
    const providerOnlyPage = await providerOnlyContext.newPage();
    const providerOnlyWitnessPage = await providerOnlyWitnessContext.newPage();
    await providerOnlyPage.goto("http://localhost:8080/login");
    await providerOnlyPage.locator("#username").fill("admin");
    await providerOnlyPage.locator("#password").fill(password);
    await providerOnlyPage.getByRole("button", { name: "Sign in with password" }).click();
    await providerOnlyPage.waitForURL("http://localhost:8080/");
    await providerOnlyWitnessPage.goto("http://localhost:8080/login");
    await providerOnlyWitnessPage.locator("#username").fill("admin");
    await providerOnlyWitnessPage.locator("#password").fill(password);
    await providerOnlyWitnessPage.getByRole("button", { name: "Sign in with password" }).click();
    await providerOnlyWitnessPage.waitForURL("http://localhost:8080/");
    await providerOnlyWitnessPage.goto("http://gateway-integration.localhost:5556/auth/login");
    await providerOnlyWitnessPage.waitForURL("http://gateway-integration.localhost:5556/");
    await assertSession(providerOnlyWitnessContext, "http://gateway-integration.localhost:5556", 200);
    await providerOnlyPage.goto("http://localhost:8080/logout");
    await providerOnlyPage.getByRole("button", { name: "Sign out of all apps" }).click();
    await providerOnlyPage.waitForURL("http://localhost:8080/signed-out");
    await providerOnlyPage.reload();
    await providerOnlyPage.getByRole("link", { name: "Sign in to Shauth" }).waitFor();
    await providerOnlyPage.goto("http://localhost:8080/apps");
    await providerOnlyPage.waitForURL((url) => url.origin === "http://localhost:8080" && url.pathname === "/login");
    await providerOnlyWitnessPage.goto("http://localhost:8080/apps");
    await providerOnlyWitnessPage.waitForURL((url) => url.origin === "http://localhost:8080" && url.pathname === "/login");
    await waitForSessionStatus(providerOnlyWitnessContext, "http://gateway-integration.localhost:5556", 401);
    await providerOnlyWitnessPage.goto("http://gateway-integration.localhost:5556/");
    await providerOnlyWitnessPage.waitForURL("http://gateway-integration.localhost:5556/auth/signed-out");
  } finally {
    await providerOnlyContext.close();
    await providerOnlyWitnessContext.close();
  }

  // A browser can disappear after the real logout form is accepted but before
  // Hydra's public callback completes. Local logout remains fail-closed, the
  // correlation grant is single-use, and durable recovery revokes the RP.
  await exerciseLogoutCorrelationFailure(browser, primaryDatabase);
  await exerciseCorrelationCreationFailure(browser, primaryDatabase);
} finally {
  await browser.close();
  await Promise.all([closeServer(primary.server), closeServer(secondary.server), closeServer(tertiary.server)]);
}
}

async function exerciseLogoutCorrelationFailure(browserInstance, database) {
  const abandonedContext = await browserInstance.newContext();
  try {
    const abandonedPage = await abandonedContext.newPage();
    await signInPortalAndPrimaryRP(abandonedPage, abandonedContext);
    const providerSessionID = queryGateway(database, "SELECT provider_session_id FROM oidc_gateway_sessions WHERE client_id='gateway-integration' AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1");
    assert.ok(providerSessionID, "abandoned-flow relying party has no provider session");
    const correlationCookie = await interruptProviderStart(abandonedPage, abandonedContext);
    assert.equal(activeShauthSessionCount(), "0", "POST /logout must revoke the Shauth session before provider navigation");
    await abandonedPage.goto("http://localhost:8080/apps");
    await abandonedPage.waitForURL((url) => url.origin === "http://localhost:8080" && url.pathname === "/login");
    const tokenHash = createHash("sha256").update(correlationCookie.value).digest("hex");
    queryShauth(`UPDATE logout_correlation_grants SET created_at=now()-interval '3 minutes',expires_at=now()-interval '1 minute',cleanup_after=now() WHERE token_hash=decode('${tokenHash}','hex')`);
    await waitForQuery(`SELECT count(*) FROM logout_correlation_grants WHERE completed_at IS NOT NULL AND token_hash=decode('${tokenHash}','hex')`, "1");
    await waitForSessionStatus(abandonedContext, "http://gateway-integration.localhost:5556", 401);
    assert.equal(queryGateway(database, `SELECT count(*) FROM oidc_gateway_sessions WHERE provider_session_id='${providerSessionID}' AND revoked_at IS NULL`), "0", "recovery left the relying-party session active");
    await abandonedPage.goto("http://gateway-integration.localhost:5556/");
    await abandonedPage.waitForURL("http://gateway-integration.localhost:5556/auth/signed-out");
    assert.equal(await abandonedPage.getByRole("link", { name: "Sign in with Shauth", exact: true }).getAttribute("href"), "/auth/login");
    await abandonedPage.goto("http://gateway-integration.localhost:5556/auth/login");
    await abandonedPage.waitForURL((url) => url.origin === "http://localhost:8080" && url.pathname === "/login");
  } finally {
    await abandonedContext.close();
  }

  const providerOnlyContext = await browserInstance.newContext();
  try {
    const providerOnlyPage = await providerOnlyContext.newPage();
    await signInPortalAndPrimaryRP(providerOnlyPage, providerOnlyContext);
    await providerOnlyPage.goto("http://gateway-secondary.localhost:5558/auth/login");
    await providerOnlyPage.waitForURL("http://gateway-secondary.localhost:5558/");
    await providerOnlyPage.goto("http://gateway-tertiary.localhost:5560/auth/login");
    await providerOnlyPage.waitForURL("http://gateway-tertiary.localhost:5560/");
    await providerOnlyContext.clearCookies({ name: "shauth_session" });
    const callbackRequest = providerOnlyPage.waitForRequest((request) => new URL(request.url()).pathname === "/oauth/logout");
    await providerOnlyPage.goto("http://gateway-integration.localhost:5556/");
    await (await applicationSignOutControl(providerOnlyPage, "admin", "primary application")).click();
    const callbackURL = new URL((await callbackRequest).url());
    assert.equal(callbackURL.pathname, "/oauth/logout");
    await providerOnlyPage.waitForURL("http://gateway-integration.localhost:5556/auth/signed-out");
    assert.equal(await providerOnlyPage.getByRole("link", { name: "Sign in with Shauth", exact: true }).getAttribute("href"), "/auth/login");
  } finally {
    await providerOnlyContext.close();
  }

  const directProviderContext = await browserInstance.newContext();
  try {
    const directProviderPage = await directProviderContext.newPage();
    await signInPortalAndPrimaryRP(directProviderPage, directProviderContext);
    await directProviderContext.clearCookies({ name: "shauth_session" });
    await directProviderPage.goto("http://gateway-integration.localhost:5556/");
    await (await applicationSignOutControl(directProviderPage, "admin", "primary application")).click();
    await directProviderPage.waitForURL("http://gateway-integration.localhost:5556/auth/signed-out");
    assert.equal(await directProviderPage.getByRole("link", { name: "Sign in with Shauth", exact: true }).getAttribute("href"), "/auth/login");
  } finally {
    await directProviderContext.close();
  }
}

async function exerciseCorrelationCreationFailure(browserInstance, database) {
  const rpInitiatedContext = await browserInstance.newContext();
  let rpInitiatedSessionID = "";
  try {
    const page = await rpInitiatedContext.newPage();
    await signInPortalAndPrimaryRP(page, rpInitiatedContext);
    rpInitiatedSessionID = newestActiveShauthSessionID();
    const grantCount = queryShauth("SELECT count(*) FROM logout_correlation_grants");
    rejectLogoutCorrelationInserts();
    try {
      await page.goto("http://gateway-integration.localhost:5556/");
      await (await applicationSignOutControl(page, "admin", "primary application")).click();
      await page.waitForURL((url) => url.origin === "http://localhost:8080" && url.pathname === "/oauth/logout");
      await page.getByText("OAuth logout could not be correlated with an exact provider session").waitFor();
    } finally {
      allowLogoutCorrelationInserts();
    }
    assert.equal(activeShauthSession(rpInitiatedSessionID), "1", "RP-initiated correlation failure mutated the Shauth session without durable evidence");
    await waitForSessionStatus(rpInitiatedContext, "http://gateway-integration.localhost:5556", 401);
    assert.equal(queryShauth("SELECT count(*) FROM logout_correlation_grants"), grantCount, "failed correlation insert unexpectedly persisted a grant");
    assert.equal(queryGateway(database, "SELECT count(*) FROM oidc_gateway_sessions WHERE client_id='gateway-integration' AND revoked_at IS NULL"), "0", "RP-initiated correlation failure left the relying party authenticated");
  } finally {
    allowLogoutCorrelationInserts();
    revokeTestShauthSession(rpInitiatedSessionID);
    await rpInitiatedContext.close();
  }

  const providerCallbackContext = await browserInstance.newContext();
  let providerCallbackSessionID = "";
  try {
    const page = await providerCallbackContext.newPage();
    await signInPortalAndPrimaryRP(page, providerCallbackContext);
    providerCallbackSessionID = newestActiveShauthSessionID();
    await providerCallbackContext.clearCookies({ name: "shauth_session" });
    rejectLogoutCorrelationInserts();
    try {
      await page.goto("http://gateway-integration.localhost:5556/");
      await (await applicationSignOutControl(page, "admin", "primary application")).click();
      await page.waitForURL((url) => url.origin === "http://localhost:8080" && url.pathname === "/oauth/logout");
      await page.getByText("OAuth logout could not be correlated with an exact provider session").waitFor();
    } finally {
      allowLogoutCorrelationInserts();
    }
    assert.equal(activeShauthSession(providerCallbackSessionID), "1", "provider callback correlation failure mutated the Shauth session without durable evidence");
    await waitForSessionStatus(providerCallbackContext, "http://gateway-integration.localhost:5556", 401);
    assert.equal(queryGateway(database, "SELECT count(*) FROM oidc_gateway_sessions WHERE client_id='gateway-integration' AND revoked_at IS NULL"), "0", "provider callback correlation failure left the relying party authenticated");
  } finally {
    allowLogoutCorrelationInserts();
    revokeTestShauthSession(providerCallbackSessionID);
    await providerCallbackContext.close();
  }
}

function rejectLogoutCorrelationInserts() {
  queryShauth("ALTER TABLE logout_correlation_grants DROP CONSTRAINT IF EXISTS logout_correlation_test_reject; ALTER TABLE logout_correlation_grants ADD CONSTRAINT logout_correlation_test_reject CHECK (false) NOT VALID");
}

function allowLogoutCorrelationInserts() {
  queryShauth("ALTER TABLE logout_correlation_grants DROP CONSTRAINT IF EXISTS logout_correlation_test_reject");
}

async function signInPortalAndPrimaryRP(page, context) {
  await page.goto("http://localhost:8080/login");
  await page.locator("#username").fill("admin");
  await page.locator("#password").fill(password);
  await page.getByRole("button", { name: "Sign in with password" }).click();
  await page.waitForURL("http://localhost:8080/");
  await page.goto("http://gateway-integration.localhost:5556/auth/login");
  await page.waitForURL("http://gateway-integration.localhost:5556/");
  await assertSession(context, "http://gateway-integration.localhost:5556", 200);
}

async function interruptProviderStart(page, context) {
  await page.goto("http://localhost:8080/logout");
  const csrf = (await context.cookies("http://localhost:8080/logout")).find((candidate) => candidate.name === "shauth_csrf");
  assert.ok(csrf, "Shauth logout page did not issue a CSRF cookie");
  const body = new URLSearchParams({ _csrf: csrf.value });
  const response = await context.request.post("http://localhost:8080/logout", {
    data: body.toString(),
    headers: {
      origin: "http://localhost:8080",
      "content-type": "application/x-www-form-urlencoded;charset=UTF-8",
    },
    maxRedirects: 0,
  });
  const responseBody = response.status() === 303 ? "" : await response.text();
  const diagnostic = JSON.stringify({
    status: response.status(),
    body: responseBody.slice(0, 200),
    origin: "http://localhost:8080",
    contentType: "application/x-www-form-urlencoded;charset=UTF-8",
    cookieTokenLength: csrf.value.length,
    formTokenLength: body.get("_csrf")?.length ?? 0,
    tokenLengthsMatch: csrf.value.length === (body.get("_csrf")?.length ?? 0),
  });
  assert.equal(response.status(), 303, diagnostic);
  assert.equal(response.headers().location, "/oauth2/sessions/logout");
  const cookie = (await context.cookies("http://localhost:8080/oauth/logout")).find((candidate) => candidate.name === "shauth_logout_correlation");
  assert.ok(cookie, "logout correlation cookie was not created");
  assert.equal(cookie.httpOnly, true);
  assert.equal(cookie.path, "/oauth/logout");
  assert.equal(cookie.sameSite, "Lax");
  return cookie;
}

function activeShauthSessionCount() {
  return queryShauth("SELECT count(*) FROM sessions JOIN users ON users.id=sessions.user_id WHERE users.username='admin' AND sessions.revoked_at IS NULL");
}

function newestActiveShauthSessionID() {
  const sessionID = queryShauth("SELECT sessions.id::text FROM sessions JOIN users ON users.id=sessions.user_id WHERE users.username='admin' AND sessions.revoked_at IS NULL ORDER BY sessions.created_at DESC,sessions.id DESC LIMIT 1");
  assert.match(sessionID, /^[0-9a-f-]{36}$/, "active Shauth session ID is unavailable");
  return sessionID;
}

function activeShauthSession(sessionID) {
  assert.match(sessionID, /^[0-9a-f-]{36}$/);
  return queryShauth(`SELECT count(*) FROM sessions WHERE id='${sessionID}'::uuid AND revoked_at IS NULL`);
}

function revokeTestShauthSession(sessionID) {
  if (!sessionID) return;
  assert.match(sessionID, /^[0-9a-f-]{36}$/);
  queryShauth(`WITH revoked AS (UPDATE sessions SET revoked_at=now() WHERE id='${sessionID}'::uuid AND revoked_at IS NULL RETURNING refresh_family_id) UPDATE refresh_tokens SET revoked_at=now() WHERE family_id IN (SELECT refresh_family_id FROM revoked) AND revoked_at IS NULL`);
}

async function waitForQuery(query, expected) {
  let actual = "";
  for (let attempt = 0; attempt < 120; attempt += 1) {
    actual = queryShauth(query);
    if (actual === expected) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  assert.equal(actual, expected, `query did not reach expected value: ${query}`);
}

async function waitForFile(file, timeout) {
  const deadline = Date.now() + timeout;
  while (!existsSync(file) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  assert.equal(existsSync(file), true, `timed out waiting for ${file}`);
}

async function createUpstream(port, title, releaseRevision) {
  let latestIdentity;
  const server = http.createServer((request, response) => {
    const username = request.headers["x-forwarded-preferred-username"] ?? "";
    const email = request.headers["x-forwarded-email"] ?? "";
    const role = request.headers["x-forwarded-role"] ?? "";
    latestIdentity = {
      subject: request.headers["x-forwarded-subject"],
      username: request.headers["x-forwarded-preferred-username"],
      email: request.headers["x-forwarded-email"],
      role: request.headers["x-forwarded-role"],
      authorization: request.headers.authorization,
    };
    response.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
      "x-frame-options": "SAMEORIGIN",
    });
    response.end(`<!doctype html><html lang=en><title>${title}</title><h1>${title}</h1><details><summary data-shauth-user="${escapeHTML(username)}">${escapeHTML(username)}</summary><form method=post action=/auth/logout><button data-shauth-sign-out>Sign out</button></form></details><dl><dt>Username</dt><dd data-testid=validation-username>${escapeHTML(username)}</dd><dt>Email</dt><dd data-testid=validation-email>${escapeHTML(email)}</dd><dt>Role</dt><dd data-testid=validation-role>${escapeHTML(role)}</dd><dt>Release</dt><dd data-testid=validation-release>${releaseRevision}</dd></dl></html>`);
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
  return {
    server,
    identity: () => latestIdentity,
    resetIdentity: () => { latestIdentity = undefined; },
  };
}

function escapeHTML(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function queryGateway(database, query) {
  return execFileSync(
    "docker",
    ["compose", "exec", "-T", "postgres", "psql", "-U", "shauth", "-d", database, "-Atc", query],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        SHAUTH_VALIDATOR_TOKEN: "unused-compose-interpolation-value",
        SHAUTH_VALIDATION_STATUS_TOKEN: "unused-compose-interpolation-value",
      },
    },
  ).trim();
}

function queryShauth(query) {
  return queryGateway("shauth", query);
}

async function waitForLogoutTokenCount(database, expected) {
  let count = 0;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    count = countLogoutTokens(database);
    if (count === expected) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  assert.equal(count, expected, `${database} must validate every provider logout token`);
}

function countLogoutTokens(database) {
  return Number(queryGateway(database, "SELECT count(*) FROM oidc_gateway_logout_tokens"));
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

async function signInFromLocalTerminal(page, applicationOrigin) {
  await page.goto(`${applicationOrigin}/`);
  await page.waitForURL(`${applicationOrigin}/auth/signed-out`);
  const signIn = page.getByRole("link", { name: "Sign in with Shauth", exact: true });
  assert.equal(await signIn.getAttribute("href"), "/auth/login");
  await signIn.click();
  await page.waitForURL(`${applicationOrigin}/`);
}

function sanitizeURL(value) {
  const parsed = new URL(value);
  return `${parsed.origin}${parsed.pathname}`;
}

async function assertSession(context, applicationOrigin, expectedStatus) {
  const result = await browserSession(context, applicationOrigin);
  assert.equal(result.status, expectedStatus);
  if (expectedStatus === 200) assert.deepEqual(result.session, {
    subject: result.session.subject,
    username: "admin",
    email: "admin@localhost.test",
    role: "admin",
  });
}

async function waitForSessionStatus(context, applicationOrigin, expectedStatus) {
  let actualStatus = 0;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    actualStatus = (await browserSession(context, applicationOrigin)).status;
    if (actualStatus === expectedStatus) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  assert.equal(actualStatus, expectedStatus, `${applicationOrigin} session did not reach expected status`);
}

async function browserSession(context, applicationOrigin) {
  const probe = await context.newPage();
  try {
    const response = await probe.goto(`${applicationOrigin}/auth/session`);
    assert.ok(response, `${applicationOrigin} session request produced no browser response`);
    return {
      status: response.status(),
      session: response.status() === 200 ? await response.json() : undefined,
    };
  } finally {
    await probe.close();
  }
}

async function gatewayRequest(context, method, resource, options = {}) {
  const publicURL = new URL(resource);
  const requestURL = new URL(resource);
  requestURL.hostname = "127.0.0.1";
  const cookies = await context.cookies(publicURL.origin);
  const headers = {
    ...options.headers,
    host: publicURL.host,
  };
  if (cookies.length > 0) headers.cookie = cookies.map(({ name, value }) => `${name}=${value}`).join("; ");
  return context.request.fetch(requestURL.toString(), {
    ...options,
    method,
    headers,
  });
}
