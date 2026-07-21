// SPDX-License-Identifier: AGPL-3.0-or-later
import { chromium } from "playwright";
import { boundedFailureWithLatestTrace, installCredentialBoundary, redactCredentialMaterial } from "./security.mjs";

const input = await new Promise((resolve, reject) => {
  let body = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => { body += chunk; });
  process.stdin.on("end", () => resolve(body));
  process.stdin.on("error", reject);
});

const job = JSON.parse(input);
const username = process.env.SHAUTH_VALIDATION_USERNAME;
const email = process.env.SHAUTH_VALIDATION_EMAIL;
if (!username || !email) throw new Error("validation account identity is unavailable");
if (!Array.isArray(job.bootstrap_urls) || job.bootstrap_urls.length !== 2) throw new Error("validation browser bootstraps are unavailable");
const bootstrapTokens = job.bootstrap_urls.map((rawURL) => new URL(rawURL).hash.slice(1));
if (bootstrapTokens.some((token) => !/^[0-9a-f]{64}$/.test(token)) || new Set(bootstrapTokens).size !== bootstrapTokens.length) {
  throw new Error("validation browser bootstraps are invalid");
}
let nextBootstrap = 0;
let validationStage = "initialize validator";

function sameOrigin(actual, expected) {
  return new URL(actual).origin === new URL(expected).origin;
}

function sanitizeFailure(value) {
  return redactCredentialMaterial(value, [username, ...bootstrapTokens])
    .replace(/([?&](?:code|state|token|challenge|consent_challenge|login_challenge|logout_challenge|login_verifier|consent_verifier|logout_verifier|id_token_hint|logout_hint|access_token|refresh_token|device_code)=)[^&\s]+/gi, "$1[redacted]");
}

function formatFailure(stage, detail, trace) {
  return boundedFailureWithLatestTrace(
    sanitizeFailure(`${stage}: ${detail}`),
    trace.map((event) => sanitizeFailure(event)),
  );
}

function signInControl(page) {
  return page.getByRole("link", { name: "Sign in with Shauth", exact: true })
    .or(page.getByRole("button", { name: "Sign in with Shauth", exact: true })).first();
}

function signOutControl(page) {
  return page.getByRole("button", { name: "Sign out", exact: true })
    .or(page.getByRole("link", { name: "Sign out", exact: true })).first();
}

function assertAuthorizationClient(providerTrace, start, expectedClientID, failure) {
  const observed = providerTrace.authorizationClientIDs.slice(start);
  if (observed.length === 0) throw new Error(`${failure}; no Shauth authorization request was observed`);
  if (observed.some((clientID) => clientID !== expectedClientID)) {
    throw new Error(`${failure}; expected OpenID Connect client ${expectedClientID}`);
  }
}

async function waitForRegisteredURL(page, predicate, failure) {
  try {
    await page.waitForURL(predicate, { timeout: 30_000 });
  } catch {
    const coordinate = new URL(page.url());
    throw new Error(`${failure}; browser stopped at ${coordinate.origin}${coordinate.pathname}`);
  }
}

async function waitForApplicationReady(page, registeredURL, failure) {
  await waitForRegisteredURL(page, (value) => sameOrigin(value.toString(), registeredURL), failure);
  try {
    await page.waitForLoadState("networkidle", { timeout: 30_000 });
  } catch {
    const coordinate = new URL(page.url());
    throw new Error(`${failure}; application did not become browser-ready at ${coordinate.origin}${coordinate.pathname}`);
  }
}

function assertExactCoordinate(page, expected, failure) {
  if (page.url() === expected) return;
  const observed = new URL(page.url());
  throw new Error(`${failure}; browser stopped at ${observed.origin}${observed.pathname}`);
}

async function waitForShauthLogin(page) {
  await waitForRegisteredURL(page, (value) => sameOrigin(value.toString(), job.shauth_url) && value.pathname === "/login", "browser did not reach the exact Shauth login page");
  const form = page.locator('form[action="/login"]').filter({ has: page.getByRole("button", { name: "Sign in with password", exact: true }) }).first();
  await form.waitFor({ state: "visible", timeout: 30_000 });
  const action = new URL(await form.getAttribute("action"), page.url());
  if (!sameOrigin(action.toString(), job.shauth_url) || action.pathname !== "/login" || (await form.getAttribute("method"))?.toLowerCase() !== "post") {
    throw new Error("Shauth credential form target is invalid");
  }
  return form;
}

async function assertValidationIdentity(page, appSlug) {
  const expected = {
    "validation-username": username,
    "validation-email": email,
    "validation-role": "developer",
    "validation-release": appSlug === job.app_slug ? job.release_revision : job.witness?.release_revision,
  };
  for (const [testID, value] of Object.entries(expected)) {
    if (!value) throw new Error(`${appSlug} validation contract omitted ${testID}`);
    const field = page.getByTestId(testID);
    await field.waitFor({ state: "visible", timeout: 30_000 });
    if ((await field.textContent())?.trim() !== value) {
      throw new Error(`${appSlug} ${testID} did not match its validation contract`);
    }
  }
}

async function completeAuthorizationAtShauth(page, authorizationURL) {
  const login = new URL(authorizationURL);
  if (!sameOrigin(login.toString(), job.shauth_url) || login.pathname !== "/login") throw new Error("authorization login coordinate is invalid");
  const next = login.searchParams.get("next") ?? "";
  const continuation = new URL(next, job.shauth_url);
  if (!next.startsWith("/") || next.startsWith("//") || next.includes("\\") || continuation.origin !== new URL(job.shauth_url).origin || continuation.hash !== "" || `${continuation.pathname}${continuation.search}` !== next) {
    throw new Error("authorization continuation is invalid");
  }
  await page.goto(continuation.toString(), { waitUntil: "domcontentloaded" });
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (!sameOrigin(page.url(), job.shauth_url)) {
      await waitForApplicationReady(page, job.launch_url, "authorization did not finish loading the application");
      return;
    }
    const authorize = page.getByRole("button", { name: "Authorize application", exact: true });
    if (await authorize.isVisible().catch(() => false)) {
      await authorize.click();
    }
    await page.waitForTimeout(250);
  }
  throw new Error(`authorization did not leave Shauth (${new URL(page.url()).pathname})`);
}

async function consumeBootstrap(page, expectedPath) {
  if (nextBootstrap >= job.bootstrap_urls.length) throw new Error("validation browser bootstrap budget was exhausted");
  const bootstrapURL = job.bootstrap_urls[nextBootstrap];
  nextBootstrap += 1;
  await page.goto(bootstrapURL, { waitUntil: "domcontentloaded" });
  await waitForRegisteredURL(page, (value) => sameOrigin(value.toString(), job.shauth_url) && value.pathname === expectedPath, "Shauth did not establish the one-time validation browser session");
}

async function assertAnonymousValidationFailsClosed(browser) {
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await page.goto(job.validation_url, { waitUntil: "domcontentloaded" });
    if (page.url() === job.signed_out_url) {
      await signInControl(page).waitFor({ state: "visible", timeout: 30_000 });
      return;
    }
    if (sameOrigin(page.url(), job.shauth_url)) {
      await waitForShauthLogin(page);
      return;
    }
    throw new Error(`${job.app_slug} exposed its authenticated validation page without a Shauth session`);
  } finally {
    await context.close();
  }
}

async function establishWitnessSession(context, providerTrace) {
  validationStage = `establish ${job.witness.app_slug} witness session`;
  const witnessPage = await context.newPage();
  const authorizationCount = providerTrace.authorizationClientIDs.length;
  await witnessPage.goto(job.witness.launch_url, { waitUntil: "domcontentloaded" });
  if (witnessPage.url() === job.witness.signed_out_url) {
    await signInControl(witnessPage).click();
  } else if (!sameOrigin(witnessPage.url(), job.shauth_url) && !sameOrigin(witnessPage.url(), job.witness.launch_url)) {
    throw new Error(`${job.witness.app_slug} witness direct entry escaped its registered origins`);
  }
  for (let attempt = 0; attempt < 120 && !sameOrigin(witnessPage.url(), job.witness.launch_url); attempt += 1) {
    const coordinate = new URL(witnessPage.url());
    if (sameOrigin(coordinate.toString(), job.shauth_url) && coordinate.pathname === "/login") {
      throw new Error(`${job.witness.app_slug} witness requested credentials instead of using the Shauth SSO session`);
    }
    await witnessPage.waitForTimeout(250);
  }
  if (!sameOrigin(witnessPage.url(), job.witness.launch_url)) throw new Error(`${job.witness.app_slug} witness did not complete Shauth SSO`);
  await waitForApplicationReady(witnessPage, job.witness.launch_url, `${job.witness.app_slug} witness did not become browser-ready`);
  assertAuthorizationClient(providerTrace, authorizationCount, job.witness.oidc_client_id, `${job.witness.app_slug} witness used the wrong Shauth registration`);
  await witnessPage.goto(job.witness.validation_url, { waitUntil: "domcontentloaded" });
  assertExactCoordinate(witnessPage, job.witness.validation_url, `${job.witness.app_slug} witness did not expose its exact authenticated validation URL`);
  await assertValidationIdentity(witnessPage, job.witness.app_slug);
  await signOutControl(witnessPage).waitFor({ state: "visible", timeout: 30_000 });
  return witnessPage;
}

async function assertWitnessRevoked(witnessPage) {
  validationStage = `verify ${job.witness.app_slug} witness revocation`;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    await witnessPage.goto(job.witness.validation_url, { waitUntil: "domcontentloaded" });
    if (witnessPage.url() === job.witness.signed_out_url) {
      await signInControl(witnessPage).waitFor({ state: "visible", timeout: 30_000 });
      return;
    }
    await witnessPage.waitForTimeout(250);
  }
  throw new Error(`${job.witness.app_slug} witness session remained authenticated after global logout`);
}

async function assertAppSignedInAndGlobalLogout(page, context, providerTrace) {
  validationStage = `verify ${job.app_slug} authenticated page`;
  if (!sameOrigin(page.url(), job.launch_url)) throw new Error(`browser did not reach ${job.app_slug}`);
  await waitForApplicationReady(page, job.launch_url, `${job.app_slug} did not become browser-ready`);
  await page.goto(job.validation_url, { waitUntil: "domcontentloaded" });
  assertExactCoordinate(page, job.validation_url, `${job.app_slug} did not expose its exact authenticated validation URL`);
  await assertValidationIdentity(page, job.app_slug);
  await signOutControl(page).waitFor({ state: "visible", timeout: 30_000 });
  const witnessPage = await establishWitnessSession(context, providerTrace);
  validationStage = `sign out ${job.app_slug} through Shauth`;
  const logoutCount = providerTrace.logout;
  await signOutControl(page).click();
  await waitForRegisteredURL(page, (value) => value.toString() === job.signed_out_url, `${job.app_slug} global logout did not return to its exact local signed-out page`);
  if (providerTrace.logout <= logoutCount) throw new Error(`${job.app_slug} sign out did not use Shauth global logout`);
  await signInControl(page).waitFor({ state: "visible", timeout: 30_000 });
  await page.reload({ waitUntil: "domcontentloaded" });
  await signInControl(page).waitFor({ state: "visible", timeout: 30_000 });
  await assertWitnessRevoked(witnessPage);

  validationStage = "verify Shauth browser session revocation";
  const providerPage = await context.newPage();
  await providerPage.goto(`${job.shauth_url.replace(/\/$/, "")}/apps`, { waitUntil: "domcontentloaded" });
  await waitForShauthLogin(providerPage);
  await providerPage.close();
  await witnessPage.close();

  const authorizationCount = providerTrace.authorizationClientIDs.length;
  validationStage = `reauthenticate ${job.app_slug} through its local sign-in control`;
  await signInControl(page).click();
  await waitForShauthLogin(page);
  const authorizationURL = page.url();
  assertAuthorizationClient(providerTrace, authorizationCount, job.oidc_client_id, `${job.app_slug} sign-in control used the wrong Shauth registration`);
  await consumeBootstrap(page, "/");
  await completeAuthorizationAtShauth(page, authorizationURL);
  await page.goto(job.validation_url, { waitUntil: "domcontentloaded" });
  assertExactCoordinate(page, job.validation_url, `${job.app_slug} did not restore its authenticated validation page`);
  await assertValidationIdentity(page, job.app_slug);
  await signOutControl(page).waitFor({ state: "visible", timeout: 30_000 });
  const providerLogoutWitnessPage = await establishWitnessSession(context, providerTrace);
  validationStage = `sign out at Shauth with an active ${job.app_slug} session`;
  const providerLogoutPage = await context.newPage();
  await providerLogoutPage.goto(`${job.shauth_url.replace(/\/$/, "")}/logout`, { waitUntil: "domcontentloaded" });
  await providerLogoutPage.getByRole("button", { name: "Sign out of all apps", exact: true }).click();
  await waitForRegisteredURL(providerLogoutPage, (value) => sameOrigin(value.toString(), job.shauth_url) && value.pathname === "/signed-out", "Shauth provider logout did not reach its signed-out page");
  await providerLogoutPage.getByRole("link", { name: "Sign in to Shauth", exact: true }).waitFor({ state: "visible", timeout: 30_000 });
  await providerLogoutPage.reload({ waitUntil: "domcontentloaded" });
  await providerLogoutPage.getByRole("link", { name: "Sign in to Shauth", exact: true }).waitFor({ state: "visible", timeout: 30_000 });
  await providerLogoutPage.close();

  validationStage = `verify Shauth provider logout revoked ${job.app_slug}`;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    await page.goto(job.validation_url, { waitUntil: "domcontentloaded" });
    if (page.url() === job.signed_out_url) break;
    await page.waitForTimeout(250);
  }
  if (page.url() !== job.signed_out_url) throw new Error(`${job.app_slug} remained authenticated after Shauth provider logout`);
  await signInControl(page).waitFor({ state: "visible", timeout: 30_000 });
  await page.reload({ waitUntil: "domcontentloaded" });
  await signInControl(page).waitFor({ state: "visible", timeout: 30_000 });
  await assertWitnessRevoked(providerLogoutWitnessPage);
  await providerLogoutWitnessPage.close();
}

const browser = await chromium.launch({ headless: true });
let credentialBoundaryFailure = "";
const flowTrace = [];
try {
  validationStage = `verify ${job.app_slug} fails closed for an anonymous browser`;
  await assertAnonymousValidationFailsClosed(browser);
  const context = await browser.newContext();
  const page = await context.newPage();
  await installCredentialBoundary(context, job.shauth_url, "", "", (violation) => {
    credentialBoundaryFailure = violation;
  }, bootstrapTokens);
  const providerTrace = { authorizationClientIDs: [], logout: 0 };
  context.on("request", (request) => {
    const coordinate = new URL(request.url());
    if (sameOrigin(coordinate.toString(), job.shauth_url)) {
      if (coordinate.pathname === "/oauth2/auth") providerTrace.authorizationClientIDs.push(coordinate.searchParams.get("client_id") ?? "");
      if (coordinate.pathname === "/oauth2/sessions/logout" || coordinate.pathname === "/oauth/logout") providerTrace.logout += 1;
    }
    if (isTrackedOrigin(coordinate)) flowTrace.push(`request ${request.method()} ${coordinate.origin}${coordinate.pathname}`);
  });
  context.on("response", (response) => {
    const coordinate = new URL(response.url());
    if (isTrackedOrigin(coordinate)) flowTrace.push(`response ${response.status()} ${coordinate.origin}${coordinate.pathname}`);
  });
  context.on("requestfailed", (request) => {
    const coordinate = new URL(request.url());
    if (isTrackedOrigin(coordinate)) flowTrace.push(`requestfailed ${request.method()} ${coordinate.origin}${coordinate.pathname} ${request.failure()?.errorText ?? "unknown"}`);
  });

  if (job.direction === "from_shauth") {
    validationStage = `open ${job.app_slug} from the Shauth catalog`;
    await page.goto(`${job.shauth_url.replace(/\/$/, "")}/login?next=/apps`, { waitUntil: "domcontentloaded" });
    await waitForShauthLogin(page);
    await consumeBootstrap(page, "/apps");
    const authorizationCount = providerTrace.authorizationClientIDs.length;
    await page.getByRole("link", { name: `Open ${job.app_name}`, exact: true }).click();
    await waitForApplicationReady(page, job.launch_url, `${job.app_slug} catalog launch did not reach a browser-ready application`);
    assertAuthorizationClient(providerTrace, authorizationCount, job.oidc_client_id, `${job.app_slug} catalog entry used the wrong Shauth registration`);
  } else if (job.direction === "from_app") {
    validationStage = `open ${job.app_slug} from its public origin`;
    const authorizationCount = providerTrace.authorizationClientIDs.length;
    await page.goto(job.launch_url, { waitUntil: "domcontentloaded" });
    if (page.url() === job.signed_out_url) {
      await signInControl(page).click();
    } else if (!sameOrigin(page.url(), job.shauth_url)) {
      throw new Error(`${job.app_slug} direct entry neither failed closed nor started Shauth authorization`);
    }
    await waitForShauthLogin(page);
    const authorizationURL = page.url();
    await consumeBootstrap(page, "/");
    await completeAuthorizationAtShauth(page, authorizationURL);
    assertAuthorizationClient(providerTrace, authorizationCount, job.oidc_client_id, `${job.app_slug} direct entry used the wrong Shauth registration`);
  } else {
    throw new Error(`unsupported direction ${job.direction}`);
  }
  await assertAppSignedInAndGlobalLogout(page, context, providerTrace);
  if (nextBootstrap !== job.bootstrap_urls.length) throw new Error("validation browser bootstrap budget was not consumed exactly once");
  process.stdout.write(JSON.stringify({ status: "passed", failure: "" }));
  await context.close();
} catch (error) {
  const detail = credentialBoundaryFailure || (error instanceof Error ? error.message : error);
  const message = formatFailure(validationStage, detail, flowTrace);
  process.stdout.write(JSON.stringify({ status: "failed", failure: message }));
} finally {
  await browser.close();
}

function isTrackedOrigin(coordinate) {
  return [job.shauth_url, job.launch_url, job.validation_url, job.signed_out_url, job.witness?.launch_url, job.witness?.validation_url, job.witness?.signed_out_url]
    .filter(Boolean)
    .some((value) => sameOrigin(coordinate.toString(), value));
}
