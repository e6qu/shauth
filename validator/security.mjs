// SPDX-License-Identifier: AGPL-3.0-or-later

const maximumEncodingDepth = 4;
const canonicalLoginFields = ["_csrf", "next", "password", "username"];
const credentialVariantCache = new Map();
const encodingVariantCache = new Map();

function encodingVariants(secret) {
  const cacheKey = String(secret ?? "");
  const cached = encodingVariantCache.get(cacheKey);
  if (cached) return cached;
  const seen = new Set();
  let frontier = [cacheKey].filter(Boolean);
  for (let depth = 0; depth <= maximumEncodingDepth && frontier.length > 0; depth += 1) {
    const next = [];
    for (const value of frontier) {
      if (seen.has(value)) continue;
      seen.add(value);
      const percentEncoded = encodeURIComponent(value);
      const formEncoded = new URLSearchParams({ value }).toString().slice("value=".length);
      const base64 = Buffer.from(value, "utf8").toString("base64");
      const base64URL = Buffer.from(value, "utf8").toString("base64url");
      for (const encoded of [percentEncoded, percentEncoded.toLowerCase(), formEncoded, formEncoded.toLowerCase(), base64, base64URL]) {
        if (encoded && !seen.has(encoded)) next.push(encoded);
      }
    }
    frontier = next;
  }
  const result = [...seen].sort((left, right) => right.length - left.length);
  encodingVariantCache.set(cacheKey, result);
  return result;
}

function credentialVariants(username, password) {
  const cacheKey = JSON.stringify([username, password]);
  const cached = credentialVariantCache.get(cacheKey);
  if (cached) return cached;
  const variants = new Set();
  const seeds = [username, password].filter(Boolean);
  if (username && password) seeds.push(`${username}:${password}`);
  for (const seed of seeds) {
    for (const value of encodingVariants(seed)) variants.add(value);
  }
  const result = [...variants].sort((left, right) => right.length - left.length);
  credentialVariantCache.set(cacheKey, result);
  return result;
}

function containsCredentialMaterial(value, username, password) {
  const text = String(value ?? "");
  return credentialVariants(username, password).some((candidate) => text.includes(candidate));
}

function headerValue(headers, wantedName) {
  return Object.entries(headers).find(([name]) => name.toLowerCase() === wantedName)?.[1] ?? "";
}

function safeRelativeNext(value, shauthURL) {
  if (!value.startsWith("/") || value.startsWith("//") || value.includes("\\") || value.includes("\0")) return false;
  let target;
  try {
    target = new URL(value, shauthURL);
  } catch {
    return false;
  }
  const provider = new URL(shauthURL);
  return target.origin === provider.origin
    && target.username === ""
    && target.password === ""
    && target.hash === ""
    && `${target.pathname}${target.search}` === value;
}

export function redactCredentialMaterial(value, secrets) {
  let redacted = String(value ?? "");
  const variants = new Set();
  for (const secret of secrets) {
    for (const candidate of encodingVariants(secret)) variants.add(candidate);
  }
  for (const candidate of [...variants].sort((left, right) => right.length - left.length)) {
    redacted = redacted.replaceAll(candidate, "[redacted]");
  }
  return redacted;
}

export function boundedFailureWithLatestTrace(prefix, trace, maximumLength = 1000) {
  if (!Number.isInteger(maximumLength) || maximumLength < 1) throw new Error("maximum failure length must be a positive integer");
  const boundedPrefix = String(prefix ?? "").slice(0, Math.min(450, maximumLength));
  const separator = "; flow: ";
  let remaining = maximumLength - boundedPrefix.length - separator.length;
  if (remaining <= 0) return boundedPrefix;
  const latestEvents = [];
  for (const rawEvent of [...trace].slice(-60).reverse()) {
    const event = String(rawEvent ?? "");
    const required = event.length + (latestEvents.length === 0 ? 0 : 3);
    if (required > remaining) break;
    latestEvents.unshift(event);
    remaining -= required;
  }
  return latestEvents.length === 0 ? boundedPrefix : `${boundedPrefix}${separator}${latestEvents.join(" | ")}`;
}

export function credentialRequestViolation(request, shauthURL, username, password) {
  const url = new URL(request.url);
  const headers = request.headers ?? {};
  const body = request.body ?? "";
  const headerText = Object.entries(headers).flat().join("\n");
  const urlHasCredentials = containsCredentialMaterial(url.toString(), username, password);
  const headersHaveCredentials = containsCredentialMaterial(headerText, username, password);
  const bodyHasCredentials = containsCredentialMaterial(body, username, password);
  if (!urlHasCredentials && !headersHaveCredentials && !bodyHasCredentials) return "";

  const expected = new URL("/login", shauthURL);
  const contentType = headerValue(headers, "content-type").split(";", 1)[0].trim().toLowerCase();
  const origin = headerValue(headers, "origin");
  if (urlHasCredentials
    || headersHaveCredentials
    || request.method !== "POST"
    || url.toString() !== expected.toString()
    || contentType !== "application/x-www-form-urlencoded"
    || (origin !== expected.origin && origin !== "null")) {
    return "validation credentials attempted to leave the exact Shauth POST /login boundary";
  }

  const fields = new URLSearchParams(body);
  const fieldNames = [...fields.keys()].sort();
  const canonicalFields = fieldNames.length === canonicalLoginFields.length
    && fieldNames.every((name, index) => name === canonicalLoginFields[index]);
  const singleValues = canonicalLoginFields.every((name) => fields.getAll(name).length === 1);
  const csrf = fields.get("_csrf") ?? "";
  const next = fields.get("next") ?? "";
  const valid = canonicalFields
    && singleValues
    && fields.get("username") === username
    && fields.get("password") === password
    && /^[0-9a-f]{64}$/.test(csrf)
    && !containsCredentialMaterial(csrf, username, password)
    && safeRelativeNext(next, shauthURL)
    && !containsCredentialMaterial(next, username, password);
  return valid ? "" : "validation credentials attempted to leave the canonical Shauth login form boundary";
}

export function bootstrapRequestViolation(request, shauthURL, bootstrapTokens) {
  const tokens = bootstrapTokens.filter(Boolean);
  if (tokens.length === 0) return "";
  const url = new URL(request.url);
  const headers = request.headers ?? {};
  const body = request.body ?? "";
  const headerText = Object.entries(headers).flat().join("\n");
  const containsToken = (value) => tokens.some((token) => encodingVariants(token).some((candidate) => String(value ?? "").includes(candidate)));
  const urlHasToken = containsToken(url.toString());
  const headersHaveToken = containsToken(headerText);
  const bodyHasToken = containsToken(body);
  if (!urlHasToken && !headersHaveToken && !bodyHasToken) return "";

  const expected = new URL("/validator/bootstrap", shauthURL);
  const contentType = headerValue(headers, "content-type").split(";", 1)[0].trim().toLowerCase();
  const origin = headerValue(headers, "origin");
  if (urlHasToken
    || headersHaveToken
    || request.method !== "POST"
    || url.toString() !== expected.toString()
    || contentType !== "application/x-www-form-urlencoded"
    || (origin !== expected.origin && origin !== "null")) {
    return "validation browser bootstrap attempted to leave the exact Shauth POST /validator/bootstrap boundary";
  }
  const fields = new URLSearchParams(body);
  const names = [...fields.keys()].sort();
  const canonicalFields = names.length === 2 && names[0] === "_csrf" && names[1] === "token";
  const csrf = fields.get("_csrf") ?? "";
  const token = fields.get("token") ?? "";
  const valid = canonicalFields
    && fields.getAll("_csrf").length === 1
    && fields.getAll("token").length === 1
    && /^[0-9a-f]{64}$/.test(csrf)
    && !containsToken(csrf)
    && tokens.includes(token);
  return valid ? "" : "validation browser bootstrap attempted to leave the canonical Shauth bootstrap form boundary";
}

export async function installCredentialBoundary(context, shauthURL, username, password, onViolation = () => {}, bootstrapTokens = []) {
  await context.route("**/*", async (route) => {
    const request = route.request();
    const observed = {
      method: request.method(),
      url: request.url(),
      headers: await request.allHeaders(),
      body: request.postData() ?? "",
    };
    const violation = credentialRequestViolation(observed, shauthURL, username, password)
      || bootstrapRequestViolation(observed, shauthURL, bootstrapTokens);
    if (violation) {
      onViolation(violation);
      await route.abort("blockedbyclient");
      return;
    }
    await route.continue();
  });
}
