// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFile } from "node:fs/promises";
import http from "node:http";
import { chromium } from "playwright";

const cookieJarPath = process.argv[2];
if (!cookieJarPath) throw new Error("cookie jar path is required");

const cookies = (await readFile(cookieJarPath, "utf8"))
  .split("\n")
  .filter((line) => line && (!line.startsWith("#") || line.startsWith("#HttpOnly_")))
  .map((line) => {
    const httpOnly = line.startsWith("#HttpOnly_");
    const fields = line.replace(/^#HttpOnly_/, "").split("\t");
    if (fields.length !== 7) throw new Error("cookie jar contains an invalid record");
    const [domain, , path, secure, expires, name, value] = fields;
    const cookie = { name, value, domain: domain.replace(/^\./, ""), path, secure: secure === "TRUE", httpOnly };
    if (Number(expires) > 0) cookie.expires = Number(expires);
    return cookie;
  });

if (!cookies.some((cookie) => cookie.name === "shauth_session")) throw new Error("Shauth browser session cookie is unavailable");

const upstream = http.createServer((_request, response) => {
  response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  response.end("<!doctype html><html lang=en><title>Primary application</title><h1>Primary application</h1></html>");
});
await new Promise((resolve, reject) => {
  upstream.once("error", reject);
  upstream.listen(5557, "127.0.0.1", resolve);
});

const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext();
  await context.addCookies(cookies);
  const page = await context.newPage();
  await page.goto("http://gateway-integration.localhost:5556/auth/login", { waitUntil: "domcontentloaded" });
  await page.waitForURL("http://gateway-integration.localhost:5556/", { timeout: 30_000 });
  await page.getByRole("heading", { name: "Primary application", exact: true }).waitFor({ state: "visible" });
  const authenticatedSession = await browserResponse(context, "http://gateway-integration.localhost:5556/auth/session");
  if (authenticatedSession.status() !== 200) throw new Error("relying-party browser session was not established");
  await page.goto("http://localhost:8080/logout", { waitUntil: "domcontentloaded" });
  await page.getByRole("button", { name: "Sign out of all apps", exact: true }).click();
  await page.waitForURL("http://localhost:8080/signed-out", { timeout: 30_000 });
  await page.getByRole("link", { name: "Sign in to Shauth", exact: true }).waitFor({ state: "visible" });
  await page.goto("http://gateway-integration.localhost:5556/", { waitUntil: "domcontentloaded" });
  await page.waitForURL("http://gateway-integration.localhost:5556/auth/signed-out", { timeout: 30_000 });
  await page.getByRole("link", { name: "Sign in with Shauth", exact: true }).waitFor({ state: "visible" });
  const revokedSession = await browserResponse(context, "http://gateway-integration.localhost:5556/auth/session");
  if (revokedSession.status() !== 401) throw new Error("relying-party browser session remained active after global logout");
} finally {
  await browser.close();
  await new Promise((resolve) => upstream.close(resolve));
}

async function browserResponse(context, url) {
  const probe = await context.newPage();
  try {
    const response = await probe.goto(url, { waitUntil: "domcontentloaded" });
    if (!response) throw new Error(`${url} produced no browser response`);
    return response;
  } finally {
    await probe.close();
  }
}
