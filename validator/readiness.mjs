// SPDX-License-Identifier: AGPL-3.0-or-later

function sameOrigin(actual, expected) {
  return new URL(actual).origin === new URL(expected).origin;
}

export async function waitForRegisteredURL(page, predicate, failure, timeout = 30_000) {
  try {
    await page.waitForURL(predicate, { timeout });
  } catch {
    const coordinate = new URL(page.url());
    throw new Error(`${failure}; browser stopped at ${coordinate.origin}${coordinate.pathname}`);
  }
}

export async function waitForApplicationReady(page, registeredURL, failure, timeout = 30_000) {
  await waitForRegisteredURL(page, (value) => sameOrigin(value.toString(), registeredURL), failure, timeout);
  try {
    await page.waitForLoadState("domcontentloaded", { timeout });
    await page.locator("body").waitFor({ state: "visible", timeout });
  } catch {
    const coordinate = new URL(page.url());
    throw new Error(`${failure}; application did not become browser-ready at ${coordinate.origin}${coordinate.pathname}`);
  }
}
