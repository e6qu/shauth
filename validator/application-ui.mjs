// SPDX-License-Identifier: AGPL-3.0-or-later

export async function assertApplicationIdentity(page, expectedUsername, appSlug) {
  const identity = page.locator("[data-shauth-user]").first();
  await identity.waitFor({ state: "visible", timeout: 30_000 });
  const observed = (await identity.getAttribute("data-shauth-user"))?.trim() ?? "";
  if (observed !== expectedUsername) {
    throw new Error(`${appSlug} launch UI did not expose the authenticated Shauth identity`);
  }
  return identity;
}

export async function applicationSignOutControl(page, expectedUsername, appSlug) {
  const identity = await assertApplicationIdentity(page, expectedUsername, appSlug);
  const signOut = page.locator("[data-shauth-sign-out]").first();
  if (!(await signOut.isVisible().catch(() => false))) {
    await identity.click();
  }
  await signOut.waitFor({ state: "visible", timeout: 30_000 });
  const tagName = await signOut.evaluate((element) => element.tagName);
  if (tagName !== "A" && tagName !== "BUTTON") {
    throw new Error(`${appSlug} launch UI Shauth sign-out control is not actionable`);
  }
  return signOut;
}
