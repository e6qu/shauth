// SPDX-License-Identifier: AGPL-3.0-or-later

export function requiredShauthPublicURL(environment = process.env) {
  const raw = environment.SHAUTH_URL;
  if (!raw) throw new Error("SHAUTH_URL is required");
  const parsed = new URL(raw);
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new Error("SHAUTH_URL must be an HTTP(S) origin without credentials, path, query, or fragment");
  }
  return parsed.origin;
}
