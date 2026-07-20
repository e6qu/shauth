// SPDX-License-Identifier: AGPL-3.0-or-later

export function isStrictOIDCIdentity(claims) {
  return typeof claims?.sub === "string" && claims.sub.length > 0
    && typeof claims.preferred_username === "string" && claims.preferred_username.length > 0
    && typeof claims.email === "string" && claims.email.length > 0
    && claims.email_verified === true
    && (claims.role === "admin" || claims.role === "developer");
}
