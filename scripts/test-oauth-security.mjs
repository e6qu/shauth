// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise the real Hydra authorization endpoint; no provider responses are simulated.
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { requiredShauthPublicURL } from './test-public-url.mjs';

const issuer = requiredShauthPublicURL();
const admin = 'http://localhost:4445';
const clientID = `security-pkce-${randomUUID()}`;
const callback = 'http://localhost:5555/security-callback';
const request = (url, options = {}) => fetch(url, { ...options, redirect: 'manual', signal: AbortSignal.timeout(15000) });
const registration = await request(`${admin}/admin/clients`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ client_id: clientID, token_endpoint_auth_method: 'none', grant_types: ['authorization_code'], response_types: ['code'], redirect_uris: [callback], scope: 'openid' }),
});
assert.equal(registration.status, 201, 'Register the real public security-test client');
try {
  const discovery = await (await request(`${issuer}/.well-known/openid-configuration`)).json();
  assert.deepEqual(discovery.code_challenge_methods_supported, ['S256']);
  const verifier = randomBytes(32).toString('base64url');
  for (const [label, fields] of [
    ['missing PKCE', {}],
    ['plain PKCE', { code_challenge: verifier, code_challenge_method: 'plain' }],
    ['implicit plain PKCE', { code_challenge: verifier }],
  ]) {
    const params = new URLSearchParams({ client_id: clientID, redirect_uri: callback, response_type: 'code', scope: 'openid', state: randomUUID(), ...fields });
    const result = await request(`${issuer}/oauth2/auth?${params}`);
    const target = new URL(result.headers.get('location') ?? '', issuer);
    assert.equal(target.origin + target.pathname, callback, `${label}: reject through the exact registered callback`);
    assert.equal(target.searchParams.get('error'), 'invalid_request', `${label}: authorization must fail before login`);
  }
  const params = new URLSearchParams({ client_id: clientID, redirect_uri: callback, response_type: 'code', scope: 'openid', state: randomUUID(), code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' });
  const result = await request(`${issuer}/oauth2/auth?${params}`);
  const target = new URL(result.headers.get('location') ?? '', issuer);
  assert.equal(target.origin, new URL(issuer).origin);
  assert.equal(target.pathname, '/oauth/login');
  assert.ok(target.searchParams.get('login_challenge'), 'S256 proceeds to real sign-in');
  for (const path of ['/login', '/signed-out']) {
    const response = await request(`${issuer}${path}`);
    assert.match(response.headers.get('cache-control') ?? '', /no-store/, `${path}: authentication pages must not be cached`);
  }
  const asset = await request(`${issuer}/assets/theme.js`);
  assert.equal(asset.status, 200);
  assert.equal(asset.headers.get('set-cookie'), null, 'A public cacheable asset must not mint browser state');
  console.log('Real OAuth security checks passed: public PKCE required, S256 accepted, plain refused, sensitive pages uncacheable, static assets cookie-free');
} finally {
  const removed = await request(`${admin}/admin/clients/${clientID}`, { method: 'DELETE' });
  assert.equal(removed.status, 204, 'Remove the security-test client');
}
