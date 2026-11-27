// SPDX-License-Identifier: AGPL-3.0-or-later
// Real browser, PostgreSQL and Hydra: the callback only receives real OAuth responses.
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { chromium } from 'playwright';
import { requiredShauthPublicURL } from './test-public-url.mjs';

const issuer = requiredShauthPublicURL();
const clientID = `security-pkce-${randomUUID()}`;
const password = process.env.SHAUTH_BOOTSTRAP_ADMIN_PASSWORD;
assert.ok(password, 'A real local acceptance account is required');
const request = (url, options = {}) => fetch(url, { ...options, redirect: 'manual', signal: AbortSignal.timeout(15000) });
const receiver = createServer((_request, response) => {
  response.writeHead(200, { 'content-type': 'text/html', 'cache-control': 'no-store' });
  response.end('<!doctype html><title>OAuth response received</title><p>OAuth response received.</p>');
});
await new Promise((resolve, reject) => { receiver.once('error', reject); receiver.listen(0, '127.0.0.1', resolve); });
const callback = `http://127.0.0.1:${receiver.address().port}/callback`;
const clientURL = `http://localhost:4445/admin/clients/${clientID}`;
let browser;
let registered = false;
try {
  const registration = await request('http://localhost:4445/admin/clients', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_id: clientID, token_endpoint_auth_method: 'none', grant_types: ['authorization_code'], response_types: ['code'], redirect_uris: [callback], scope: 'openid' }),
  });
  assert.equal(registration.status, 201, 'Register the real public security-test client');
  registered = true;
  const discovery = await (await request(`${issuer}/.well-known/openid-configuration`)).json();
  assert.deepEqual(discovery.code_challenge_methods_supported, ['S256']);
  browser = await chromium.launch({ headless: true, timeout: 20000 });
  const page = await browser.newPage();
  page.setDefaultTimeout(20000);
  await page.goto(`${issuer}/login`);
  await page.locator('#username').fill('admin');
  await page.locator('#password').fill(password);
  await page.getByRole('button', { name: 'Sign in with password' }).click();
  await page.waitForURL(`${issuer}/`);

  async function authorize(fields) {
    const state = randomUUID();
    const params = new URLSearchParams({ client_id: clientID, redirect_uri: callback, response_type: 'code', scope: 'openid', state, nonce: randomUUID(), ...fields });
    await page.goto(`${issuer}/oauth2/auth?${params}`);
    await page.waitForURL(url => url.pathname === '/oauth/consent' || url.origin + url.pathname === callback);
    if (new URL(page.url()).pathname === '/oauth/consent') {
      await page.getByRole('button', { name: 'Allow', exact: true }).click();
      await page.waitForURL(url => url.origin + url.pathname === callback);
    }
    const result = new URL(page.url());
    assert.equal(result.searchParams.get('state'), state);
    return result.searchParams;
  }
  const verifier = randomBytes(32).toString('base64url');
  for (const [label, fields] of [
    ['missing PKCE', {}],
    ['plain PKCE', { code_challenge: verifier, code_challenge_method: 'plain' }],
    ['implicit plain PKCE', { code_challenge: verifier }],
  ]) {
    const result = await authorize(fields);
    assert.equal(result.get('error'), 'invalid_request', `${label}: authorization must fail`);
    assert.equal(result.get('code'), null, `${label}: no authorization code may be issued`);
  }
  const fields = { code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' };
  async function exchange(code, proof) {
    return request(`${issuer}/oauth2/token`, { method: 'POST', body: new URLSearchParams({ grant_type: 'authorization_code', client_id: clientID, redirect_uri: callback, code, code_verifier: proof }) });
  }
  const wrongProofGrant = await authorize(fields);
  assert.ok(wrongProofGrant.get('code'), 'S256 issues an authorization code after real consent');
  const refused = await exchange(wrongProofGrant.get('code'), randomBytes(32).toString('base64url'));
  assert.equal(refused.status, 400, 'A mismatched verifier must not issue tokens');
  assert.equal((await refused.json()).error, 'invalid_grant');
  const validGrant = await authorize(fields);
  assert.ok(validGrant.get('code'));
  const accepted = await exchange(validGrant.get('code'), verifier);
  assert.equal(accepted.status, 200, 'A matching S256 verifier must issue real tokens');
  const tokens = await accepted.json();
  assert.ok(tokens.access_token && tokens.id_token);
  const replay = await exchange(validGrant.get('code'), verifier);
  assert.equal(replay.status, 400, 'An authorization code must not be redeemable twice');
  assert.equal((await replay.json()).error, 'invalid_grant');
  for (const path of ['/login', '/signed-out']) {
    const response = await request(`${issuer}${path}`);
    assert.match(response.headers.get('cache-control') ?? '', /no-store/, `${path}: authentication pages must not be cached`);
  }
  const asset = await request(`${issuer}/assets/theme.js`);
  assert.equal(asset.status, 200);
  assert.equal(asset.headers.get('set-cookie'), null, 'A public cacheable asset must not mint browser state');
  console.log('Real OAuth security checks passed: public PKCE required, S256 accepted, plain refused, verifier mismatch and code replay rejected, authentication pages uncacheable');
} finally {
  if (browser) await browser.close();
  receiver.closeAllConnections();
  await new Promise(resolve => receiver.close(resolve));
  if (registered) {
    const removed = await request(clientURL, { method: 'DELETE' });
    assert.equal(removed.status, 204, 'Remove the security-test client');
  }
}
