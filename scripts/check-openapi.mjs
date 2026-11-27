// SPDX-License-Identifier: AGPL-3.0-or-later
// Validate the published contract against the actual registered API surface.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createRequire } from 'node:module';
const require = createRequire(new URL('../website/package.json', import.meta.url));
const SwaggerParser = require('@apidevtools/swagger-parser');

const root = fileURLToPath(new URL('../', import.meta.url));
const specification = path.resolve(process.argv[2] ?? path.join(root, 'openapi.json'));
const document = JSON.parse(await readFile(specification, 'utf8'));
const appSource = await readFile(path.join(root, 'internal/app/app.go'), 'utf8');
const routes = new Map([...appSource.matchAll(/mux\.HandleFunc\("(GET|POST|PUT|DELETE|PATCH) (\/(?:api\/v1(?:\/[^" ]*)?|internal(?:\/[^" ]*)?|healthz))", s\.(\w+)\)/g)]
  .map(([, method, route, handler]) => [`${method} ${route}`, handler]));
assert(routes.size > 0, 'No source API routes found; check the registration parser.');
assert.equal(document.openapi, '3.1.0', 'Use OpenAPI 3.1.0.');
assert(!document.servers?.length, 'The public contract must not embed deployment coordinates.');

const methods = new Set(['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'trace']);
const declared = new Set();
const identifiers = new Set();
const schemas = document.components?.schemas ?? {};
const securitySchemes = document.components?.securitySchemes ?? {};
const catalog = new Set(['applicationsAPI', 'appAPI', 'applicationValidationStatusAPI', 'applicationValidationHistoryAPI']);
const securityByHandler = {
  health: [],
  mySessionsAPI: ['BrowserSession'],
  revokeMySessionAPI: ['BrowserSession'],
  sessionResetAPI: ['SessionReset'],
  hydraTokenHook: ['TokenHook'],
  validatorClaim: ['Validator'],
  validatorComplete: ['Validator'],
  validatorCreateBrowserBootstraps: ['Validator'],
};

function resolve(reference) {
  assert(reference.startsWith('#/'), `External reference is not allowed: ${reference}`);
  let value = document;
  for (const part of reference.slice(2).split('/')) {
    value = value?.[part.replaceAll('~1', '/').replaceAll('~0', '~')];
  }
  assert(value !== undefined, `Unresolved reference: ${reference}`);
  return value;
}

function visit(value, callback, location = '#') {
  if (!value || typeof value !== 'object') return;
  callback(value, location);
  for (const [key, child] of Object.entries(value)) {
    visit(child, callback, `${location}/${key}`);
  }
}

visit(document, (value, location) => {
  if (value.$ref) resolve(value.$ref);
  assert(!('nullable' in value), `${location}: use JSON Schema null types, not OpenAPI 3.0 nullable.`);
  if (value.type === 'array') assert(value.items, `${location}: an array needs an item schema.`);
  if (value.properties && value.required) {
    for (const field of value.required) {
      assert(field in value.properties, `${location}: required property ${field} has no schema.`);
    }
  }
});

for (const [route, item] of Object.entries(document.paths ?? {})) {
  for (const [method, operation] of Object.entries(item)) {
    if (!methods.has(method)) continue;
    const key = `${method.toUpperCase()} ${route}`;
    declared.add(key);
    assert(routes.has(key), `Undeclared server route in OpenAPI: ${key}`);
    assert(operation.operationId, `${key}: missing operationId.`);
    assert(!identifiers.has(operation.operationId), `Duplicate operationId: ${operation.operationId}`);
    identifiers.add(operation.operationId);
    assert(operation.summary?.trim(), `${key}: missing summary.`);
    const parameters = [...(item.parameters ?? []), ...(operation.parameters ?? [])].map(p => p.$ref ? resolve(p.$ref) : p);
    const pathParameters = parameters.filter(p => p.in === 'path');
    const expectedParameters = [...route.matchAll(/\{([^}]+)\}/g)].map(([, name]) => name).sort();
    assert.deepEqual(pathParameters.map(p => p.name).sort(), expectedParameters, `${key}: path parameters disagree.`);
    assert(pathParameters.every(p => p.required === true), `${key}: path parameters must be required.`);
    const parameterKeys = parameters.map(p => `${p.in}:${p.name}`);
    assert.equal(new Set(parameterKeys).size, parameterKeys.length, `${key}: duplicate parameters.`);
    const handler = routes.get(key);
    const expectedSecurity = securityByHandler[handler] ?? (catalog.has(handler) ? ['AdminRead', 'CatalogRead'] : [method === 'get' ? 'AdminRead' : 'AdminWrite']);
    assert.deepEqual((operation.security ?? []).flatMap(s => Object.keys(s)).sort(), [...expectedSecurity].sort(), `${key}: security boundary differs from the handler.`);
    for (const requirement of operation.security ?? []) {
      for (const name of Object.keys(requirement)) assert(securitySchemes[name], `${key}: unknown security scheme ${name}.`);
    }
    assert(Object.keys(operation.responses ?? {}).some(code => /^2\d\d$/.test(code)), `${key}: no success response.`);
    for (const [status, unresolved] of Object.entries(operation.responses)) {
      const response = unresolved.$ref ? resolve(unresolved.$ref) : unresolved;
      assert(response.description?.trim(), `${key} ${status}: missing response description.`);
      if (status === '204') assert(!response.content, `${key}: a 204 must not declare a response body.`);
    }
  }
}
assert.deepEqual([...declared].sort(), [...routes.keys()].sort(), 'OpenAPI must cover every explicit JSON API/internal route and GET /healthz.');
for (const [name, scheme] of Object.entries(securitySchemes)) {
  if (name === 'BrowserSession') {
    assert.equal(scheme.in, 'cookie');
    assert.equal(scheme.name, 'shauth_session');
  } else {
    assert.equal(scheme.type, 'http');
    assert.equal(scheme.scheme, 'bearer');
  }
}
assert.equal(schemas.CreateUser.properties.password.writeOnly, true);
assert.equal(schemas.CreateOIDCClient.properties.client_secret.writeOnly, true);
assert(!schemas.User.properties.password, 'Never publish account passwords.');
assert(!schemas.OIDCClient.properties.client_secret, 'Never return client secrets.');

// swagger-parser validates the full OpenAPI 3.1 document as well as all local
// schema references. Disable external resolution to keep this gate offline.
await SwaggerParser.validate(structuredClone(document), {
  resolve: { external: false },
});
console.log(`OpenAPI 3.1 valid: ${declared.size} registered operations, ${Object.keys(schemas).length} schemas, exact route and security coverage.`);
