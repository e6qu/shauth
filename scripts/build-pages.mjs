// SPDX-License-Identifier: AGPL-3.0-or-later
import { cp, mkdir, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
async function run(command, args) {
  await new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: root, stdio: 'inherit', detached: true });
    let expired = false, killTimer;
    const signal = name => { try { process.kill(-child.pid, name); } catch (error) { if (error.code !== 'ESRCH') throw error; } };
    const timer = setTimeout(() => {
      expired = true;
      console.error(`Website build exceeded 180 seconds: ${command} ${args.join(' ')}; terminating process group`);
      signal('SIGTERM');
      killTimer = setTimeout(() => signal('SIGKILL'), 5000);
    }, 180000);
    child.on('error', error => { clearTimeout(timer); clearTimeout(killTimer); reject(error); });
    child.on('close', (code, signal) => {
      clearTimeout(timer); clearTimeout(killTimer);
      if (expired || code !== 0) reject(new Error(`Website build failed: ${command} (exit ${code}, signal ${signal}, timed out ${expired})`));
      else resolve();
    });
  });
}

await run(process.execPath, ['scripts/sync-pages-assets.mjs', '--check']);
await run(process.execPath, ['scripts/check-openapi.mjs']);
await rm(new URL('../.pages/', import.meta.url), { recursive: true, force: true });
await mkdir(new URL('../.pages/', import.meta.url));
// Explicit public allowlist: build dependencies and repository files are never served.
for (const name of ['index.html', '.nojekyll', 'assets', 'demo', 'components.js', 'docs.css', 'docs-search.js']) {
  await cp(new URL(`../website/${name}`, import.meta.url), new URL(`../.pages/${name}`, import.meta.url), { recursive: true });
}
await cp(new URL('../openapi.json', import.meta.url), new URL('../.pages/openapi.json', import.meta.url));
await run(process.execPath, ['scripts/build-docs.mjs']);
await run('npm', ['--prefix', 'website', 'run', 'build:storybook']);
console.log('Pages: built presentation, interactive demo, documentation, OpenAPI, and Storybook in .pages/');
