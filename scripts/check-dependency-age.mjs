// SPDX-License-Identifier: AGPL-3.0-or-later
// Check changed dependency selections before accepting version or security PRs.
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';

const base = process.argv[2] ?? 'origin/main';
if (!/^[a-zA-Z0-9_./-]+$/.test(base) || base.startsWith('-')) throw new Error('Invalid base ref');
execFileSync('git', ['rev-parse', '--verify', `${base}^{commit}`], { stdio: 'ignore' });
const cutoff = Date.now() - 24 * 60 * 60 * 1000;
const selections = new Map();
function add(kind, name, version, file) {
  const key = `${kind}:${name}@${version}`;
  if (!selections.has(key)) selections.set(key, { kind, name, version, files: new Set() });
  selections.get(key).files.add(file);
}
function previous(file) {
  const result = spawnSync('git', ['show', `${base}:${file}`], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  if (result.status === 0) return result.stdout;
  if (result.stderr.includes('does not exist in') || result.stderr.includes('exists on disk, but not in')) return '';
  throw new Error(`Cannot read ${file} from ${base}`);
}
const files = execFileSync('git', ['ls-files', '-co', '--exclude-standard'], { encoding: 'utf8' }).trim().split('\n');
for (const file of new Set(files)) {
  if (!existsSync(file)) continue; // A removed recipe selects no dependencies.
  if (!/(package-lock\.json|go\.mod|\.terraform\.lock\.hcl|Dockerfile[^/]*|\.github\/workflows\/[^/]+\.ya?ml|compose\.ya?ml|main\.tf|terragrunt\.hcl)$/.test(file)) continue;
  const text = readFileSync(file, 'utf8');
  const old = previous(file);
  if (text === old) continue;
  // A changed action without a release annotation must not silently evade
  // timestamp verification. Local actions have no external release to check.
  const actionLines = /^\s*-?\s*uses:\s*([^\s#]+)([^\n]*)/gm;
  const oldActions = new Set([...old.matchAll(actionLines)].map(m => m[0].trim()));
  for (const match of text.matchAll(actionLines)) {
    if (oldActions.has(match[0].trim()) || match[1].startsWith('./')) continue;
    if (!/^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/.test(match[1]) || !/^\s*#\s*v\d+\.\d+\.\d+\s*$/.test(match[2])) {
      throw new Error(`${file}: changed external actions require an immutable SHA and a stable # vX.Y.Z release annotation`);
    }
  }
  if (file.endsWith('package-lock.json')) {
    const oldPackages = old ? JSON.parse(old).packages ?? {} : {};
    const oldVersions = new Set(Object.entries(oldPackages).filter(([path]) => path).map(([path,p]) => `${p.name ?? path.split('node_modules/').at(-1)}@${p.version}`));
    for (const [path, pkg] of Object.entries(JSON.parse(text).packages ?? {})) {
      if (!path || !pkg.version) continue;
      const name = pkg.name ?? path.split('node_modules/').at(-1);
      if (!oldVersions.has(`${name}@${pkg.version}`)) add('npm', name, pkg.version, file);
    }
  }
  const patterns = [
    ['go', /(?:^\s*|\s)([\w.-]+\/[\w./!+-]+)(?:\s+|@)(v\d+\.\d+\.\d+(?:-[\w.-]+)?)/gm],
    ['terraform', /provider "registry\.terraform\.io\/([^"]+)"\s*\{\s*version\s*=\s*"([^"]+)"/g],
    ['action', /uses:\s*([\w.-]+\/[\w.-]+)@([0-9a-f]{40})[^\n]*?#[ \t]*(v\d+\.\d+\.\d+)/g],
    ['docker', /(?:public\.ecr\.aws\/docker\/library|docker\.io\/library|mirror\.gcr\.io\/library)\/([\w.-]+):([\w.-]+)@(sha256:[0-9a-f]{64})/g],
  ];
  for (const [kind, pattern] of patterns) {
    const identity = m => `${m[1]}@${m[2]}${m[3] ? ':'+m[3] : ''}`;
    const prior = new Set([...old.matchAll(pattern)].map(identity));
    for (const match of text.matchAll(pattern)) {
      if (prior.has(identity(match))) continue;
      add(kind, match[1], kind === 'action' ? `${match[3]}:${match[2]}` : kind === 'docker' ? `${match[2]}@${match[3]}` : match[2], file);
    }
  }
}
const cache = new Map();
async function metadata(url) {
  if (!cache.has(url)) cache.set(url, (async () => {
    const headers = { 'user-agent': 'dependency-release-age' };
    if (url.startsWith('https://api.github.com/') && process.env.GITHUB_TOKEN) headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    const response = await fetch(url, { headers, signal: AbortSignal.timeout(20000) });
    if (!response.ok) throw Object.assign(new Error(`${new URL(url).host}: HTTP ${response.status}`), { status: response.status });
    return response.json();
  })());
  return cache.get(url);
}
async function timestamp(item) {
  const { kind, name, version } = item;
  if (kind === 'npm') return (await metadata(`https://registry.npmjs.org/${encodeURIComponent(name)}`)).time?.[version];
  if (kind === 'go') {
    // go run/install select a package, which may be below its module root.
    // Only a genuine 404 permits trying its parent; outages fail closed.
    let module = name;
    while (module.includes('/')) {
      const escaped = module.replace(/[A-Z]/g, c => '!'+c.toLowerCase());
      try { return (await metadata(`https://proxy.golang.org/${escaped}/@v/${version}.info`)).Time; }
      catch (error) {
        if (error.status !== 404) throw error;
        module = module.slice(0, module.lastIndexOf('/'));
      }
    }
    throw new Error('No published Go module contains this versioned package');
  }
  if (kind === 'terraform') return (await metadata(`https://registry.terraform.io/v1/providers/${name}/${version}`)).published_at;
  if (kind === 'action') {
    const [tag, sha] = version.split(':');
    const release = await metadata(`https://api.github.com/repos/${name}/releases/tags/${tag}`);
    const commit = await metadata(`https://api.github.com/repos/${name}/commits/${tag}`);
    if (release.draft || release.prerelease || commit.sha !== sha) throw new Error('Action pin does not match a stable published release');
    return release.published_at;
  }
  if (kind === 'docker') {
    const [tag,digest] = version.split('@');
    const data = await metadata(`https://hub.docker.com/v2/repositories/library/${name}/tags/${encodeURIComponent(tag)}`);
    if (data.digest !== digest) throw new Error('Image digest does not match the timestamped Docker Hub tag');
    return data.tag_last_pushed;
  }
  throw new Error('Unknown dependency ecosystem');
}
let failed = 0;
const queue = [...selections.values()];
await Promise.all(Array.from({ length: Math.min(4, queue.length) }, async () => {
  while (queue.length) {
    const item = queue.shift();
    try {
      const published = await timestamp(item);
      const time = Date.parse(published ?? '');
      if (!Number.isFinite(time)) throw new Error('No release timestamp is available');
      if (time > cutoff) throw new Error(`24-hour cooldown ends ${new Date(time+86400000).toISOString()}`);
      console.log(`PASS ${item.kind} ${item.name}@${item.version} (${published})`);
    } catch (error) {
      failed++;
      console.error(`FAIL ${item.kind} ${item.name}@${item.version}: ${error.message} [${[...item.files].join(', ')}]`);
    }
  }
}));
console.log(`${selections.size} changed dependency selections checked; ${failed} failures`);
process.exitCode = failed ? 1 : 0;
