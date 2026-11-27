// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fails when a pinned container image is behind what Docker Hub serves for it.
//
// Every image this repository pulls is a copy of a Docker Hub image, pinned by
// tag and digest: public.ecr.aws/docker/library/<name> for official images and
// mirror.gcr.io/<repository> for the rest. A digest that never moves rots, so
// each pin is compared with Docker Hub:
//
//   ok     the pin is the digest Docker Hub serves for its tag, and the mirror
//          serves that digest too
//   HELD   Docker Hub has something newer (a new digest for the tag, or a newer
//          release with the same variant and major version), but it is less
//          than 24 hours old
//   DRIFT  Docker Hub has had something newer for at least 24 hours, or the
//          mirror serves a different digest than the pin: fails
//
// Dependabot does not cover this: it applies no cooldown to public.ecr.aws, and
// its anonymous lookups there can exceed ECR Public's limit of one
// unauthenticated request per second. This check makes a few requests per
// image and spaces its ECR Public requests 1.1 seconds apart.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { pathToFileURL } from "node:url";

export const WAIT_MS = 24 * 60 * 60 * 1000;
const PIN = /(public\.ecr\.aws\/docker\/library|mirror\.gcr\.io)\/([a-z0-9._/-]+):([\w.-]+)@(sha256:[0-9a-f]{64})/g;
const VERSION = /^(v?)(\d+(?:\.\d+)*)(-[\w.-]+)?$/;
const INDEX_TYPES = [
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.docker.distribution.manifest.list.v2+json",
  "application/vnd.oci.image.manifest.v1+json",
  "application/vnd.docker.distribution.manifest.v2+json",
].join(", ");
const ECR_SPACING_MS = 1100;

/** Map each distinct pin to the files that name it. */
export function findPins(files) {
  const pins = new Map();
  for (const [path, text] of files) {
    for (const [, registry, repository, tag, digest] of text.matchAll(PIN)) {
      const hub = registry === "mirror.gcr.io" && repository.includes("/") ? repository : `library/${repository}`;
      const key = `${registry}/${repository}:${tag}@${digest}`;
      const pin = pins.get(key) ?? { registry, repository, hub, tag, digest, files: new Set() };
      pin.files.add(path);
      pins.set(key, pin);
    }
  }
  return pins;
}

/** Newer releases of `tag` with the same prefix, variant, component count and
 * major version, newest first. Tags that are not versions have none. */
export function newerTags(tag, candidates) {
  const match = VERSION.exec(tag);
  if (!match) return [];
  const [, prefix, numbers, suffix = ""] = match;
  const pinned = numbers.split(".").map(Number);
  const compare = (a, b) => {
    for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return a[i] - b[i];
    return 0;
  };
  return candidates
    .map(({ name, pushed }) => {
      const other = VERSION.exec(name);
      if (!other || other[1] !== prefix || (other[3] ?? "") !== suffix) return null;
      const version = other[2].split(".").map(Number);
      if (version.length !== pinned.length || version[0] !== pinned[0] || compare(version, pinned) <= 0) return null;
      return { name, pushed, version };
    })
    .filter(Boolean)
    .sort((a, b) => compare(b.version, a.version))
    .map(({ name, pushed }) => ({ name, pushed }));
}

/** Classify one pin. Times are milliseconds since the epoch. */
export function verdict({ pinned, hubDigest, hubPushed, mirrorDigest, newer, now }) {
  const problems = [];
  const held = [];
  if (hubDigest !== pinned) {
    const when = new Date(hubPushed).toISOString();
    if (now - hubPushed >= WAIT_MS) problems.push(`Docker Hub has served ${hubDigest} for the tag since ${when}`);
    else held.push(`Docker Hub moved the tag to ${hubDigest} at ${when}`);
  } else if (mirrorDigest !== pinned) {
    problems.push(`the mirror serves ${mirrorDigest} for the tag, not the pinned digest`);
  }
  const eligible = newer.filter(({ pushed }) => now - pushed >= WAIT_MS);
  if (eligible.length > 0) {
    problems.push(`newer release ${eligible[0].name} has been on Docker Hub since ${new Date(eligible[0].pushed).toISOString()}`);
  } else if (newer.length > 0) {
    held.push(`newer release ${newer[0].name} is inside the 24-hour quarantine`);
  }
  if (problems.length > 0) return { state: "DRIFT", notes: problems };
  if (held.length > 0) return { state: "HELD", notes: held };
  return { state: "ok", notes: [] };
}

async function request(url, { headers = {}, method = "GET" } = {}) {
  const response = await fetch(url, {
    method,
    headers: { "user-agent": "shauth-image-pins", ...headers },
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error(`${method} ${url}: HTTP ${response.status}`);
  return response;
}

let lastEcr = 0;
async function ecrRequest(url, options) {
  const wait = lastEcr + ECR_SPACING_MS - Date.now();
  if (wait > 0) await sleep(wait);
  try {
    return await request(url, options);
  } finally {
    lastEcr = Date.now();
  }
}

async function mirrorDigest({ registry, repository, tag }) {
  const headers = { accept: INDEX_TYPES };
  let response;
  if (registry === "mirror.gcr.io") {
    response = await request(`https://mirror.gcr.io/v2/${repository}/manifests/${tag}`, { headers, method: "HEAD" });
  } else {
    const scope = encodeURIComponent(`repository:docker/library/${repository}:pull`);
    const { token } = await (await ecrRequest(`https://public.ecr.aws/token/?scope=${scope}&service=public.ecr.aws`)).json();
    headers.authorization = `Bearer ${token}`;
    response = await ecrRequest(`https://public.ecr.aws/v2/docker/library/${repository}/manifests/${tag}`, { headers, method: "HEAD" });
  }
  const digest = response.headers.get("docker-content-digest");
  if (!digest) throw new Error(`${registry} returned no digest for ${repository}:${tag}`);
  return digest;
}

async function hubTag({ hub, tag }) {
  const data = await (await request(`https://hub.docker.com/v2/repositories/${hub}/tags/${encodeURIComponent(tag)}`)).json();
  const pushed = Date.parse(data.tag_last_pushed ?? "");
  if (typeof data.digest !== "string" || Number.isNaN(pushed)) throw new Error("Docker Hub returned no digest or push time");
  return { hubDigest: data.digest, hubPushed: pushed };
}

async function hubCandidates({ hub, tag }) {
  const match = VERSION.exec(tag);
  if (!match) return [];
  const name = encodeURIComponent(`${match[1]}${match[2].split(".")[0]}.`);
  const data = await (await request(`https://hub.docker.com/v2/repositories/${hub}/tags?page_size=100&ordering=last_updated&name=${name}`)).json();
  return data.results
    .filter((row) => row.tag_last_pushed)
    .map((row) => ({ name: row.name, pushed: Date.parse(row.tag_last_pushed) }));
}

function trackedFiles() {
  let out;
  try {
    out = execFileSync("git", ["grep", "-lE", "(public\\.ecr\\.aws/docker/library|mirror\\.gcr\\.io)/[a-z0-9._/-]+:[A-Za-z0-9_.-]+@sha256:", "--", ":!*.md"], { encoding: "utf8" });
  } catch (error) {
    if (error.status === 1) return [];
    throw error;
  }
  return out.split("\n").filter(Boolean);
}

async function main() {
  const now = Date.now();
  const pins = findPins(trackedFiles().map((path) => [path, readFileSync(path, "utf8")]));
  if (pins.size === 0) {
    console.error("found no pinned images; the check is not looking at anything");
    return 1;
  }
  let failed = 0;
  for (const [key, pin] of [...pins.entries()].sort()) {
    const label = `${key.replace(/@.*/, "")} (${[...pin.files].sort().join(", ")})`;
    try {
      const { hubDigest, hubPushed } = await hubTag(pin);
      const mirrored = await mirrorDigest(pin);
      const newer = newerTags(pin.tag, await hubCandidates(pin));
      const { state, notes } = verdict({ pinned: pin.digest, hubDigest, hubPushed, mirrorDigest: mirrored, newer, now });
      console.log(`${state.padEnd(6)} ${label}${notes.map((note) => `\n         ${note}`).join("")}`);
      if (state === "DRIFT") failed += 1;
    } catch (error) {
      console.error(`ERROR  ${label}: could not be checked: ${error.message}`);
      failed += 1;
    }
  }
  if (failed > 0) {
    console.error(`${failed} image pin(s) are behind Docker Hub or could not be checked. Bump each one to the digest Docker Hub serves once the mirror serves the same digest.`);
    return 1;
  }
  console.log(`All ${pins.size} pinned images are current or held.`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main();
}
