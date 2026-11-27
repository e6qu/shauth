// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import test from "node:test";

import { findPins, newerTags, verdict, WAIT_MS } from "./image-pins.mjs";

const NOW = Date.parse("2026-10-11T12:00:00Z");
const OLD = NOW - WAIT_MS;
const YOUNG = OLD + 1;
const PINNED = `sha256:${"a".repeat(64)}`;
const MOVED = `sha256:${"b".repeat(64)}`;

test("pins name the Docker Hub repository they copy", () => {
  const pins = findPins([
    ["Dockerfile", `FROM public.ecr.aws/docker/library/golang:1.27.2-alpine@${PINNED} AS build`],
    ["ci.yml", `driver-opts: image=mirror.gcr.io/moby/buildkit:buildx-stable-1@${PINNED}`],
    ["compose.yaml", "image: public.ecr.aws/docker/library/postgres:18-alpine"],
  ]);
  assert.deepEqual(
    [...pins.values()].map(({ registry, repository, hub, tag }) => [registry, repository, hub, tag]),
    [
      ["public.ecr.aws/docker/library", "golang", "library/golang", "1.27.2-alpine"],
      ["mirror.gcr.io", "moby/buildkit", "moby/buildkit", "buildx-stable-1"],
    ],
  );
});

test("newer releases keep the variant, component count and major version", () => {
  const candidates = ["1.27.3-alpine", "1.27.3-bookworm", "1.28.0-alpine", "2.0.0-alpine", "1.27-alpine", "1.27.1-alpine"]
    .map((name) => ({ name, pushed: OLD }));
  assert.deepEqual(newerTags("1.27.2-alpine", candidates).map(({ name }) => name), ["1.28.0-alpine", "1.27.3-alpine"]);
  assert.deepEqual(newerTags("buildx-stable-1", candidates), []);
  assert.deepEqual(newerTags("v0.33.0", [{ name: "v0.34.0", pushed: OLD }, { name: "0.35.0", pushed: OLD }]).map(({ name }) => name), ["v0.34.0"]);
});

const base = { pinned: PINNED, hubDigest: PINNED, hubPushed: OLD, mirrorDigest: PINNED, newer: [], now: NOW };

test("a current pin the mirror serves is ok", () => {
  assert.deepEqual(verdict(base), { state: "ok", notes: [] });
});

test("a moved tag is held for 24 hours, then drifts", () => {
  assert.equal(verdict({ ...base, hubDigest: MOVED, hubPushed: YOUNG }).state, "HELD");
  assert.equal(verdict({ ...base, hubDigest: MOVED, hubPushed: OLD }).state, "DRIFT");
});

test("a newer release is held for 24 hours, then drifts", () => {
  assert.equal(verdict({ ...base, newer: [{ name: "1.27.3", pushed: YOUNG }] }).state, "HELD");
  assert.equal(verdict({ ...base, newer: [{ name: "1.27.3", pushed: OLD }] }).state, "DRIFT");
});

test("a mirror serving another digest fails", () => {
  assert.equal(verdict({ ...base, mirrorDigest: MOVED }).state, "DRIFT");
});
