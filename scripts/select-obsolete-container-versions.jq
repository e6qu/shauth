# SPDX-License-Identifier: AGPL-3.0-or-later

# A release is kept when it is among the newest $keep, or younger than
# $retain_seconds: this repository cannot see which release a deployment
# runs, so an age floor keeps a release a deployment may still pull even
# after many newer ones were published.
([ .[]
   | select(any(.metadata.container.tags[]?; test("^[0-9a-f]{12}$")))
 ]
 | sort_by(.created_at)
 | reverse
 | to_entries
 | map(select(.key < $keep or ((.value.created_at | fromdateiso8601) >= (now - $retain_seconds))))
 | [.[].value.metadata.container.tags[] | select(test("^[0-9a-f]{12}$"))]
) as $release_tags
| ($release_tags
   | map(., . + "-amd64", . + "-arm64")
   | unique
  ) as $keep_tags
| .[]
| . as $version
| ($version.metadata.container.tags // []) as $tags
| select([ $tags[] | select(. as $tag | $keep_tags | index($tag) != null) ] | length == 0)
# Never delete something a publish may still be assembling. Architecture images
# are pushed before the manifest that makes them reachable, so a very recent
# version can be a live run's work rather than an obsolete release. The
# concurrency group makes overlap unlikely; this makes it harmless.
| select(($version.created_at | fromdateiso8601) < (now - $inflight_seconds))
| $version.id
