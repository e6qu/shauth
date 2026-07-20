# SPDX-License-Identifier: AGPL-3.0-or-later

([ .[]
   | select(any(.metadata.container.tags[]?; test("^[0-9a-f]{12}$")))
 ]
 | sort_by(.created_at)
 | reverse
 | .[:$keep]
 | [.[].metadata.container.tags[] | select(test("^[0-9a-f]{12}$"))]
) as $release_tags
| ($release_tags
   | map(., . + "-amd64", . + "-arm64")
   | unique
  ) as $keep_tags
| .[]
| . as $version
| ($version.metadata.container.tags // []) as $tags
| select(($tags | length) > 0)
| select([ $tags[] | select(. as $tag | $keep_tags | index($tag) != null) ] | length == 0)
| $version.id
