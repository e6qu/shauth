#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail

root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
workflow="$root/.github/workflows/ci.yml"
gha='$'

expect_count() {
	local expected="$1" literal="$2" actual
	actual="$(grep -Fxc -- "$literal" "$workflow" || true)"
	if [[ "$actual" != "$expected" ]]; then
		echo "publication workflow expected $expected exact occurrence(s), found $actual: $literal" >&2
		exit 1
	fi
}

expect_count 1 '    runs-on: ubuntu-24.04-arm'
expect_count 1 '          platforms: linux/amd64'
expect_count 1 '          platforms: linux/arm64'
expect_count 1 "          tags: ghcr.io/e6qu/shauth:${gha}{{ steps.sha.outputs.short_sha }}-amd64"
expect_count 1 "          tags: ghcr.io/e6qu/shauth:${gha}{{ steps.sha.outputs.short_sha }}-arm64"
expect_count 2 '          provenance: false'
expect_count 2 '          sbom: false'
expect_count 1 "          --tag ghcr.io/e6qu/shauth:${gha}{{ needs.build-amd64.outputs.short_sha }}"
expect_count 1 "          ghcr.io/e6qu/shauth:${gha}{{ needs.build-amd64.outputs.short_sha }}-amd64"
expect_count 1 "          ghcr.io/e6qu/shauth:${gha}{{ needs.build-arm64.outputs.short_sha }}-arm64"
expect_count 1 '          ./scripts/verify-published-container.sh'
expect_count 1 "        run: ./scripts/prune-ghcr-images.sh \"${gha}{{ github.repository_owner }}\" \"${gha}{{ github.event.repository.name }}\" 20"

image_reference_count="$(grep -Fo 'ghcr.io/e6qu/shauth:' "$workflow" | wc -l | tr -d ' ')"
if [[ "$image_reference_count" != 5 ]]; then
	echo "publication workflow contained $image_reference_count Shauth tag references; expected exactly the generic and two direct image publications" >&2
	exit 1
fi

if grep -Eiq 'tags?:[^#]*(:(latest|main))([[:space:]]|$)' "$workflow"; then
	echo 'publication workflow must not publish latest or main image tags' >&2
	exit 1
fi

	fixture="$(mktemp)"
trap 'rm -f "$fixture"' EXIT
	jq -n '[
	range(0; 22) as $release
	| (("000000000000" + ($release | tostring))[-12:]) as $tag
	| range(0; 3) as $kind
	| {
		id: ($release * 10 + $kind),
		created_at: ("2026-07-" + (("00" + (($release + 1) | tostring))[-2:]) + "T00:00:00Z"),
		metadata: {container: {tags: [
			if $kind == 0 then $tag
			elif $kind == 1 then ($tag + "-amd64")
			else ($tag + "-arm64") end
		]}}
	}
] + [{id: 999, created_at: "2026-08-01T00:00:00Z", metadata: {container: {tags: []}}}]' >"$fixture"

selected="$(jq -r --argjson keep 20 -f "$root/scripts/select-obsolete-container-versions.jq" "$fixture" | sort -n | paste -sd, -)"
if [[ "$selected" != '0,1,2,10,11,12,999' ]]; then
	echo "retention selector chose unexpected package versions: $selected" >&2
	exit 1
fi

echo 'container publication workflow contract passed'
