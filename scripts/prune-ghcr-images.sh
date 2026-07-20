#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail

owner="${1:?usage: prune-ghcr-images.sh <owner> <package> [release-count]}"
package="${2:?usage: prune-ghcr-images.sh <owner> <package> [release-count]}"
keep="${3:-20}"

if [[ ! "$keep" =~ ^[1-9][0-9]*$ ]]; then
	echo "release count must be a positive integer: $keep" >&2
	exit 1
fi

case "$(gh api "/users/$owner" --jq .type)" in
	Organization) package_namespace=orgs ;;
	User) package_namespace=users ;;
	*)
		echo "unsupported GitHub package owner: $owner" >&2
		exit 1
		;;
esac

base="/$package_namespace/$owner/packages/container/$package/versions"
versions_file="$(mktemp)"
trap 'rm -f "$versions_file"' EXIT
gh api --paginate "$base?per_page=100" | jq -s 'add' >"$versions_file"

jq -r --argjson keep "$keep" -f "$(dirname "${BASH_SOURCE[0]}")/select-obsolete-container-versions.jq" "$versions_file" |
	while IFS= read -r version_id; do
		echo "deleting obsolete $package package version $version_id"
		gh api --method DELETE "$base/$version_id"
	done

remaining_releases="$(gh api --paginate "$base?per_page=100" | jq -s '[add[] | select(any(.metadata.container.tags[]?; test("^[0-9a-f]{12}$")))] | length')"
if ((remaining_releases > keep)); then
	echo "$package retained $remaining_releases releases; expected at most $keep" >&2
	exit 1
fi
echo "$package retained $remaining_releases immutable release(s)"
