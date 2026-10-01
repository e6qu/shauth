#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail

owner="${1:?usage: prune-ghcr-images.sh <owner> <package> [release-count]}"
package="${2:?usage: prune-ghcr-images.sh <owner> <package> [release-count]}"
keep="${3:-20}"
# Architecture images are pushed before the manifest that makes them reachable,
# so anything younger than this may belong to a publish still in flight and is
# never pruned. Twenty minutes comfortably exceeds a full publish run.
inflight_seconds="${4:-1200}"
# Releases younger than this are kept however many newer ones exist, so a
# deployment that has not caught up can still pull the image it runs.
retain_days="${5:-90}"

if [[ ! "$retain_days" =~ ^[0-9]+$ ]]; then
	echo "retention days must be a whole number: $retain_days" >&2
	exit 1
fi
retain_seconds=$((retain_days * 86400))
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

jq -r --argjson keep "$keep" --argjson inflight_seconds "$inflight_seconds" --argjson retain_seconds "$retain_seconds" -f "$(dirname "${BASH_SOURCE[0]}")/select-obsolete-container-versions.jq" "$versions_file" |
	while IFS= read -r version_id; do
		echo "deleting obsolete $package package version $version_id"
		gh api --method DELETE "$base/$version_id"
	done

remaining_versions_file="$(mktemp)"
trap 'rm -f "$versions_file" "$remaining_versions_file"' EXIT
gh api --paginate "$base?per_page=100" | jq -s 'add' >"$remaining_versions_file"

remaining_releases="$(jq '[.[] | select(any(.metadata.container.tags[]?; test("^[0-9a-f]{12}$")))] | length' "$remaining_versions_file")"
# Releases beyond the newest $keep are allowed only inside the age floor.
allowed_releases="$(jq --argjson keep "$keep" --argjson retain_seconds "$retain_seconds" '[.[] | select(any(.metadata.container.tags[]?; test("^[0-9a-f]{12}$")))] | sort_by(.created_at) | reverse | to_entries | map(select(.key < $keep or ((.value.created_at | fromdateiso8601) >= (now - $retain_seconds)))) | length' "$remaining_versions_file")"
if ((remaining_releases > allowed_releases)); then
	echo "$package retained $remaining_releases releases; expected at most $allowed_releases" >&2
	exit 1
fi
keep=$allowed_releases

remaining_unrecognized="$(jq '[.[] | select(
	(.metadata.container.tags | length) == 0
	or any(.metadata.container.tags[]; test("^[0-9a-f]{12}(-(amd64|arm64))?$") | not)
)] | length' "$remaining_versions_file")"
if ((remaining_unrecognized > 0)); then
	echo "$package retained $remaining_unrecognized untagged or non-release package version(s)" >&2
	exit 1
fi

remaining_versions="$(jq 'length' "$remaining_versions_file")"
maximum_versions=$((keep * 3))
if ((remaining_versions > maximum_versions)); then
	echo "$package retained $remaining_versions package versions; expected at most $maximum_versions for $keep releases" >&2
	exit 1
fi

echo "$package retained $remaining_releases immutable release(s) across $remaining_versions package version(s)"
