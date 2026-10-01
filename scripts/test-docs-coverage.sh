#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Proves the documentation coverage check fails when a variable or a route
# disappears from the docs, not only that it passes today.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
fixtures=$(mktemp -d)
trap 'rm -rf "$fixtures"' EXIT INT TERM

"$root/scripts/check-docs-coverage.sh" >/dev/null

expect_failure() {
	description=$1
	expression=$2
	rm -rf "$fixtures/docs"
	cp -R "$root/docs" "$fixtures/docs"
	find "$fixtures/docs" -name '*.md' -exec sed -i.bak "$expression" {} +
	find "$fixtures/docs" -name '*.bak' -exec rm -f {} +
	if "$root/scripts/check-docs-coverage.sh" "$fixtures/docs" >/dev/null 2>&1; then
		echo "documentation coverage check accepted docs without $description" >&2
		exit 1
	fi
}

expect_failure 'a configuration variable' 's#SHAUTH_TOKEN_HOOK_TOKEN#REMOVED#g'
expect_failure 'an API route' 's#/api/v1/logout-grants#REMOVED#g'
expect_failure 'a gateway route' 's#/auth/backchannel-logout#REMOVED#g'
# /login must not count as documented merely because /oauth/login is.
expect_failure 'the sign-in page' 's#\([` ]\)/login\([`,]\)#\1REMOVED\2#g'

echo 'documentation coverage check contract passed'
