#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu

unset CDPATH
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

stale='http://localhost:5556|http://127\.0\.0\.1:5558|http%3A%2F%2Flocalhost%3A5556|http%3A%2F%2F127\.0\.0\.1%3A5558'
if grep -En "$stale" scripts/test-stack.sh scripts/test-gateway-oidc.mjs scripts/test-browser-global-logout.mjs; then
	echo 'gateway acceptance tests contained a stale relying-party origin' >&2
	exit 1
fi

for coordinate in \
	'gateway-integration|gateway-integration.localhost:5556' \
	'gateway-secondary|gateway-secondary.localhost:5558' \
	'gateway-tertiary|gateway-tertiary.localhost:5560'; do
	slug=${coordinate%%|*}
	host=${coordinate#*|}
	grep -Fq "OIDC_GATEWAY_CLIENT_ID=${slug}" scripts/test-stack.sh
	grep -Fq "OIDC_GATEWAY_PUBLIC_URL=http://${host}" scripts/test-stack.sh || \
		grep -Fq "OIDC_GATEWAY_PUBLIC_URL='http://${host}'" scripts/test-stack.sh
	grep -Fq "\"slug\":\"${slug}\"" scripts/test-stack.sh
	grep -Fq "\"redirect_uris\":[\"http://${host}/auth/callback\"]" scripts/test-stack.sh
	grep -Fq "\"backchannel_logout_uri\":\"http://${host}/auth/backchannel-logout\"" scripts/test-stack.sh
	done

echo 'Gateway acceptance-test coordinate contract passed'
