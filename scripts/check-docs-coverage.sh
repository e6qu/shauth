#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Fails when the code reads a configuration variable or serves a route that
# the documentation does not mention, so docs/ cannot silently fall behind.
# An optional argument names the documentation directory (for the self-test).
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
docs=${1:-$root/docs}

documented() {
	grep -rqF -- "$1" "$docs"
}

missing=0

variables=$(
	{
		grep -ohE '"(SHAUTH|HYDRA|GITHUB|ENTRA|DATABASE|OIDC_GATEWAY|APPLICATION)_[A-Z0-9_]+"' \
			"$root/internal/config/config.go" "$root/internal/gateway/config.go"
		grep -ohE '(Getenv|required)\("(SHAUTH|DATABASE)_[A-Z0-9_]+"\)' "$root"/cmd/*/main.go |
			grep -oE '"[A-Z0-9_]+"'
	} | tr -d '"' | sort -u
)
[ -n "$variables" ] || {
	echo 'found no configuration variables; the extraction pattern is broken' >&2
	exit 1
}
for variable in $variables; do
	if ! documented "$variable"; then
		echo "configuration variable $variable is not documented in docs/" >&2
		missing=1
	fi
done

# Static assets and the catch-all handlers are not part of the contract.
routes=$(
	grep -ohE 'mux\.Handle(Func)?\("([A-Z]+ )?/[^"]*"' "$root/internal/app/app.go" "$root/internal/gateway/server.go" |
		sed -E 's/^mux\.Handle(Func)?\("([A-Z]+ )?//; s/"$//' |
		grep -vE '^/$|^/\{\$\}$|^/assets/|^/favicon\.|^/auth/gateway\.css$' |
		sed -E 's/\{path\.\.\.\}$//' | sort -u
)
[ -n "$routes" ] || {
	echo 'found no routes; the extraction pattern is broken' >&2
	exit 1
}
for route in $routes; do
	if ! documented "\`$route" && ! documented " $route"; then
		echo "route $route is not documented in docs/" >&2
		missing=1
	fi
done

[ "$missing" -eq 0 ] || exit 1
echo 'documentation covers every configuration variable and route'
