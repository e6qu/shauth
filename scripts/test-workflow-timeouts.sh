#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
fixtures=$(mktemp -d)
trap 'rm -rf "$fixtures"' EXIT INT TERM

cat >"$fixtures/valid.yml" <<'EOF'
name: valid
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps: []
  publish-image:
    timeout-minutes: 1
    runs-on: ubuntu-latest
    steps: []
EOF
"$root/scripts/check-workflow-timeouts.sh" "$fixtures/valid.yml" >/dev/null

cat >"$fixtures/missing.yml" <<'EOF'
jobs:
  test:
    runs-on: ubuntu-latest
    steps: []
EOF
if "$root/scripts/check-workflow-timeouts.sh" "$fixtures/missing.yml" >/dev/null 2>&1; then
	echo 'workflow timeout checker accepted a job without a timeout' >&2
	exit 1
fi

cat >"$fixtures/too-long.yml" <<'EOF'
jobs:
  test:
    timeout-minutes: 16
    runs-on: ubuntu-latest
    steps: []
EOF
if "$root/scripts/check-workflow-timeouts.sh" "$fixtures/too-long.yml" >/dev/null 2>&1; then
	echo 'workflow timeout checker accepted a timeout greater than 15 minutes' >&2
	exit 1
fi

cat >"$fixtures/expression.yml" <<'EOF'
jobs:
  test:
    timeout-minutes: ${{ matrix.timeout }}
    runs-on: ubuntu-latest
    steps: []
EOF
if "$root/scripts/check-workflow-timeouts.sh" "$fixtures/expression.yml" >/dev/null 2>&1; then
	echo 'workflow timeout checker accepted a non-literal timeout' >&2
	exit 1
fi

cat >"$fixtures/empty.yml" <<'EOF'
name: empty
jobs: {}
EOF
if "$root/scripts/check-workflow-timeouts.sh" "$fixtures/empty.yml" >/dev/null 2>&1; then
	echo 'workflow timeout checker accepted a workflow without recognized jobs' >&2
	exit 1
fi

cat >"$fixtures/quoted-job.yml" <<'EOF'
jobs:
  "test job":
    timeout-minutes: 5
    runs-on: ubuntu-latest
    steps: []
EOF
if "$root/scripts/check-workflow-timeouts.sh" "$fixtures/quoted-job.yml" >/dev/null 2>&1; then
	echo 'workflow timeout checker silently ignored unsupported quoted job syntax' >&2
	exit 1
fi

echo 'GitHub Actions job timeout checker tests passed'
