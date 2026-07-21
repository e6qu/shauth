#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu

unset CDPATH
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
. "$root/scripts/process-wait.sh"

work=$(mktemp -d)
cleanup() {
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

sleep 60 &
child_pid=$!
set +e
wait_for_process "$child_pid" 'process-wait regression child' 1 2>"$work/timeout.log"
result=$?
set -e
[ "$result" -eq 124 ]
[ "$wait_timed_out" -eq 1 ]
grep -Fx 'process-wait regression child timed out after 1 seconds; sending TERM' "$work/timeout.log" >/dev/null
if grep -E 'trap_list|signal handler|not a child' "$work/timeout.log" >/dev/null; then
	echo 'process wait emitted a shell trap or child-ownership warning' >&2
	exit 1
fi

(exit 7) &
child_pid=$!
set +e
wait_for_process "$child_pid" 'process-wait exit-status child' 5 2>"$work/status.log"
result=$?
set -e
[ "$result" -eq 7 ]
[ "$wait_timed_out" -eq 0 ]
[ ! -s "$work/status.log" ]
