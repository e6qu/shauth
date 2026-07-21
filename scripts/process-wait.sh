#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later

# Wait for a child process without relying on GNU timeout or a trap-bearing
# watchdog subshell. The polling design behaves consistently in macOS Bash 3.2
# and Linux POSIX shells while preserving the child's real exit status.
wait_timed_out=0
wait_for_process() {
	process_pid=$1
	process_label=$2
	process_timeout=$3
	elapsed=0
	wait_timed_out=0
	while kill -0 "$process_pid" 2>/dev/null; do
		if [ "$elapsed" -ge "$process_timeout" ]; then
			printf '%s timed out after %s seconds; sending TERM\n' "$process_label" "$process_timeout" >&2
			kill "$process_pid" 2>/dev/null || true
			grace_elapsed=0
			while kill -0 "$process_pid" 2>/dev/null && [ "$grace_elapsed" -lt 5 ]; do
				sleep 1
				grace_elapsed=$((grace_elapsed + 1))
			done
			if kill -0 "$process_pid" 2>/dev/null; then
				printf '%s ignored TERM; sending KILL\n' "$process_label" >&2
				kill -KILL "$process_pid" 2>/dev/null || true
			fi
			wait "$process_pid" 2>/dev/null || true
			wait_timed_out=1
			return 124
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	if wait "$process_pid" 2>/dev/null; then
		process_status=0
	else
		process_status=$?
	fi
	return "$process_status"
}

stop_process() {
	process_pid=$1
	process_label=$2
	[ -n "$process_pid" ] || return 0
	if ! kill -0 "$process_pid" 2>/dev/null; then
		wait "$process_pid" 2>/dev/null || true
		return 0
	fi
	kill "$process_pid" 2>/dev/null || true
	if wait_for_process "$process_pid" "$process_label cleanup" 10; then
		return 0
	fi
	[ "$wait_timed_out" -eq 0 ]
}
