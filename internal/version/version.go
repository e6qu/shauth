// SPDX-License-Identifier: AGPL-3.0-or-later

// Package version reports which build is running and when it started
// serving, so an operator looking at any page or contract can tell exactly
// which revision produced it.
package version

import "time"

// revision is the full Git commit the binary was built from. It is set at
// build time with -X and stays "unknown" for a local build, which is honest:
// a developer build has no published revision.
var revision = "unknown"

// startedAt records when this process began serving. For an immutable
// container image this is when the deployment rolled.
var startedAt = time.Now().UTC()

// Revision reports the full build revision.
func Revision() string { return revision }

// Short reports the abbreviated revision used in the interface, matching the
// twelve-character form the application catalog already displays.
func Short() string {
	const displayLength = 12
	if len(revision) <= displayLength {
		return revision
	}
	return revision[:displayLength]
}

// StartedAt reports when this process began serving, in UTC.
func StartedAt() time.Time { return startedAt }
