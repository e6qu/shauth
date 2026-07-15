// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"strings"
	"testing"
)

func TestRevocationQueriesRevokeRefreshTokens(t *testing.T) {
	for name, query := range map[string]string{
		"single session":    revokeFamilySQL,
		"all user sessions": revokeUserSessionsSQL,
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(query, "UPDATE refresh_tokens") || !strings.Contains(query, "revoked_at") {
				t.Fatalf("query does not revoke refresh tokens: %s", query)
			}
		})
	}
}
