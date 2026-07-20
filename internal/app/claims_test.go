// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"testing"

	"github.com/e6qu/shauth/internal/identity"
)

func TestOIDCIdentityClaimsPreserveEmailVerificationEvidence(t *testing.T) {
	verified := oidcIdentityClaims(identity.User{ID: "verified", Username: "verified-user", Email: "verified@example.test", EmailVerified: true, Role: identity.RoleDeveloper})
	if value, ok := verified["email_verified"].(bool); !ok || !value {
		t.Fatalf("verified email claim = %#v", verified["email_verified"])
	}

	unverified := oidcIdentityClaims(identity.User{ID: "unverified", Username: "unverified-user", Email: "unverified@example.test", EmailVerified: false, Role: identity.RoleDeveloper})
	if value, ok := unverified["email_verified"].(bool); !ok || value {
		t.Fatalf("unverified email claim = %#v", unverified["email_verified"])
	}
}

func TestEntraEmailVerificationRequiresTheEmailClaim(t *testing.T) {
	email, verified := entraEmail(entraClaims{Email: "person@example.test", EmailVerified: true, PreferredUsername: "different@example.test"})
	if email != "person@example.test" || !verified {
		t.Fatalf("verified Microsoft Entra ID email = %q, %t", email, verified)
	}

	email, verified = entraEmail(entraClaims{EmailVerified: true, PreferredUsername: "fallback@example.test"})
	if email != "fallback@example.test" || verified {
		t.Fatalf("fallback Microsoft Entra ID email = %q, %t", email, verified)
	}
}
