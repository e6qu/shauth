// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"strings"
	"testing"
	"time"

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

// A consent form is browser input: a granted scope must be one the
// application actually requested, whatever the form submits.
func TestConsentGrantsOnlyRequestedScopes(t *testing.T) {
	granted := grantableScopes([]string{"openid", "profile"}, []string{"openid", "admin", "profile", "openid", "offline_access"})
	if strings.Join(granted, " ") != "openid profile" {
		t.Fatalf("granted scopes = %v, want [openid profile]", granted)
	}
	if granted := grantableScopes([]string{"openid"}, nil); len(granted) != 0 {
		t.Fatalf("an empty submission granted %v", granted)
	}
}

func TestReauthenticationDemandReadsPromptAndMaxAge(t *testing.T) {
	for requestURL, want := range map[string]struct {
		prompt bool
		maxAge time.Duration
	}{
		"https://auth.example.test/oauth2/auth?client_id=a":                       {false, -1},
		"https://auth.example.test/oauth2/auth?prompt=login":                      {true, -1},
		"https://auth.example.test/oauth2/auth?prompt=consent+login":              {true, -1},
		"https://auth.example.test/oauth2/auth?prompt=none":                       {false, -1},
		"https://auth.example.test/oauth2/auth?max_age=0":                         {false, 0},
		"https://auth.example.test/oauth2/auth?max_age=300&prompt=select_account": {false, 300 * time.Second},
		"https://auth.example.test/oauth2/auth?max_age=-5":                        {false, -1},
	} {
		prompt, maxAge := reauthenticationDemand(requestURL)
		if prompt != want.prompt || maxAge != want.maxAge {
			t.Errorf("%s = (%v, %v), want (%v, %v)", requestURL, prompt, maxAge, want.prompt, want.maxAge)
		}
	}
}

// prompt=login is satisfied only by a browser session created after the
// person was sent back to sign in, and only for that login challenge.
func TestReauthenticationMarkerBindsChallengeAndTime(t *testing.T) {
	sentAt := time.Now()
	marker := reauthenticationMarker("challenge-1", sentAt)
	if !reauthenticatedSince(marker, "challenge-1", sentAt.Add(time.Second)) {
		t.Fatal("a session created after the marker did not satisfy it")
	}
	if reauthenticatedSince(marker, "challenge-1", sentAt.Add(-time.Second)) {
		t.Fatal("a session created before the marker satisfied it")
	}
	if reauthenticatedSince(marker, "challenge-2", sentAt.Add(time.Second)) {
		t.Fatal("a marker for another challenge satisfied it")
	}
	if reauthenticatedSince("forged", "challenge-1", sentAt.Add(time.Second)) {
		t.Fatal("a malformed marker satisfied it")
	}
}
