// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/json"
	"math"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/e6qu/shauth/internal/identity"
)

func TestParseSessionPolicyForm(t *testing.T) {
	policy, err := parseSessionPolicyForm(url.Values{
		"browser_absolute_hours": {"168"},
		"browser_idle_minutes":   {"60"},
		"oidc_sso_hours":         {"24"},
		"access_token_minutes":   {"10"},
		"id_token_minutes":       {"10"},
		"refresh_token_hours":    {"48"},
	})
	if err != nil {
		t.Fatalf("parseSessionPolicyForm() error = %v", err)
	}
	if policy.BrowserAbsoluteLifetime != 7*24*time.Hour || policy.BrowserIdleTimeout != time.Hour || policy.OIDCSessionLifetime != 24*time.Hour {
		t.Fatalf("browser and SSO policy = %#v", policy)
	}
	if policy.AccessTokenLifetime != 10*time.Minute || policy.IDTokenLifetime != 10*time.Minute || policy.RefreshTokenLifetime != 48*time.Hour {
		t.Fatalf("token policy = %#v", policy)
	}
}

func TestParseSessionPolicyFormRejectsDurationOverflow(t *testing.T) {
	_, err := parseSessionPolicyForm(url.Values{"browser_absolute_hours": {strconv.FormatInt(math.MaxInt64, 10)}})
	if err == nil {
		t.Fatal("parseSessionPolicyForm accepted a duration that overflows time.Duration")
	}
}

func TestNextHydraPageToken(t *testing.T) {
	header := `<http://hydra:4445/admin/clients?page_size=1000>; rel="first", <http://hydra:4445/admin/clients?page_size=1000&page_token=client-1000>; rel="next"`
	token, err := nextHydraPageToken(header)
	if err != nil {
		t.Fatal(err)
	}
	if token != "client-1000" {
		t.Fatalf("next page token = %q", token)
	}
}

func TestHydraClientLifespansChangesRealTokenLifespans(t *testing.T) {
	body, err := json.Marshal(hydraClientLifespans(identity.DefaultSessionPolicy()))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result["authorization_code_grant_access_token_lifespan"] != "15m0s" || result["authorization_code_grant_refresh_token_lifespan"] != "720h0m0s" {
		t.Fatalf("Hydra lifespans = %#v", result)
	}
}
