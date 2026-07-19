// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/json"
	"testing"
)

func TestOIDCClientInputValidate(t *testing.T) {
	valid := oidcClientInput{
		ID:           "intraktible-dev",
		Name:         "Intraktible development",
		Secret:       "0123456789abcdef0123456789abcdef",
		RedirectURIs: []string{"https://intraktible.dev.e6qu.dev/v1/auth/oidc/shauth/callback"},
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("validate valid client: %v", err)
	}

	for name, mutate := range map[string]func(*oidcClientInput){
		"invalid identifier": func(input *oidcClientInput) { input.ID = "Invalid" },
		"short secret":       func(input *oidcClientInput) { input.Secret = "too-short" },
		"insecure remote": func(input *oidcClientInput) {
			input.RedirectURIs = []string{"http://intraktible.dev.e6qu.dev/callback"}
		},
		"fragment": func(input *oidcClientInput) {
			input.RedirectURIs = []string{"https://intraktible.dev.e6qu.dev/callback#fragment"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := valid
			mutate(&input)
			if err := input.validate(); err == nil {
				t.Fatal("validate accepted invalid client")
			}
		})
	}
}

func TestOIDCClientInputAllowsLoopbackHTTP(t *testing.T) {
	input := oidcClientInput{
		ID:           "local-client",
		Name:         "Local client",
		Secret:       "0123456789abcdef0123456789abcdef",
		RedirectURIs: []string{"http://127.0.0.1:8080/callback", "http://localhost:3000/callback"},
	}
	if err := input.validate(); err != nil {
		t.Fatalf("validate loopback client: %v", err)
	}
}

func TestMarshalHydraClientUsesConfidentialAuthorizationCodeFlow(t *testing.T) {
	body, err := marshalHydraClient(oidcClientInput{
		ID:           "intraktible-dev",
		Name:         "Intraktible",
		Secret:       "a-very-long-client-secret-that-is-safe-for-a-test",
		RedirectURIs: []string{"https://intraktible.example.test/v1/auth/oidc/shauth/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		ClientID                string   `json:"client_id"`
		ClientSecret            string   `json:"client_secret"`
		GrantTypes              []string `json:"grant_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ClientID != "intraktible-dev" || payload.ClientSecret == "" {
		t.Fatalf("client payload = %#v, want client ID and secret", payload)
	}
	if len(payload.GrantTypes) != 2 || payload.GrantTypes[0] != "authorization_code" || payload.GrantTypes[1] != "refresh_token" {
		t.Fatalf("grant types = %#v", payload.GrantTypes)
	}
	if payload.TokenEndpointAuthMethod != "client_secret_post" {
		t.Fatalf("token endpoint auth method = %q", payload.TokenEndpointAuthMethod)
	}
}

func TestMarshalHydraClientPostLogoutRedirectURIs(t *testing.T) {
	// Present only when the client registers some.
	withURIs, err := marshalHydraClient(oidcClientInput{
		ID:                     "e6irc-dev",
		Name:                   "e6irc",
		Secret:                 "a-very-long-client-secret-that-is-safe-for-a-test",
		RedirectURIs:           []string{"https://e6irc.dev.e6qu.dev/api/v1/auth/oidc/shauth/callback"},
		PostLogoutRedirectURIs: []string{"https://e6irc.dev.e6qu.dev"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		PostLogout []string `json:"post_logout_redirect_uris"`
	}
	if err := json.Unmarshal(withURIs, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.PostLogout) != 1 || got.PostLogout[0] != "https://e6irc.dev.e6qu.dev" {
		t.Fatalf("post_logout_redirect_uris = %#v", got.PostLogout)
	}

	// Absent (not just empty) when the client registers none, so existing
	// clients' payloads are unchanged.
	without, err := marshalHydraClient(oidcClientInput{
		ID:           "e6irc-dev",
		Name:         "e6irc",
		Secret:       "a-very-long-client-secret-that-is-safe-for-a-test",
		RedirectURIs: []string{"https://e6irc.dev.e6qu.dev/api/v1/auth/oidc/shauth/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if m := map[string]any{}; json.Unmarshal(without, &m) == nil {
		if _, present := m["post_logout_redirect_uris"]; present {
			t.Fatal("post_logout_redirect_uris should be omitted when empty")
		}
	}
}

func TestOIDCClientInputValidatesPostLogoutRedirectURIs(t *testing.T) {
	base := oidcClientInput{
		ID:           "e6irc-dev",
		Name:         "e6irc",
		Secret:       "0123456789abcdef0123456789abcdef",
		RedirectURIs: []string{"https://e6irc.dev.e6qu.dev/api/v1/auth/oidc/shauth/callback"},
	}
	ok := base
	ok.PostLogoutRedirectURIs = []string{"https://e6irc.dev.e6qu.dev"}
	if err := ok.validate(); err != nil {
		t.Fatalf("valid post-logout URI rejected: %v", err)
	}
	for name, uri := range map[string]string{
		"insecure": "http://e6irc.dev.e6qu.dev",
		"fragment": "https://e6irc.dev.e6qu.dev/#x",
		"relative": "/logged-out",
	} {
		t.Run(name, func(t *testing.T) {
			bad := base
			bad.PostLogoutRedirectURIs = []string{uri}
			if err := bad.validate(); err == nil {
				t.Fatalf("validate accepted invalid post-logout URI %q", uri)
			}
		})
	}
}
