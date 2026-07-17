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

func TestSameStrings(t *testing.T) {
	if !sameStrings([]string{"a", "b"}, []string{"a", "b"}) {
		t.Fatal("sameStrings rejected identical values")
	}
	if sameStrings([]string{"a", "b"}, []string{"b", "a"}) {
		t.Fatal("sameStrings accepted reordered values")
	}
	if sameStrings([]string{"a"}, []string{"a", "b"}) {
		t.Fatal("sameStrings accepted differently sized values")
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
	if !sameStrings(payload.GrantTypes, []string{"authorization_code", "refresh_token"}) {
		t.Fatalf("grant types = %#v", payload.GrantTypes)
	}
	if payload.TokenEndpointAuthMethod != "client_secret_post" {
		t.Fatalf("token endpoint auth method = %q", payload.TokenEndpointAuthMethod)
	}
}
