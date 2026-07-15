// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import "testing"

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
