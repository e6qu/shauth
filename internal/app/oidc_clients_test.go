// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/json"
	"testing"

	"github.com/e6qu/shauth/internal/identity"
)

func TestOIDCClientInputValidate(t *testing.T) {
	valid := oidcClientInput{
		ID:                     "intraktible-dev",
		Name:                   "Intraktible development",
		Secret:                 "0123456789abcdef0123456789abcdef",
		RedirectURIs:           []string{"https://intraktible.dev.e6qu.dev/v1/auth/oidc/shauth/callback"},
		PostLogoutRedirectURIs: []string{"https://intraktible.dev.e6qu.dev/"},
		FrontChannelLogoutURI:  "https://intraktible.dev.e6qu.dev/v1/auth/oidc/shauth/frontchannel-logout",
		BackChannelLogoutURI:   "https://intraktible.dev.e6qu.dev/v1/auth/oidc/shauth/backchannel-logout",
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
		"front-channel origin mismatch": func(input *oidcClientInput) {
			input.FrontChannelLogoutURI = "https://attacker.example.test/frontchannel-logout"
		},
		"back-channel origin mismatch": func(input *oidcClientInput) {
			input.BackChannelLogoutURI = "https://attacker.example.test/backchannel-logout"
		},
		"post-logout origin mismatch": func(input *oidcClientInput) {
			input.PostLogoutRedirectURIs = []string{"https://attacker.example.test/signed-out"}
		},
		"fragment": func(input *oidcClientInput) {
			input.RedirectURIs = []string{"https://intraktible.dev.e6qu.dev/callback#fragment"}
		},
		"missing logout receiver": func(input *oidcClientInput) {
			input.FrontChannelLogoutURI = ""
			input.BackChannelLogoutURI = ""
		},
		"missing post-logout redirect": func(input *oidcClientInput) { input.PostLogoutRedirectURIs = nil },
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

func TestOIDCClientInputAllowsEitherLogoutChannel(t *testing.T) {
	base := oidcClientInput{
		ID:                     "logout-client",
		Name:                   "Logout client",
		Secret:                 "0123456789abcdef0123456789abcdef",
		RedirectURIs:           []string{"https://app.example.test/callback"},
		PostLogoutRedirectURIs: []string{"https://app.example.test/"},
	}
	for name, input := range map[string]oidcClientInput{
		"front channel only": func() oidcClientInput {
			value := base
			value.FrontChannelLogoutURI = "https://app.example.test/frontchannel-logout"
			return value
		}(),
		"back channel only": func() oidcClientInput {
			value := base
			value.BackChannelLogoutURI = "https://app.example.test/backchannel-logout"
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := input.validate(); err != nil {
				t.Fatalf("validate() error = %v", err)
			}
		})
	}
}

func TestOIDCClientInputAllowsLoopbackHTTP(t *testing.T) {
	input := oidcClientInput{
		ID:                     "local-client",
		Name:                   "Local client",
		Secret:                 "0123456789abcdef0123456789abcdef",
		RedirectURIs:           []string{"http://app.localhost:8080/callback", "http://app.localhost:8080/second-callback"},
		PostLogoutRedirectURIs: []string{"http://app.localhost:8080/"},
		BackChannelLogoutURI:   "http://app.localhost:8080/backchannel-logout",
	}
	if err := input.validate(); err != nil {
		t.Fatalf("validate loopback client: %v", err)
	}
}

func TestMarshalHydraClientOmitsUnusedLogoutChannel(t *testing.T) {
	body, err := marshalHydraClient(oidcClientInput{
		ID:                     "frontchannel-client",
		Name:                   "Front-channel client",
		Secret:                 "a-very-long-client-secret-that-is-safe-for-a-test",
		RedirectURIs:           []string{"https://app.example.test/callback"},
		PostLogoutRedirectURIs: []string{"https://app.example.test/"},
		FrontChannelLogoutURI:  "https://app.example.test/frontchannel-logout",
	}, identity.DefaultSessionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["frontchannel_logout_uri"] == nil || payload["frontchannel_logout_session_required"] != true {
		t.Fatalf("front-channel metadata = %#v", payload)
	}
	if _, exists := payload["backchannel_logout_uri"]; exists {
		t.Fatalf("unused back-channel URI was registered: %#v", payload)
	}
	if _, exists := payload["backchannel_logout_session_required"]; exists {
		t.Fatalf("unused back-channel session flag was registered: %#v", payload)
	}
}

func TestMarshalHydraClientUsesConfidentialAuthorizationCodeFlow(t *testing.T) {
	body, err := marshalHydraClient(oidcClientInput{
		ID:                     "intraktible-dev",
		Name:                   "Intraktible",
		Secret:                 "a-very-long-client-secret-that-is-safe-for-a-test",
		RedirectURIs:           []string{"https://intraktible.example.test/v1/auth/oidc/shauth/callback"},
		PostLogoutRedirectURIs: []string{"https://intraktible.example.test/"},
		FrontChannelLogoutURI:  "https://intraktible.example.test/oidc/frontchannel-logout",
		BackChannelLogoutURI:   "https://intraktible.example.test/oidc/backchannel-logout",
	}, identity.DefaultSessionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		ClientID                string   `json:"client_id"`
		ClientSecret            string   `json:"client_secret"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
		FrontChannelLogoutURI   string   `json:"frontchannel_logout_uri"`
		BackChannelLogoutURI    string   `json:"backchannel_logout_uri"`
		FrontSessionRequired    bool     `json:"frontchannel_logout_session_required"`
		BackSessionRequired     bool     `json:"backchannel_logout_session_required"`
		AccessTokenLifespan     string   `json:"authorization_code_grant_access_token_lifespan"`
		IDTokenLifespan         string   `json:"authorization_code_grant_id_token_lifespan"`
		RefreshTokenLifespan    string   `json:"authorization_code_grant_refresh_token_lifespan"`
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
	if !sameStringSet(payload.ResponseTypes, []string{"code"}) {
		t.Fatalf("response types = %#v", payload.ResponseTypes)
	}
	if payload.TokenEndpointAuthMethod != "client_secret_post" {
		t.Fatalf("token endpoint auth method = %q", payload.TokenEndpointAuthMethod)
	}
	if payload.FrontChannelLogoutURI == "" || payload.BackChannelLogoutURI == "" || len(payload.PostLogoutRedirectURIs) != 1 {
		t.Fatalf("logout metadata = %#v", payload)
	}
	if !payload.FrontSessionRequired || !payload.BackSessionRequired {
		t.Fatalf("logout session correlation is not required: %#v", payload)
	}
	if payload.AccessTokenLifespan != "15m0s" || payload.IDTokenLifespan != "15m0s" || payload.RefreshTokenLifespan != "720h0m0s" {
		t.Fatalf("token lifespans = %#v", payload)
	}
}

func TestManagedAppAndOIDCClientRegistrationContract(t *testing.T) {
	app := identity.ManagedApp{
		LaunchURL:    "https://app.example.test/ui",
		OIDCClientID: "app-client",
		SignedOutURL: "https://app.example.test/auth/signed-out",
	}
	client := oidcClient{
		ID:                     "app-client",
		RedirectURIs:           []string{"https://app.example.test/auth/callback"},
		PostLogoutRedirectURIs: []string{"https://app.example.test/other-signed-out", app.SignedOutURL},
		BackChannelLogoutURI:   "https://app.example.test/auth/backchannel-logout",
	}
	if err := validateManagedAppClient(app, client); err != nil {
		t.Fatalf("matching registration rejected: %v", err)
	}

	for name, mutate := range map[string]func(*identity.ManagedApp, *oidcClient){
		"missing client": func(_ *identity.ManagedApp, client *oidcClient) {
			client.ID = ""
		},
		"application origin mismatch": func(app *identity.ManagedApp, _ *oidcClient) {
			app.LaunchURL = "https://other.example.test/ui"
		},
		"missing post-logout redirect": func(_ *identity.ManagedApp, client *oidcClient) {
			client.PostLogoutRedirectURIs = nil
		},
		"same-origin wrong path": func(_ *identity.ManagedApp, client *oidcClient) {
			client.PostLogoutRedirectURIs = []string{"https://app.example.test/auth/other-signed-out"}
		},
		"trailing slash mismatch": func(_ *identity.ManagedApp, client *oidcClient) {
			client.PostLogoutRedirectURIs = []string{"https://app.example.test/auth/signed-out/"}
		},
		"path normalization mismatch": func(_ *identity.ManagedApp, client *oidcClient) {
			client.PostLogoutRedirectURIs = []string{"https://app.example.test/auth/../auth/signed-out"}
		},
		"host spelling mismatch": func(_ *identity.ManagedApp, client *oidcClient) {
			client.PostLogoutRedirectURIs = []string{"https://APP.example.test/auth/signed-out"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changedApp := app
			changedClient := client
			mutate(&changedApp, &changedClient)
			if err := validateManagedAppClient(changedApp, changedClient); err == nil {
				t.Fatal("invalid managed app and OpenID Connect client registration was accepted")
			}
		})
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
	}, identity.DefaultSessionPolicy())
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
	}, identity.DefaultSessionPolicy())
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
		ID:                   "e6irc-dev",
		Name:                 "e6irc",
		Secret:               "0123456789abcdef0123456789abcdef",
		RedirectURIs:         []string{"https://e6irc.dev.e6qu.dev/api/v1/auth/oidc/shauth/callback"},
		BackChannelLogoutURI: "https://e6irc.dev.e6qu.dev/api/v1/auth/oidc/shauth/backchannel-logout",
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
		"userinfo": "https://user:password@e6irc.dev.e6qu.dev/",
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
