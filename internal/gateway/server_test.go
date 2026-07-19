// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

func TestGatewaySecurityHeadersDoNotOverrideUpstreamFramingPolicy(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'")
		response.Header().Set("X-Frame-Options", "SAMEORIGIN")
		response.Header().Set("Referrer-Policy", "strict-origin")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	server := &Server{config: Config{Issuer: issuer}}
	request := httptest.NewRequest(http.MethodGet, "https://console.example.test/terminal/", nil)
	response := httptest.NewRecorder()
	server.securityHeaders(proxy).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
	want := map[string]string{
		"Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
		"X-Frame-Options":         "SAMEORIGIN",
		"Referrer-Policy":         "strict-origin",
		"X-Content-Type-Options":  "nosniff",
	}
	for name, expected := range want {
		if actual := response.Header().Get(name); actual != expected {
			t.Errorf("%s = %q, want upstream value %q", name, actual, expected)
		}
	}
}

func TestGatewayAuthHandlersRetainGatewaySecurityPolicy(t *testing.T) {
	t.Parallel()
	issuer, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{config: Config{Issuer: issuer}}
	request := httptest.NewRequest(http.MethodGet, "https://console.example.test/auth/healthz", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	wantCSP := "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' https://auth.example.test"
	if actual := response.Header().Get("Content-Security-Policy"); actual != wantCSP {
		t.Fatalf("Content-Security-Policy = %q, want %q", actual, wantCSP)
	}
	if actual := response.Header().Get("X-Frame-Options"); actual != "DENY" {
		t.Fatalf("X-Frame-Options = %q, want DENY", actual)
	}
}

func TestValidLogoutEvent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		events map[string]json.RawMessage
		want   bool
	}{
		{name: "empty object", events: map[string]json.RawMessage{logoutEvent: json.RawMessage(`{}`)}, want: true},
		{name: "nonempty object", events: map[string]json.RawMessage{logoutEvent: json.RawMessage(`{"reason":"administrator"}`)}, want: false},
		{name: "missing event", events: map[string]json.RawMessage{}, want: false},
		{name: "null", events: map[string]json.RawMessage{logoutEvent: json.RawMessage(`null`)}, want: false},
		{name: "string", events: map[string]json.RawMessage{logoutEvent: json.RawMessage(`"logout"`)}, want: false},
		{name: "array", events: map[string]json.RawMessage{logoutEvent: json.RawMessage(`[]`)}, want: false},
		{name: "invalid JSON", events: map[string]json.RawMessage{logoutEvent: json.RawMessage(`{`)}, want: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validLogoutEvent(test.events); got != test.want {
				t.Fatalf("validLogoutEvent() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestBackchannelLogoutRequiresBodyFormParameter(t *testing.T) {
	t.Parallel()
	server := &Server{}
	for name, request := range map[string]*http.Request{
		"query parameter":      httptest.NewRequest(http.MethodPost, "https://app.example.test/auth/backchannel-logout?logout_token=query", strings.NewReader("")),
		"duplicate body value": httptest.NewRequest(http.MethodPost, "https://app.example.test/auth/backchannel-logout", strings.NewReader("logout_token=one&logout_token=two")),
	} {
		t.Run(name, func(t *testing.T) {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			server.backchannelLogout(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("back-channel logout response was cacheable")
			}
		})
	}
}

func TestBackchannelLogoutRejectsInvalidMediaTypePrefix(t *testing.T) {
	t.Parallel()
	server := &Server{}
	request := httptest.NewRequest(http.MethodPost, "https://app.example.test/auth/backchannel-logout", strings.NewReader("logout_token=value"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded-malicious")
	response := httptest.NewRecorder()
	server.backchannelLogout(response, request)
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnsupportedMediaType)
	}
}

func TestEndSessionURLIdentifiesClientWithoutLocalSession(t *testing.T) {
	t.Parallel()
	postLogout, err := url.Parse("https://app.example.test/auth/signed-out")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{config: Config{ClientID: "app-client", PostLogoutURL: postLogout}, endSessionEndpoint: "https://auth.example.test/oauth2/sessions/logout"}
	for name, idToken := range map[string]string{"active session": "signed.id.token", "missing session": ""} {
		t.Run(name, func(t *testing.T) {
			target, err := url.Parse(server.endSessionURL(idToken))
			if err != nil {
				t.Fatal(err)
			}
			if target.Query().Get("client_id") != "app-client" || target.Query().Get("post_logout_redirect_uri") != postLogout.String() {
				t.Fatalf("logout request omitted registered client coordinates: %s", target)
			}
			if target.Query().Get("id_token_hint") != idToken {
				t.Fatalf("id_token_hint = %q, want %q", target.Query().Get("id_token_hint"), idToken)
			}
		})
	}
}

func TestSessionEncryptionAdditionalDataBindsIdentity(t *testing.T) {
	t.Parallel()
	base := Session{ID: "session", Subject: "subject", ProviderSessionID: "provider-session"}
	want := string(sessionAdditionalData("client", "https://issuer.example", base))
	for name, value := range map[string]string{
		"client":           string(sessionAdditionalData("another-client", "https://issuer.example", base)),
		"issuer":           string(sessionAdditionalData("client", "https://other-issuer.example", base)),
		"session":          string(sessionAdditionalData("client", "https://issuer.example", Session{ID: "another-session", Subject: base.Subject, ProviderSessionID: base.ProviderSessionID})),
		"subject":          string(sessionAdditionalData("client", "https://issuer.example", Session{ID: base.ID, Subject: "another-subject", ProviderSessionID: base.ProviderSessionID})),
		"provider session": string(sessionAdditionalData("client", "https://issuer.example", Session{ID: base.ID, Subject: base.Subject, ProviderSessionID: "another-provider-session"})),
	} {
		if value == want {
			t.Errorf("%s was not bound into encrypted session additional data", name)
		}
	}
}

func TestInvalidFrontchannelLogoutDoesNotClearApplicationCookie(t *testing.T) {
	t.Parallel()
	issuer, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{config: Config{Issuer: issuer}}
	request := httptest.NewRequest(http.MethodGet, "https://app.example.test/auth/frontchannel-logout?iss=https%3A%2F%2Fattacker.example&sid=provider-session", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: strings.Repeat("a", 43)})
	response := httptest.NewRecorder()
	server.frontchannelLogout(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if values := response.Header().Values("Set-Cookie"); len(values) != 0 {
		t.Fatalf("invalid logout request changed application cookies: %q", values)
	}
}

func TestGatewayCookiesAreRemovedBeforeProxying(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodGet, "https://app.example.test/", nil)
	request.AddCookie(&http.Cookie{Name: configCookieName(false), Value: "session"})
	request.AddCookie(&http.Cookie{Name: configTransactionCookieName(false), Value: "transaction"})
	request.AddCookie(&http.Cookie{Name: "application-preference", Value: "dark"})
	removeCookie(request, configCookieName(false))
	removeCookie(request, configTransactionCookieName(false))
	if got := request.Header.Get("Cookie"); got != "application-preference=dark" {
		t.Fatalf("proxied Cookie header = %q", got)
	}
}

func TestProxyHeadersUseConfiguredPublicCoordinates(t *testing.T) {
	t.Parallel()
	publicURL, err := url.Parse("https://app.example.test")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://upstream.internal/", nil)
	request.Header.Set("Authorization", "Bearer attacker")
	request.Header.Set("Forwarded", "for=attacker;host=attacker.example;proto=http")
	request.Header.Set("X-Forwarded-For", "192.0.2.1")
	request.Header.Set("X-Forwarded-Host", "attacker.example")
	request.Header.Set("X-Forwarded-Proto", "http")
	request.Header.Set("X-Forwarded-Role", "admin")
	request.Header.Set("X-Real-IP", "192.0.2.1")
	sanitizeProxyHeaders(request, Config{PublicURL: publicURL})
	for _, name := range []string{"Authorization", "Forwarded", "X-Forwarded-For", "X-Forwarded-Role", "X-Real-IP"} {
		if value := request.Header.Get(name); value != "" {
			t.Errorf("spoofable %s header survived: %q", name, value)
		}
	}
	if request.Header.Get("X-Forwarded-Host") != "app.example.test" || request.Header.Get("X-Forwarded-Proto") != "https" {
		t.Fatalf("public forwarding coordinates were not set: %#v", request.Header)
	}
}
