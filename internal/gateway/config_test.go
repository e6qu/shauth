// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestLoadRequiresCompleteSecureCoordinates(t *testing.T) {
	base := map[string]string{
		"OIDC_GATEWAY_ISSUER":          "https://auth.example.test",
		"OIDC_GATEWAY_CLIENT_ID":       "console",
		"OIDC_GATEWAY_CLIENT_SECRET":   "0123456789abcdef0123456789abcdef",
		"OIDC_GATEWAY_PUBLIC_URL":      "https://console.example.test",
		"OIDC_GATEWAY_UPSTREAM_URL":    "http://127.0.0.1:7681",
		"OIDC_GATEWAY_POST_LOGOUT_URL": "https://console.example.test/auth/signed-out",
		"OIDC_GATEWAY_COOKIE_SECRET":   "abcdef0123456789abcdef0123456789",
		"DATABASE_URL":                 "postgres://localhost/shauth",
	}
	getenv := func(name string) string { return base[name] }
	config, err := Load(getenv)
	if err != nil {
		t.Fatal(err)
	}
	if config.Address != ":4180" || config.ClientID != "console" || config.UpstreamURL.String() != "http://127.0.0.1:7681" {
		t.Fatalf("unexpected config: %#v", config)
	}

	base["OIDC_GATEWAY_PUBLIC_URL"] = "http://console.example.test"
	if _, err := Load(getenv); err == nil {
		t.Fatal("insecure public URL was accepted")
	}
	base["OIDC_GATEWAY_ALLOW_INSECURE_COOKIE"] = "true"
	if _, err := Load(getenv); err == nil {
		t.Fatal("insecure-cookie mode accepted a remote public URL")
	}
	base["OIDC_GATEWAY_ISSUER"] = "http://localhost:8080"
	base["OIDC_GATEWAY_PUBLIC_URL"] = "http://localhost:4180"
	base["OIDC_GATEWAY_POST_LOGOUT_URL"] = "http://localhost:4180/auth/signed-out"
	if _, err := Load(getenv); err != nil {
		t.Fatalf("explicit loopback insecure-cookie mode was rejected: %v", err)
	}
	base["OIDC_GATEWAY_SESSION_MAX_AGE"] = "4m"
	if _, err := Load(getenv); err == nil {
		t.Fatal("too-short application session lifetime was accepted")
	}
}

func TestSecurityHeadersAllowOnlyApplicationAndIssuerForms(t *testing.T) {
	issuer, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{config: Config{Issuer: issuer}}
	request := httptest.NewRequest(http.MethodGet, "https://console.example.test/", nil)
	response := httptest.NewRecorder()
	server.securityHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(response, request)
	want := "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' https://auth.example.test"
	if actual := response.Header().Get("Content-Security-Policy"); actual != want {
		t.Fatalf("Content-Security-Policy = %q, want %q", actual, want)
	}
}

func TestLoadRejectsProviderOriginAsPostLogoutDestination(t *testing.T) {
	values := map[string]string{
		"OIDC_GATEWAY_ISSUER":          "https://auth.example.test",
		"OIDC_GATEWAY_CLIENT_ID":       "console",
		"OIDC_GATEWAY_CLIENT_SECRET":   "0123456789abcdef0123456789abcdef",
		"OIDC_GATEWAY_PUBLIC_URL":      "https://console.example.test",
		"OIDC_GATEWAY_UPSTREAM_URL":    "http://127.0.0.1:7681",
		"OIDC_GATEWAY_POST_LOGOUT_URL": "https://auth.example.test/apps",
		"OIDC_GATEWAY_COOKIE_SECRET":   "abcdef0123456789abcdef0123456789",
		"DATABASE_URL":                 "postgres://localhost/shauth",
	}
	if _, err := Load(func(name string) string { return values[name] }); err == nil {
		t.Fatal("provider-origin post-logout redirect was accepted")
	}
}

func TestSameOriginAcceptsBrowserOriginOrReferer(t *testing.T) {
	publicURL, err := url.Parse("http://localhost:5556")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{config: Config{PublicURL: publicURL}}
	for name, headers := range map[string]map[string]string{
		"origin":         {"Origin": "http://localhost:5556"},
		"referer":        {"Referer": "http://localhost:5556/terminal"},
		"fetch metadata": {"Origin": "null", "Sec-Fetch-Site": "same-origin"},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "http://localhost:5556/auth/logout", nil)
			for header, value := range headers {
				request.Header.Set(header, value)
			}
			if !server.sameOrigin(request) {
				t.Fatalf("same-origin %s was rejected", name)
			}
		})
	}
	request := httptest.NewRequest("POST", "http://localhost:5556/auth/logout", nil)
	request.Header.Set("Origin", "https://attacker.example")
	request.Header.Set("Referer", "http://localhost:5556/")
	if server.sameOrigin(request) {
		t.Fatal("cross-origin request was accepted through its referer")
	}
}

func TestRelativeReturnToRejectsExternalAndNetworkPathTargets(t *testing.T) {
	for input, expected := range map[string]string{
		"":                         "/",
		"/terminal?workspace=dev":  "/terminal?workspace=dev",
		"https://attacker.test/":   "/",
		"//attacker.test/terminal": "/",
		"terminal":                 "/",
	} {
		if actual := relativeReturnTo(input); actual != expected {
			t.Errorf("relativeReturnTo(%q) = %q, want %q", input, actual, expected)
		}
	}
}
