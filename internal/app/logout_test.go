// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/e6qu/shauth/internal/config"
)

func TestHydraLogoutWithoutShauthCookieAcceptsTrustedChallenge(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := ""
		switch r.URL.Path {
		case "/admin/oauth2/auth/requests/logout":
			if r.URL.Query().Get("logout_challenge") != "trusted-challenge" {
				t.Fatalf("logout challenge = %q", r.URL.Query().Get("logout_challenge"))
			}
			body = `{"subject":"user-1"}`
		case "/admin/oauth2/auth/requests/logout/accept":
			body = `{"redirect_to":"https://client.example.test/signed-out"}`
		default:
			t.Fatalf("unexpected Hydra request %s", r.URL.String())
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	hydraURL, err := url.Parse("http://hydra.test")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{config: configWithHydraAdminURL(hydraURL), httpClient: httpClient}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://auth.example.test/oauth/logout?logout_challenge=trusted-challenge", nil)

	server.hydraLogout(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d; body=%q", recorder.Code, http.StatusSeeOther, recorder.Body.String())
	}
	if location := recorder.Header().Get("Location"); location != "https://client.example.test/signed-out" {
		t.Fatalf("Location = %q", location)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func configWithHydraAdminURL(adminURL *url.URL) config.Config {
	return config.Config{HydraAdminURL: adminURL}
}
