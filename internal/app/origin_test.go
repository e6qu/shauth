// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCSRFPostsAllowsOAuthTokenExchangeWithoutOrigin(t *testing.T) {
	publicURL, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	handler := csrfPosts(publicURL, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodPost, "https://auth.example.test/oauth2/token", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestCSRFPostsRejectsBrowserPostWithoutToken(t *testing.T) {
	publicURL, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	handler := csrfPosts(publicURL, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodPost, "https://auth.example.test/login", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestCSRFPostsRejectsCrossOriginBrowserPost(t *testing.T) {
	publicURL, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	handler := csrfPosts(publicURL, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodPost, "https://auth.example.test/logout", nil)
	request.Header.Set("Origin", "https://attacker.example.test")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestCSRFPostsAllowsSameOriginBrowserPost(t *testing.T) {
	publicURL, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	handler := csrfPosts(publicURL, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodPost, "https://auth.example.test/logout", nil)
	request.Header.Set("Origin", "https://auth.example.test")
	request.AddCookie(&http.Cookie{Name: csrfCookie, Value: "token"})
	request.Form = url.Values{"_csrf": {"token"}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestCSRFPostsAllowsNullOriginBrowserPost(t *testing.T) {
	publicURL, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	handler := csrfPosts(publicURL, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodPost, "https://auth.example.test/login", nil)
	request.Header.Set("Origin", "null")
	request.AddCookie(&http.Cookie{Name: csrfCookie, Value: "token"})
	request.Form = url.Values{"_csrf": {"token"}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestCSRFPostsRejectsOriginWithPath(t *testing.T) {
	publicURL, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	handler := csrfPosts(publicURL, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodPost, "https://auth.example.test/logout", nil)
	request.Header.Set("Origin", "https://auth.example.test/not-an-origin")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestOAuthFormPolicyAllowsRegisteredApplicationRedirectSchemes(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		allowOIDCFormAction(w)
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodGet, "https://auth.example.test/login", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if got := response.Header().Get("Content-Security-Policy"); got != oidcContentSecurityPolicy {
		t.Fatalf("content security policy = %q, want %q", got, oidcContentSecurityPolicy)
	}
}

func TestDefaultFormPolicyRemainsSameOrigin(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodGet, "https://auth.example.test/admin", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if got := response.Header().Get("Content-Security-Policy"); got != baseContentSecurityPolicy {
		t.Fatalf("content security policy = %q, want %q", got, baseContentSecurityPolicy)
	}
}

func TestOIDCNextDetection(t *testing.T) {
	tests := map[string]bool{
		"/oauth/login?login_challenge=challenge":     true,
		"/oauth/consent?consent_challenge=challenge": true,
		"/oauth/logout?logout_challenge=challenge":   false,
		"/apps": false,
		"https://attacker.example.test/oauth/login": false,
	}
	for next, want := range tests {
		if got := isOIDCNext(relativeNext(next)); got != want {
			t.Errorf("isOIDCNext(%q) = %t, want %t", next, got, want)
		}
	}
}

func TestGitHubStateCookieNamesArePerTransaction(t *testing.T) {
	first := strings.Repeat("a", 64)
	second := strings.Repeat("b", 64)
	firstName, firstOK := validGitHubStateCookieName(first)
	secondName, secondOK := validGitHubStateCookieName(second)
	if !firstOK || !secondOK || firstName == secondName {
		t.Fatalf("valid GitHub states did not produce distinct cookie names")
	}
	for _, invalid := range []string{"", "short", strings.Repeat("z", 64), strings.Repeat("a", 62)} {
		if _, ok := validGitHubStateCookieName(invalid); ok {
			t.Errorf("invalid GitHub state %q produced a cookie name", invalid)
		}
	}
}

func TestLoginPreservesOIDCTransactionForGitHub(t *testing.T) {
	templates, err := template.New("pages").Parse(pageTemplates)
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	server := &Server{templates: templates}
	request := httptest.NewRequest(http.MethodGet, "/login?next=%2Foauth%2Flogin%3Flogin_challenge%3Dchallenge", nil)
	response := httptest.NewRecorder()

	server.login(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), `/oauth/github?next=%2Foauth%2Flogin%3Flogin_challenge%3Dchallenge`) {
		t.Fatalf("GitHub login link did not preserve the OIDC transaction")
	}
	if got := response.Header().Get("Content-Security-Policy"); got != oidcContentSecurityPolicy {
		t.Fatalf("content security policy = %q, want %q", got, oidcContentSecurityPolicy)
	}
}
