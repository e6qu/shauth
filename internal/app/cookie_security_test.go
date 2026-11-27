// SPDX-License-Identifier: AGPL-3.0-or-later
package app

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestHTTPSCookiesRejectParentDomainInjection(t *testing.T) {
	server := &Server{}
	response := httptest.NewRecorder()
	server.setCookie(response, &http.Cookie{Name: browserSessionCookie, Value: "session", Path: "/", Secure: true, HttpOnly: true})
	server.setCookie(response, &http.Cookie{Name: githubStateCookiePrefix + strings.Repeat("a", 64), Value: "transaction", Path: "/oauth/github/callback", Secure: true, HttpOnly: true})
	for _, cookie := range response.Result().Cookies() {
		if !strings.HasPrefix(cookie.Name, "__Host-") || !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" {
			t.Errorf("cookie %q is not protected against parent-domain injection", cookie.Name)
		}
	}
}

func TestHTTPSCSRFRejectsUnprefixedCookie(t *testing.T) {
	publicURL, _ := url.Parse("https://auth.example.test")
	server := &Server{}
	// This is the real password handler. CSRF rejection must occur before any
	// password or database operation, even with a matching injected form token.
	handler := csrfPosts(publicURL, http.HandlerFunc(server.passwordLogin))
	request := httptest.NewRequest(http.MethodPost, publicURL.String()+"/login", strings.NewReader("_csrf=injected&username=someone&password=invalid"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "null")
	request.AddCookie(&http.Cookie{Name: csrfCookie, Value: "injected"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("injected cookie status = %d, want 403", response.Code)
	}
}
