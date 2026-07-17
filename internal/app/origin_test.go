package app

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestSameOriginPostsAllowsOAuthTokenExchangeWithoutOrigin(t *testing.T) {
	publicURL, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	handler := sameOriginPosts(publicURL, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodPost, "https://auth.example.test/oauth2/token", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestSameOriginPostsStillRequiresOriginForBrowserPost(t *testing.T) {
	publicURL, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	handler := sameOriginPosts(publicURL, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodPost, "https://auth.example.test/login", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}
