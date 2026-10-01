// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEnsureRedirectBodyAddsBodyForUnknownLengthRedirect(t *testing.T) {
	response := &http.Response{
		StatusCode:    http.StatusSeeOther,
		ContentLength: -1,
		Header:        http.Header{"Location": {"https://app.example.test/callback"}},
		Body:          io.NopCloser(strings.NewReader("")),
	}

	if err := ensureRedirectBody(response); err != nil {
		t.Fatalf("ensure redirect body: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if got, want := string(body), "<a href=\"https://app.example.test/callback\">See Other</a>.\n"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
	if got, want := response.ContentLength, int64(len(body)); got != want {
		t.Fatalf("content length = %d, want %d", got, want)
	}
	if got, want := response.Header.Get("Content-Length"), strconv.Itoa(len(body)); got != want {
		t.Fatalf("content-length header = %q, want %q", got, want)
	}
}

func TestEnsureRedirectBodyPreservesExistingRedirectBody(t *testing.T) {
	response := &http.Response{
		StatusCode: http.StatusFound,
		Header:     http.Header{"Location": {"https://app.example.test/callback"}},
		Body:       io.NopCloser(strings.NewReader("redirecting")),
	}

	if err := ensureRedirectBody(response); err != nil {
		t.Fatalf("ensure redirect body: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if got, want := string(body), "redirecting"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestRedirectTargetExcludesOAuthQuery(t *testing.T) {
	if got, want := redirectTarget("https://app.example.test/callback?code=secret&state=secret"), "app.example.test/callback"; got != want {
		t.Fatalf("redirect target = %q, want %q", got, want)
	}
}

func TestRedirectTargetRejectsRelativeLocation(t *testing.T) {
	if got, want := redirectTarget("/callback"), "invalid"; got != want {
		t.Fatalf("redirect target = %q, want %q", got, want)
	}
}

// A dependency failure is logged, and the log is readable by administrators
// and the logs API, so it must not repeat the challenge in the request URL.
func TestProviderRequestFailuresOmitTheQueryString(t *testing.T) {
	server := &Server{httpClient: &http.Client{Timeout: time.Second}}
	request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:1/admin/oauth2/auth/requests/logout?logout_challenge=secret-challenge", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.doProvider(request)
	if err == nil {
		t.Fatal("a request to a closed port succeeded")
	}
	if strings.Contains(err.Error(), "secret-challenge") || !strings.Contains(err.Error(), "/admin/oauth2/auth/requests/logout") {
		t.Fatalf("provider failure = %q, want the endpoint without its query", err)
	}
}
