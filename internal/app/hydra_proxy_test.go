// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
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
