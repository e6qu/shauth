// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestPreservedPublicLogoutSessions(t *testing.T) {
	t.Run("Hydra session identifier", func(t *testing.T) {
		actual, err := preservedPublicLogoutSessions("provider-session", []string{"provider-session", "browser-session"})
		if err != nil {
			t.Fatalf("preserve session: %v", err)
		}
		if !reflect.DeepEqual(actual, []string{"provider-session"}) {
			t.Fatalf("preserved sessions = %#v", actual)
		}
	})

	t.Run("different Hydra session identifier", func(t *testing.T) {
		if _, err := preservedPublicLogoutSessions("other-session", []string{"browser-session"}); err == nil {
			t.Fatal("provider logout for a different browser session was accepted")
		}
	})

	t.Run("omitted Hydra session identifier", func(t *testing.T) {
		browserSessions := []string{"browser-session-a", "browser-session-b"}
		actual, err := preservedPublicLogoutSessions("", browserSessions)
		if err != nil {
			t.Fatalf("preserve browser sessions: %v", err)
		}
		if !reflect.DeepEqual(actual, browserSessions) {
			t.Fatalf("preserved sessions = %#v", actual)
		}
		actual[0] = "changed"
		if browserSessions[0] != "browser-session-a" {
			t.Fatal("preserved sessions alias the store result")
		}
	})

	t.Run("uncorrelated request", func(t *testing.T) {
		if _, err := preservedPublicLogoutSessions("", nil); err == nil {
			t.Fatal("uncorrelated public logout was accepted")
		}
	})
}

func TestLogoutCompletionWithoutCookieIgnoresQueryAndDoesNotLoop(t *testing.T) {
	server := &Server{}
	request := httptest.NewRequest(http.MethodGet, "https://auth.example.test/oauth/logout/complete?next=https%3A%2F%2Fattacker.example&redirect_uri=https%3A%2F%2Fattacker.example", nil)
	response := httptest.NewRecorder()
	server.logoutComplete(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", response.Code)
	}
	if location := response.Header().Get("Location"); location != "/signed-out" {
		t.Fatalf("missing-cookie destination = %q", location)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("logout completion response was cacheable")
	}
}

func TestLogoutRecoveryDelayIsBounded(t *testing.T) {
	for _, test := range []struct {
		attempt int
		want    time.Duration
	}{{-1, 5 * time.Second}, {1, 5 * time.Second}, {2, 10 * time.Second}, {6, 160 * time.Second}, {100, 160 * time.Second}} {
		if got := logoutRecoveryDelay(test.attempt); got != test.want {
			t.Fatalf("attempt %d: delay = %s, want %s", test.attempt, got, test.want)
		}
	}
}
