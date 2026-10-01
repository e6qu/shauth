// SPDX-License-Identifier: AGPL-3.0-or-later

package github

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseTeam(t *testing.T) {
	organization, slug, err := ParseTeam("example-org/admins")
	if err != nil {
		t.Fatalf("ParseTeam() error = %v", err)
	}
	if organization != "example-org" || slug != "admins" {
		t.Fatalf("ParseTeam() = %q/%q", organization, slug)
	}
}

func TestParseTeamRejectsInvalidValue(t *testing.T) {
	if _, _, err := ParseTeam("example-org"); err == nil {
		t.Fatal("ParseTeam() accepted an invalid team")
	}
}

// requireGitHubContract answers a request exactly the way the real GitHub API
// does when a required header is missing: a 403 with GitHub's own rejection
// message, rather than serving the fixture response. If newRequest ever
// drops one of these headers again, the fixture server rejects the call the
// same way the real API would, and the test fails.
func requireGitHubContract(t *testing.T, w http.ResponseWriter, r *http.Request, accessToken string) bool {
	t.Helper()
	if r.Header.Get("User-Agent") == "" {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Request forbidden by administrative rules. Please make sure your request has a User-Agent header (http://developer.github.com/v3/#user-agent-required)"}`))
		return false
	}
	if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
		w.WriteHeader(http.StatusNotAcceptable)
		_, _ = w.Write([]byte(`{"message":"must accept application/vnd.github+json"}`))
		return false
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+accessToken {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
		return false
	}
	if r.Header.Get("X-GitHub-Api-Version") == "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"unsupported api version"}`))
		return false
	}
	return true
}

func newTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	client, err := NewClient(server.Client(), WithBaseURL(server.URL))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	return client
}

func TestProfileSendsTheHeadersGitHubRequires(t *testing.T) {
	const accessToken = "gho_test_token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireGitHubContract(t, w, r, accessToken) {
			return
		}
		switch r.URL.Path {
		case userPath:
			_ = json.NewEncoder(w).Encode(Profile{ID: 1, Login: "octocat"})
		case emailsPath:
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"email": "octocat@example.com", "primary": true, "verified": true},
			})
		default:
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	profile, err := newTestClient(t, server).Profile(t.Context(), accessToken)
	if err != nil {
		t.Fatalf("Profile() error = %v", err)
	}
	if profile.Login != "octocat" || profile.Email != "octocat@example.com" {
		t.Fatalf("Profile() = %+v", profile)
	}
}

func TestTeamsSendsTheHeadersGitHubRequires(t *testing.T) {
	const accessToken = "gho_test_token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireGitHubContract(t, w, r, accessToken) {
			return
		}
		if r.URL.Path != teamsPath {
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
		team := Team{Slug: "admins"}
		team.Organization.Login = "example-org"
		_ = json.NewEncoder(w).Encode([]Team{team})
	}))
	defer server.Close()

	teams, err := newTestClient(t, server).Teams(t.Context(), accessToken)
	if err != nil {
		t.Fatalf("Teams() error = %v", err)
	}
	if len(teams) != 1 || teams[0].Slug != "admins" {
		t.Fatalf("Teams() = %+v", teams)
	}
}

func TestOrganizationsSendsTheHeadersGitHubRequires(t *testing.T) {
	const accessToken = "gho_test_token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireGitHubContract(t, w, r, accessToken) {
			return
		}
		if r.URL.Path != organizationsPath {
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
		if r.URL.Query().Get("state") != "active" {
			t.Fatalf("organization memberships were requested without state=active: %s", r.URL.RawQuery)
		}
		membership := OrganizationMembership{State: "active"}
		membership.Organization.Login = "example-org"
		_ = json.NewEncoder(w).Encode([]OrganizationMembership{membership})
	}))
	defer server.Close()

	organizations, err := newTestClient(t, server).Organizations(t.Context(), accessToken)
	if err != nil {
		t.Fatalf("Organizations() error = %v", err)
	}
	if len(organizations) != 1 || organizations[0] != "example-org" {
		t.Fatalf("Organizations() = %+v", organizations)
	}
}

// TestProfileFailsClosedWhenGitHubRejectsTheRequest pins that a GitHub API
// rejection surfaces as an error from Profile, never as a fabricated or
// partial identity.
func TestProfileFailsClosedWhenGitHubRejectsTheRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Request forbidden by administrative rules. Please make sure your request has a User-Agent header (http://developer.github.com/v3/#user-agent-required)"}`))
	}))
	defer server.Close()

	if _, err := newTestClient(t, server).Profile(t.Context(), "gho_test_token"); err == nil {
		t.Fatal("Profile() succeeded against a rejecting GitHub API")
	}
}

// An invitation the person has not accepted confers no role, even if GitHub
// returns it.
func TestOrganizationsIgnoresPendingMemberships(t *testing.T) {
	const accessToken = "gho_test_token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireGitHubContract(t, w, r, accessToken) {
			return
		}
		active := OrganizationMembership{State: "active"}
		active.Organization.Login = "member-org"
		pending := OrganizationMembership{State: "pending"}
		pending.Organization.Login = "invited-org"
		_ = json.NewEncoder(w).Encode([]OrganizationMembership{active, pending})
	}))
	defer server.Close()
	organizations, err := newTestClient(t, server).Organizations(t.Context(), accessToken)
	if err != nil {
		t.Fatal(err)
	}
	if len(organizations) != 1 || organizations[0] != "member-org" {
		t.Fatalf("Organizations() = %v, want only the accepted membership", organizations)
	}
}

// AccountID resolves an access rule's login to GitHub's numeric ID through the
// public API. It must send no credentials, and must reject a login GitHub does
// not know rather than storing a rule that can never match.
func TestAccountIDResolvesALoginWithoutCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Fatal("AccountID sent credentials to GitHub's public API")
		}
		if r.Header.Get("User-Agent") == "" || r.Header.Get("X-GitHub-Api-Version") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/users/octocat":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 583231, "login": "Octocat"})
		case "/users/renamed":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 7, "login": "someone-else"})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		}
	}))
	defer server.Close()
	client := newTestClient(t, server)

	id, err := client.AccountID(t.Context(), "octocat")
	if err != nil || id != 583231 {
		t.Fatalf("AccountID(octocat) = %d, %v", id, err)
	}
	if _, err := client.AccountID(t.Context(), "nobody-here"); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("AccountID(unknown) error = %v, want ErrAccountNotFound", err)
	}
	if _, err := client.AccountID(t.Context(), "renamed"); err == nil || errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("AccountID accepted a response for a different account: %v", err)
	}
	if _, err := client.AccountID(t.Context(), "a/b"); err == nil {
		t.Fatal("AccountID accepted a login containing a path separator")
	}
}
