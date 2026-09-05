// SPDX-License-Identifier: AGPL-3.0-or-later

package github

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseTeam(t *testing.T) {
	organization, slug, err := ParseTeam("e6qu-org/e6qu-org-admins")
	if err != nil {
		t.Fatalf("ParseTeam() error = %v", err)
	}
	if organization != "e6qu-org" || slug != "e6qu-org-admins" {
		t.Fatalf("ParseTeam() = %q/%q", organization, slug)
	}
}

func TestParseTeamRejectsInvalidValue(t *testing.T) {
	if _, _, err := ParseTeam("e6qu-org"); err == nil {
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
		team := Team{Slug: "e6qu-org-admins"}
		team.Organization.Login = "e6qu-org"
		_ = json.NewEncoder(w).Encode([]Team{team})
	}))
	defer server.Close()

	teams, err := newTestClient(t, server).Teams(t.Context(), accessToken)
	if err != nil {
		t.Fatalf("Teams() error = %v", err)
	}
	if len(teams) != 1 || teams[0].Slug != "e6qu-org-admins" {
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
		membership := OrganizationMembership{}
		membership.Organization.Login = "e6qu-org"
		_ = json.NewEncoder(w).Encode([]OrganizationMembership{membership})
	}))
	defer server.Close()

	organizations, err := newTestClient(t, server).Organizations(t.Context(), accessToken)
	if err != nil {
		t.Fatalf("Organizations() error = %v", err)
	}
	if len(organizations) != 1 || organizations[0] != "e6qu-org" {
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
