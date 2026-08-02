// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/e6qu/shauth/internal/config"
	"github.com/e6qu/shauth/internal/identity"
)

func applicationAPIEndpoints(server *Server) map[string]struct {
	method  string
	target  string
	handler http.HandlerFunc
} {
	return map[string]struct {
		method  string
		target  string
		handler http.HandlerFunc
	}{
		"apps":        {http.MethodGet, "/api/v1/apps", server.applicationsAPI},
		"validations": {http.MethodGet, "/api/v1/apps/validations", server.applicationValidationStatusAPI},
		"history":     {http.MethodGet, "/api/v1/apps/validations/history", server.applicationValidationHistoryAPI},
	}
}

func TestApplicationAPIEndpointsReportUnconfiguredToken(t *testing.T) {
	server := &Server{}
	for name, endpoint := range applicationAPIEndpoints(server) {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(endpoint.method, endpoint.target, nil)
			request.Header.Set("Authorization", "Bearer any")
			response := httptest.NewRecorder()
			endpoint.handler(response, request)
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("unconfigured response was cacheable")
			}
		})
	}
}

func TestApplicationAPIEndpointsRejectMissingOrWrongBearerToken(t *testing.T) {
	const token = "validation-status-token-0123456789ab"
	server := &Server{config: config.Config{ValidationStatusToken: token}}
	for name, endpoint := range applicationAPIEndpoints(server) {
		for credential, authorize := range map[string]func(*http.Request){
			"missing": func(*http.Request) {},
			"wrong":   func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") },
		} {
			t.Run(name+" "+credential, func(t *testing.T) {
				request := httptest.NewRequest(endpoint.method, endpoint.target, nil)
				authorize(request)
				response := httptest.NewRecorder()
				endpoint.handler(response, request)
				if response.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
				}
			})
		}
	}
}

func TestValidationStatusRecordCarriesDurationAndWitnessOnlyForTerminalRuns(t *testing.T) {
	duration := int64(4321)
	started := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	completed := started.Add(time.Duration(duration) * time.Millisecond)
	terminal := identity.AppValidationRun{
		AppSlug: "bleephub", Direction: identity.ValidationFromShauth, Status: identity.ValidationPassed,
		ReleaseRevision: "0123456789ab", ValidationContractHash: strings.Repeat("a", 64),
		RequestedAt: started.Add(-time.Minute), StartedAt: &started, CompletedAt: &completed,
		DurationMilliseconds: &duration,
		Witness:              &identity.AppValidationWitness{AppSlug: "witness-app"},
	}
	terminalJSON, err := json.Marshal(newValidationStatusRecord(terminal))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"duration_ms":4321`, `"witness":"witness-app"`, `"status":"passed"`} {
		if !strings.Contains(string(terminalJSON), expected) {
			t.Fatalf("terminal record omitted %s: %s", expected, terminalJSON)
		}
	}

	ongoing := terminal
	ongoing.Status = identity.ValidationRunning
	ongoing.CompletedAt = nil
	ongoingJSON, err := json.Marshal(newValidationStatusRecord(ongoing))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ongoingJSON), "duration_ms") {
		t.Fatalf("ongoing record reported a duration: %s", ongoingJSON)
	}
	if !strings.Contains(string(ongoingJSON), `"witness":"witness-app"`) {
		t.Fatalf("ongoing record dropped its witness: %s", ongoingJSON)
	}

	solo := terminal
	solo.Witness = nil
	soloJSON, err := json.Marshal(newValidationStatusRecord(solo))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(soloJSON), "witness") {
		t.Fatalf("witnessless record reported a witness: %s", soloJSON)
	}
}

func TestAppRecordReportsCatalogHealthAndValidationShape(t *testing.T) {
	duration := int64(1500)
	completed := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	view := newManagedAppView(identity.ManagedApp{
		Slug: "bleephub", Name: "Bleephub", LaunchURL: "https://bleephub.example.test/",
		OIDCClientID: "bleephub-dev", HealthURL: "https://bleephub.example.test/health",
		ValidationURL: "https://bleephub.example.test/validation", SignedOutURL: "https://bleephub.example.test/signed-out",
		ReleaseRevision: "0123456789ab", CreatedAt: completed,
	})
	view.Healthy, view.StatusCode = true, 200
	view.FromShauth = newAppValidationRunView(identity.AppValidationRun{
		AppSlug: "bleephub", Direction: identity.ValidationFromShauth, Status: identity.ValidationPassed,
		ReleaseRevision: "0123456789ab", CompletedAt: &completed, DurationMilliseconds: &duration,
	})
	encoded, err := json.Marshal(newAppRecord(view))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`"slug":"bleephub"`, `"oidc_client_id":"bleephub-dev"`,
		`"health":{"healthy":true,"status_code":200}`,
		`"from_shauth":{"slug":"bleephub"`, `"duration_ms":1500`, `"from_app":null`,
	} {
		if !strings.Contains(string(encoded), expected) {
			t.Fatalf("app record omitted %s: %s", expected, encoded)
		}
	}
	for _, unexpected := range []string{"description", "monitoring_url", `"error"`} {
		if strings.Contains(string(encoded), unexpected) {
			t.Fatalf("app record reported empty optional field %s: %s", unexpected, encoded)
		}
	}

	unreachable := newManagedAppView(identity.ManagedApp{Slug: "down"})
	unreachable.StatusError = "request health endpoint: connection refused"
	downEncoded, err := json.Marshal(newAppRecord(unreachable))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(downEncoded), `"health":{"healthy":false,"error":"request health endpoint: connection refused"}`) {
		t.Fatalf("unreachable app record hid its health error: %s", downEncoded)
	}
}

func TestParseValidationHistoryLimit(t *testing.T) {
	for raw, want := range map[string]int{"": 50, "1": 1, "42": 42, "500": 500} {
		limit, err := parseValidationHistoryLimit(raw)
		if err != nil || limit != want {
			t.Fatalf("parseValidationHistoryLimit(%q) = %d, %v; want %d", raw, limit, err, want)
		}
	}
	for _, raw := range []string{"0", "-1", "501", "abc", "1.5", "10 ", "0x10"} {
		if _, err := parseValidationHistoryLimit(raw); err == nil {
			t.Fatalf("parseValidationHistoryLimit(%q) accepted an invalid limit", raw)
		}
	}
}

func TestDecodeValidationEnqueueRequestTreatsEmptyBodyAsAllApps(t *testing.T) {
	for name, body := range map[string]string{"empty": "", "whitespace": "  \n", "empty object": "{}"} {
		t.Run(name, func(t *testing.T) {
			request, err := decodeValidationEnqueueRequest(strings.NewReader(body))
			if err != nil {
				t.Fatalf("decodeValidationEnqueueRequest(%q) error = %v", body, err)
			}
			ref, err := request.ref()
			if err != nil || !ref.All() {
				t.Fatalf("decodeValidationEnqueueRequest(%q) = %#v, %v", body, ref, err)
			}
		})
	}
	request, err := decodeValidationEnqueueRequest(strings.NewReader(`{"slug":" bleephub "}`))
	if err != nil {
		t.Fatalf("slug request error = %v", err)
	}
	ref, err := request.ref()
	if err != nil || ref.Slug != "bleephub" || ref.All() {
		t.Fatalf("slug ref = %#v, %v", ref, err)
	}

	// A present but empty slug is an unset deployment variable, not a
	// request to re-validate every registered application.
	for _, blank := range []string{`{"slug":""}`, `{"slug":"   "}`} {
		blankRequest, err := decodeValidationEnqueueRequest(strings.NewReader(blank))
		if err != nil {
			t.Fatalf("decode %s: %v", blank, err)
		}
		if _, err := blankRequest.ref(); err == nil {
			t.Fatalf("a blank slug in %s was accepted as every application", blank)
		}
	}
	for name, body := range map[string]string{
		"unknown field":  `{"slug":"bleephub","force":true}`,
		"trailing value": `{"slug":"bleephub"} {}`,
		"not an object":  `"bleephub"`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeValidationEnqueueRequest(strings.NewReader(body)); err == nil {
				t.Fatalf("invalid enqueue request %q was accepted", body)
			}
		})
	}
}

func TestCSRFPostsExemptsInternalValidationEnqueue(t *testing.T) {
	publicURL, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	handler := csrfPosts(publicURL, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))

	request := httptest.NewRequest(http.MethodPost, "https://auth.example.test/internal/apps/validations/enqueue", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d: bearer-token POSTs have no CSRF cookie to present", response.Code, http.StatusAccepted)
	}
}

// The application status credential is read-only. Queuing validations starts
// real browser sessions and global logouts against every registered relying
// party, so it must require the administration write credential.
func TestApplicationValidationEnqueueRejectsTheReadOnlyStatusToken(t *testing.T) {
	const statusToken = "validation-status-token-0123456789ab"
	const writeToken = "admin-api-write-token-0123456789abc"
	server := &Server{config: config.Config{ValidationStatusToken: statusToken, AdminAPIWriteToken: writeToken}}

	request := httptest.NewRequest(http.MethodPost, "/internal/apps/validations/enqueue", nil)
	request.Header.Set("Authorization", "Bearer "+statusToken)
	response := httptest.NewRecorder()
	server.applicationValidationEnqueueAPI(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("the read-only status credential queued validations: status = %d", response.Code)
	}
	if response.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("the rejection did not advertise its authentication scheme")
	}
}
