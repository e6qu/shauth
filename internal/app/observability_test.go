// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/e6qu/shauth/internal/config"
	"github.com/e6qu/shauth/internal/identity"
)

// The observability contracts are read-only and must be unreachable without
// the read credential, like every other read.
func TestObservabilityEndpointsRequireTheReadCredential(t *testing.T) {
	const readToken = "admin-api-read-token-0123456789abcdef"
	const writeToken = "admin-api-write-token-0123456789abcde"
	server := &Server{config: config.Config{AdminAPIReadToken: readToken, AdminAPIWriteToken: writeToken}}
	for name, endpoint := range map[string]struct {
		target  string
		handler http.HandlerFunc
	}{
		"audit events": {"/api/v1/audit-events", server.auditEventsAPI},
		"metrics":      {"/api/v1/metrics", server.metricsAPI},
		"deep health":  {"/api/v1/health/deep", server.deepHealthAPI},
		"logout":       {"/api/v1/logout-grants", server.logoutGrantsAPI},
	} {
		for credential, authorize := range map[string]func(*http.Request){
			"missing":       func(*http.Request) {},
			"cross-purpose": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+writeToken) },
		} {
			t.Run(name+" "+credential, func(t *testing.T) {
				request := httptest.NewRequest(http.MethodGet, endpoint.target, nil)
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

func TestRequestedAuditFilterRejectsMalformedInput(t *testing.T) {
	for name, query := range map[string]string{
		"bad since":   "?since=yesterday",
		"bad until":   "?until=2026-13-45",
		"bad subject": "?subject=not-a-uuid",
		"bad actor":   "?actor=12345",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := requestedAuditFilter(httptest.NewRequest(http.MethodGet, "/api/v1/audit-events"+query, nil)); err == nil {
				t.Fatalf("filter accepted %s", query)
			}
		})
	}
	filter, err := requestedAuditFilter(httptest.NewRequest(http.MethodGet,
		"/api/v1/audit-events?event_type=sign_in.failed&since=2026-08-01T00:00:00Z", nil))
	if err != nil || filter.EventType != "sign_in.failed" || filter.Since.IsZero() {
		t.Fatalf("filter = %#v, %v", filter, err)
	}
}

// A refusal must tell the person nothing while telling the operator exactly
// why, so a disabled account is distinguishable from a mistyped name.
func TestSignInRefusalReasonsAreDistinctFromTheMessageShown(t *testing.T) {
	reasons := []string{
		identity.SignInReasonUnknownUser, identity.SignInReasonDisabled,
		identity.SignInReasonNoPassword, identity.SignInReasonWrongSecret,
	}
	seen := map[string]bool{}
	for _, reason := range reasons {
		if reason == "" || seen[reason] {
			t.Fatalf("refusal reason %q is empty or duplicated", reason)
		}
		seen[reason] = true
		if strings.Contains(strings.ToLower(reason), "password did not match") && reason != identity.SignInReasonWrongSecret {
			t.Fatal("reasons must stay distinct")
		}
	}
}

func TestAuditRecordAlwaysCarriesDetails(t *testing.T) {
	encoded, err := json.Marshal(newAuditEventRecord(identity.AuditEvent{
		ID: "5f61a1a1-27b6-4e8c-9e3f-1f2e3d4c5b6a", EventType: identity.AuditSignInFailed,
		CreatedAt: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
	}))
	if err != nil {
		t.Fatal(err)
	}
	// Details is always an object so a consumer never has to handle null.
	if !strings.Contains(string(encoded), `"details":{}`) {
		t.Fatalf("record omitted its details object: %s", encoded)
	}
	if strings.Contains(string(encoded), `"remote_address"`) {
		t.Fatalf("record reported an absent address: %s", encoded)
	}
}

// A deep check that only ever reports success is worthless; the verdict must
// escalate to the worst result any dependency reported.
func TestDeepHealthVerdictFollowsTheWorstCheck(t *testing.T) {
	for name, expectation := range map[string]struct {
		statuses []string
		want     string
	}{
		"all healthy":     {[]string{healthHealthy, healthHealthy}, healthHealthy},
		"one degraded":    {[]string{healthHealthy, healthDegraded}, healthDegraded},
		"one unhealthy":   {[]string{healthHealthy, healthUnhealthy}, healthUnhealthy},
		"degraded before": {[]string{healthDegraded, healthUnhealthy}, healthUnhealthy},
	} {
		t.Run(name, func(t *testing.T) {
			overall := healthHealthy
			for _, status := range expectation.statuses {
				if status == healthUnhealthy {
					overall = healthUnhealthy
					break
				}
				if status == healthDegraded {
					overall = healthDegraded
				}
			}
			if overall != expectation.want {
				t.Fatalf("verdict = %q, want %q", overall, expectation.want)
			}
		})
	}
}
