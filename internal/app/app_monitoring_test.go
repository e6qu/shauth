// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"strings"
	"testing"

	"github.com/e6qu/shauth/internal/identity"
)

// The regression this whole file exists for: managed_apps.monitoring_url was
// stored, upserted, compared and returned by the admin API, and never once used
// to fetch an observation. Registering an endpoint has to produce a source.
func TestRegisteredMonitoringURLBecomesASource(t *testing.T) {
	sources, unpublished := applicationMonitoringSources(
		[]identity.ManagedApp{{Slug: "e6irc", Name: "e6irc", MonitoringURL: "https://e6irc.dev.e6qu.dev/v1/observations"}},
		map[string]string{"e6irc": strings.Repeat("t", 32)},
	)
	if len(sources) != 1 {
		t.Fatalf("registered monitoring URL produced %d sources, want 1", len(sources))
	}
	if sources[0].URL != "https://e6irc.dev.e6qu.dev/v1/observations" {
		t.Errorf("source URL = %q", sources[0].URL)
	}
	if sources[0].BearerToken == "" {
		t.Error("source carries no bearer token, so the read would be unauthenticated")
	}
	if len(unpublished) != 0 {
		t.Errorf("unpublished = %v, want none", unpublished)
	}
}

// An application that publishes nothing is named, not skipped. Silence here is
// what let a container thrash for five days behind a healthy-looking page.
func TestApplicationWithoutAMonitoringEndpointIsReportedNotSkipped(t *testing.T) {
	sources, unpublished := applicationMonitoringSources(
		[]identity.ManagedApp{
			{Slug: "e6irc", Name: "e6irc", MonitoringURL: "https://e6irc.dev.e6qu.dev/v1/observations"},
			{Slug: "bleephub", Name: "Bleephub"},
		},
		map[string]string{"e6irc": strings.Repeat("t", 32), "bleephub": strings.Repeat("t", 32)},
	)
	if len(sources) != 1 {
		t.Fatalf("sources = %d, want 1", len(sources))
	}
	if len(unpublished) != 1 || unpublished[0] != "Bleephub" {
		t.Fatalf("unpublished = %v, want [Bleephub]", unpublished)
	}
}

// A registered endpoint with no deployed credential is a deployment omission,
// and must not be reported as though the application failed to implement it.
func TestRegisteredEndpointWithoutACredentialIsDistinguished(t *testing.T) {
	sources, unpublished := applicationMonitoringSources(
		[]identity.ManagedApp{{Slug: "e6irc", Name: "e6irc", MonitoringURL: "https://e6irc.dev.e6qu.dev/v1/observations"}},
		map[string]string{},
	)
	if len(sources) != 0 {
		t.Fatalf("sources = %d, want 0 without a credential", len(sources))
	}
	if len(unpublished) != 1 || !strings.Contains(unpublished[0], "credential") {
		t.Fatalf("unpublished = %v, want the missing credential named", unpublished)
	}
}
