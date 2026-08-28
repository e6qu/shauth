// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
	"time"

	"github.com/e6qu/shauth/internal/identity"
	"github.com/e6qu/shauth/internal/monitoring"
)

func TestApplicationMonitoringNavigationStaysInsideShauth(t *testing.T) {
	pages, err := template.New("pages").Funcs(templateHelpers()).Parse(pageTemplates)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	const observationEndpoint = "https://example.test/monitoring/observation"
	app := newManagedAppView(identity.ManagedApp{
		Slug: "example", Name: "Example", Description: "An example application.",
		LaunchURL: "https://example.test/", MonitoringURL: observationEndpoint,
	})

	for name, test := range map[string]struct {
		data                 map[string]any
		wantMonitoringAction bool
	}{
		"administrator": {
			data:                 map[string]any{"SignedIn": true, "IsAdmin": true, "Apps": []managedAppView{app}},
			wantMonitoringAction: true,
		},
		"non-administrator": {
			data: map[string]any{"SignedIn": true, "IsAdmin": false, "Apps": []managedAppView{app}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			apps := test.data["Apps"].([]managedAppView)
			if test.data["IsAdmin"].(bool) {
				setMonitoringPageURLs(apps, identity.RoleAdmin)
			} else {
				setMonitoringPageURLs(apps, identity.RoleDeveloper)
			}
			var output bytes.Buffer
			if err := pages.ExecuteTemplate(&output, "apps", test.data); err != nil {
				t.Fatalf("ExecuteTemplate() error = %v", err)
			}
			rendered := output.String()
			if strings.Contains(rendered, `href="`+observationEndpoint+`"`) {
				t.Fatalf("application catalog exposed the machine observation endpoint as browser navigation: %s", rendered)
			}
			hasMonitoringAction := strings.Contains(rendered, `href="/monitoring"`) && strings.Contains(rendered, `View monitoring`)
			if hasMonitoringAction != test.wantMonitoringAction {
				t.Fatalf("monitoring action present = %t, want %t", hasMonitoringAction, test.wantMonitoringAction)
			}
		})
	}
}

func TestApplicationAdministrationIdentifiesMachineObservationEndpoint(t *testing.T) {
	pages, err := template.New("pages").Funcs(templateHelpers()).Parse(pageTemplates)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	const observationEndpoint = "https://example.test/monitoring/observation"
	app := newManagedAppView(identity.ManagedApp{
		Slug: "example", Name: "Example", Description: "An example application.",
		LaunchURL: "https://example.test/", MonitoringURL: observationEndpoint,
	})
	var output bytes.Buffer
	if err := pages.ExecuteTemplate(&output, "admin-apps", map[string]any{"Apps": []managedAppView{app}}); err != nil {
		t.Fatalf("ExecuteTemplate() error = %v", err)
	}
	rendered := output.String()
	for _, expected := range []string{"Observation endpoint", "Shauth reads this endpoint", `href="/monitoring"`, "View monitoring"} {
		if !strings.Contains(rendered, expected) {
			t.Errorf("application administration page omitted %q", expected)
		}
	}
	if strings.Contains(rendered, `href="`+observationEndpoint+`"`) {
		t.Fatalf("application administration exposed the machine observation endpoint as browser navigation: %s", rendered)
	}

	output.Reset()
	if err := pages.ExecuteTemplate(&output, "admin-app", map[string]any{"App": app}); err != nil {
		t.Fatalf("ExecuteTemplate(admin-app) error = %v", err)
	}
	rendered = output.String()
	for _, expected := range []string{"Observation endpoint", observationEndpoint, `href="/monitoring"`, "View monitoring"} {
		if !strings.Contains(rendered, expected) {
			t.Errorf("application detail page omitted %q", expected)
		}
	}
	if strings.Contains(rendered, `href="`+observationEndpoint+`"`) {
		t.Fatalf("application detail page exposed the machine observation endpoint as browser navigation: %s", rendered)
	}
}

func TestMonitoringPageRendersGenericResourceMetricsAndPriceBasis(t *testing.T) {
	pages, err := template.New("pages").Funcs(templateHelpers()).Parse(pageTemplates)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	activeSessions := 2
	data := map[string]any{
		"SignedIn": true, "IsAdmin": true,
		"Now": time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC),
		"Snapshot": monitoringSnapshot{
			PostgreSQLHealthy: true, HydraHealthy: true, ActiveSessions: &activeSessions,
			Infrastructure: []monitoring.Result{{
				SourceName: "Development", Stale: true,
				Snapshot: monitoring.Snapshot{
					SchemaVersion: monitoring.SchemaVersion,
					ObservedAt:    time.Date(2026, 7, 20, 11, 45, 0, 0, time.UTC),
					Resources: []monitoring.Resource{{
						ID: "shared-database", Name: "Shared PostgreSQL", Kind: "database", Health: "healthy",
						Metrics: []monitoring.Metric{{Name: "cpu.usage", Label: "CPU usage", Value: floatPointer(0.125), Unit: "vCPU", Status: "available"}},
					}},
					CostEstimate: &monitoring.CostEstimate{
						Currency: "USD", Basis: monitoring.PricingBasis, HoursPerMonth: 730,
						Hourly: 0.02, Daily: 0.48, Monthly: 14.60,
						Excludes:    []string{"taxes", "reservations", "savings_plans", "credits", "free_tier"},
						Limitations: []string{"Unmeasured request charges are not included."},
						LineItems:   []monitoring.CostLineItem{{Name: "Shared database", Hourly: 0.02, Monthly: 14.60}},
					},
				},
			}},
		},
	}
	var output bytes.Buffer
	if err := pages.ExecuteTemplate(&output, "monitoring", data); err != nil {
		t.Fatalf("ExecuteTemplate() error = %v", err)
	}
	for _, expected := range []string{"Shared PostgreSQL", "CPU usage", "0.125 vCPU", "Observation is stale", "Estimated public on-demand cost", "Savings Plans", "Unmeasured request charges"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("monitoring page omitted %q", expected)
		}
	}
}

func floatPointer(value float64) *float64 { return &value }
