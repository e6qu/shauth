// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
	"time"

	"github.com/e6qu/shauth/internal/monitoring"
)

func TestMonitoringPageRendersGenericResourceMetricsAndPriceBasis(t *testing.T) {
	pages, err := template.New("pages").Parse(pageTemplates)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	data := map[string]any{
		"SignedIn": true, "IsAdmin": true, "PostgreSQLHealthy": true, "HydraHealthy": true,
		"ActiveSessions": 2, "Now": time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC),
		"Infrastructure": []monitoring.Result{{
			SourceName: "Development", Stale: true,
			Snapshot: monitoring.Snapshot{
				SchemaVersion: monitoring.SchemaVersion,
				ObservedAt:    time.Date(2026, 7, 20, 11, 45, 0, 0, time.UTC),
				Resources: []monitoring.Resource{{
					ID: "shared-database", Name: "Shared PostgreSQL", Kind: "database", Health: "healthy",
					Metrics: []monitoring.Metric{{Name: "cpu.usage", Label: "CPU usage", Value: floatPointer(0.125), Unit: "vCPU", Status: "available"}},
				}},
				CostEstimate: monitoring.CostEstimate{
					Currency: "USD", Basis: monitoring.PricingBasis, HoursPerMonth: 730,
					Hourly: 0.02, Daily: 0.48, Monthly: 14.60,
					Excludes:    []string{"taxes", "reservations", "savings_plans", "credits", "free_tier"},
					Limitations: []string{"Unmeasured request charges are not included."},
					LineItems:   []monitoring.CostLineItem{{Name: "Shared database", Hourly: 0.02, Monthly: 14.60}},
				},
			},
		}},
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
