// SPDX-License-Identifier: AGPL-3.0-or-later

package monitoring

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testToken = "0123456789abcdef0123456789abcdef"

func TestValidateSources(t *testing.T) {
	valid := []Source{{Name: "development", URL: "https://monitoring.dev.e6qu.dev/v1/observations", BearerToken: testToken}}
	if err := ValidateSources(valid); err != nil {
		t.Fatalf("ValidateSources(valid) error = %v", err)
	}
	if err := ValidateSources([]Source{{Name: "local", URL: "http://monitoring.localhost:8080/v1/observations", BearerToken: testToken}}); err != nil {
		t.Fatalf("ValidateSources(localhost subdomain) error = %v", err)
	}
	for name, sources := range map[string][]Source{
		"duplicate name": append(valid, valid[0]),
		"insecure URL":   {{Name: "development", URL: "http://monitoring.dev.e6qu.dev/v1/observations", BearerToken: testToken}},
		"short token":    {{Name: "development", URL: "https://monitoring.dev.e6qu.dev/v1/observations", BearerToken: "short"}},
		"token whitespace": {{
			Name: "development", URL: "https://monitoring.dev.e6qu.dev/v1/observations",
			BearerToken: testToken + "\n",
		}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateSources(sources); err == nil {
				t.Fatal("ValidateSources() accepted invalid sources")
			}
		})
	}
}

func TestClientFetchesAuthenticatedStrictObservation(t *testing.T) {
	snapshot := validSnapshot()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken || r.Header.Get("Accept") != "application/json" {
			http.Error(w, "missing credentials", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(snapshot); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	defer server.Close()

	client := &Client{httpClient: server.Client(), now: func() time.Time { return testNow }}
	results := client.FetchAll(context.Background(), []Source{{Name: "development", URL: server.URL, BearerToken: testToken}})
	if len(results) != 1 || results[0].Error != "" || results[0].Snapshot.SchemaVersion != SchemaVersion {
		t.Fatalf("FetchAll() = %#v", results)
	}
}

func TestClientRejectsUnknownObservationFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"e6qu.monitoring/v1","unexpected":true}`))
	}))
	defer server.Close()
	client := &Client{httpClient: server.Client(), now: func() time.Time { return testNow }}
	result := client.FetchAll(context.Background(), []Source{{Name: "development", URL: server.URL, BearerToken: testToken}})[0]
	if !strings.Contains(result.Error, "unknown field") {
		t.Fatalf("FetchAll() error = %q", result.Error)
	}
}

func TestSnapshotValidationRequiresCompletePricingBasis(t *testing.T) {
	snapshot := validSnapshot()
	snapshot.CostEstimate.Excludes = []string{"taxes"}
	if err := snapshot.Validate(); err == nil {
		t.Fatal("Validate() accepted an incomplete public-price basis")
	}
}

func TestSnapshotValidationRequiresConsistentPricingTotals(t *testing.T) {
	for name, change := range map[string]func(*Snapshot){
		"hourly":  func(snapshot *Snapshot) { snapshot.CostEstimate.Hourly++ },
		"daily":   func(snapshot *Snapshot) { snapshot.CostEstimate.Daily++ },
		"monthly": func(snapshot *Snapshot) { snapshot.CostEstimate.Monthly++ },
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := validSnapshot()
			change(&snapshot)
			if err := snapshot.Validate(); err == nil {
				t.Fatal("Validate() accepted inconsistent pricing totals")
			}
		})
	}
}

func TestSnapshotValidationFutureClockSkewBoundary(t *testing.T) {
	for name, offset := range map[string]time.Duration{"accepted boundary": time.Minute, "rejected beyond boundary": time.Minute + time.Nanosecond} {
		t.Run(name, func(t *testing.T) {
			snapshot := validSnapshot()
			snapshot.ObservedAt = testNow.Add(offset)
			err := snapshot.validate(testNow)
			if offset == time.Minute && err != nil {
				t.Fatalf("validate() rejected clock-skew boundary: %v", err)
			}
			if offset > time.Minute && err == nil {
				t.Fatal("validate() accepted an observation beyond the clock-skew boundary")
			}
		})
	}
}

func validSnapshot() Snapshot {
	return Snapshot{
		SchemaVersion: SchemaVersion,
		ObservedAt:    testNow,
		Resources: []Resource{{
			ID: "shared-database", Name: "Shared PostgreSQL", Kind: "database", Health: "healthy",
			Metrics: []Metric{
				{Name: "cpu.allocation", Label: "CPU allocation", Value: floatPointer(0.25), Unit: "vCPU", Status: "available"},
				{Name: "memory.usage", Label: "Memory usage", Value: floatPointer(128), Unit: "MiB", Status: "available"},
				{Name: "storage.usage", Label: "Storage usage", Value: floatPointer(2048), Unit: "MiB", Status: "available"},
				{Name: "storage.read_iops", Label: "Read operations", Value: floatPointer(2.5), Unit: "operations/second", Status: "available"},
				{Name: "storage.allocation", Label: "Storage allocation", Unit: "GiB", Status: "not_applicable"},
			},
		}},
		CostEstimate: CostEstimate{
			Currency: "USD", Basis: PricingBasis, HoursPerMonth: 730,
			Hourly: 0.02, Daily: 0.48, Monthly: 14.60,
			Excludes:    []string{"taxes", "reservations", "savings_plans", "credits", "free_tier"},
			Limitations: []string{"Request-priced services and data transfer are excluded when AWS publishes no current usage metric."},
			LineItems:   []CostLineItem{{Name: "Shared PostgreSQL compute", Hourly: 0.02, Monthly: 14.60}},
		},
	}
}

func floatPointer(value float64) *float64 { return &value }

var testNow = time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
