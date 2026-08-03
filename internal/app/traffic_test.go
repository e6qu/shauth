// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestTrafficCountsEachRouteByItsPatternNotItsPath is the property that keeps
// this instrumentation safe to expose: a request naming a thousand distinct
// identifiers must produce one series, not a thousand.
func TestTrafficCountsEachRouteByItsPatternNotItsPath(t *testing.T) {
	t.Parallel()
	counters := newTraffic()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/users/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("POST /admin/users", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	handler := counters.observe(mux)

	for _, id := range []string{"a", "b", "c"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/admin/users/"+id, nil))
	}
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/admin/users", nil))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/nowhere", nil))

	report := counters.report()
	if report.Requests != 5 {
		t.Fatalf("requests = %d, want 5", report.Requests)
	}
	byPattern := map[string]trafficRecord{}
	for _, record := range report.Routes {
		byPattern[record.Method+" "+record.Pattern] = record
	}
	if len(byPattern) != 3 {
		t.Fatalf("series = %d (%v), want one per route", len(byPattern), byPattern)
	}
	listed := byPattern["GET /admin/users/{id}"]
	if listed.Requests != 3 {
		t.Fatalf("GET /admin/users/{id} requests = %d, want 3 collapsed onto one series", listed.Requests)
	}
	if listed.ByStatusClass["2xx"] != 3 {
		t.Fatalf("GET /admin/users/{id} 2xx = %d, want 3", listed.ByStatusClass["2xx"])
	}
	if listed.LastStatus != http.StatusNoContent {
		t.Fatalf("last status = %d, want %d", listed.LastStatus, http.StatusNoContent)
	}
	if failed := byPattern["POST /admin/users"]; failed.ByStatusClass["5xx"] != 1 {
		t.Fatalf("POST /admin/users 5xx = %d, want 1", failed.ByStatusClass["5xx"])
	}
	if report.ByStatusClass["5xx"] != 1 || report.ByStatusClass["4xx"] != 1 || report.ByStatusClass["2xx"] != 3 {
		t.Fatalf("overall outcomes = %v, want 3 2xx, 1 4xx, 1 5xx", report.ByStatusClass)
	}
	if report.FailureRate() != "20.0" {
		t.Fatalf("failure rate = %s%%, want 20.0%%", report.FailureRate())
	}
	if report.InFlight != 0 {
		t.Fatalf("in flight after every request finished = %d, want 0", report.InFlight)
	}
}

// TestTrafficRecordsAHandlerThatNeverWroteAStatus covers the default: a
// handler that writes a body without calling WriteHeader sent 200.
func TestTrafficRecordsAHandlerThatNeverWroteAStatus(t *testing.T) {
	t.Parallel()
	counters := newTraffic()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	counters.observe(mux).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))

	report := counters.report()
	if len(report.Routes) != 1 || report.Routes[0].LastStatus != http.StatusOK {
		t.Fatalf("report = %+v, want one route recorded as 200", report.Routes)
	}
}

// TestTrafficCountsARequestWhoseHandlerPanicked keeps the failure an operator
// most needs to see from being the one the counters miss.
func TestTrafficCountsARequestWhoseHandlerPanicked(t *testing.T) {
	t.Parallel()
	counters := newTraffic()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic("handler failed") })
	handler := counters.observe(mux)

	func() {
		defer func() { _ = recover() }()
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/boom", nil))
	}()

	report := counters.report()
	if report.Requests != 1 {
		t.Fatalf("requests = %d, want the panicking request counted", report.Requests)
	}
	if report.InFlight != 0 {
		t.Fatalf("in flight = %d, want the panicking request released", report.InFlight)
	}
}

func TestPercentileReadsTheBucketTheRequestedShareFallsIn(t *testing.T) {
	t.Parallel()
	// Ninety-nine fast requests and one that took a second: the mean hides
	// it and the ninety-fifth percentile must not.
	buckets := make([]int64, len(latencyBoundsMS)+1)
	buckets[bucketIndex(3)] = 99
	buckets[bucketIndex(1000)] = 1
	if actual := percentileMS(buckets, 100, 95, 1000); actual != 5 {
		t.Fatalf("p95 = %d ms, want the 5 ms bucket edge", actual)
	}
	if actual := percentileMS(buckets, 100, 100, 1000); actual != 1000 {
		t.Fatalf("p100 = %d ms, want the slow request's bucket", actual)
	}
	if actual := percentileMS(buckets, 0, 95, 0); actual != 0 {
		t.Fatalf("p95 with no requests = %d, want 0", actual)
	}
	slowest := make([]int64, len(latencyBoundsMS)+1)
	slowest[len(latencyBoundsMS)] = 1
	if actual := percentileMS(slowest, 1, 95, 9001); actual != 9001 {
		t.Fatalf("p95 past the last bound = %d, want the slowest observed response", actual)
	}
}

func TestStatusClassBoundaries(t *testing.T) {
	t.Parallel()
	for status, want := range map[int]string{100: "1xx", 200: "2xx", 299: "2xx", 301: "3xx", 404: "4xx", 499: "4xx", 500: "5xx", 503: "5xx"} {
		if actual := statusClass(status); actual != want {
			t.Errorf("statusClass(%d) = %q, want %q", status, actual, want)
		}
	}
}

func TestTrafficBoundsItsSeriesEvenIfTheRouteTableGrows(t *testing.T) {
	t.Parallel()
	counters := newTraffic()
	counters.maxRoutes = 3
	for index := 0; index < 20; index++ {
		counters.finish(http.MethodGet, "GET /route-"+string(rune('a'+index)), http.StatusOK, time.Millisecond)
	}
	report := counters.report()
	if len(report.Routes) > 4 {
		t.Fatalf("series = %d, want the table bounded at its limit plus the overflow series", len(report.Routes))
	}
	if report.Requests != 20 {
		t.Fatalf("requests = %d, want every request counted even once series overflowed", report.Requests)
	}
}
