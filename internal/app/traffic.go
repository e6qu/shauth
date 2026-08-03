// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// latencyBoundsMS are the upper edges of the response-time buckets, in
// milliseconds. Keeping the distribution rather than a running average is
// what makes a slow tail visible at all: a mean hides the request that took
// four seconds behind a thousand that took four.
var latencyBoundsMS = []int64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}

// routeKey identifies one instrumented route. The pattern is the one the
// route table matched, never the requested path, so a hostile URL cannot
// invent series and grow this map without bound.
type routeKey struct {
	Method  string
	Pattern string
}

// routeStat is what one route has done since this process started.
type routeStat struct {
	Requests      int64
	ByStatusClass map[string]int64
	TotalMS       int64
	MaxMS         int64
	Buckets       []int64
	LastStatus    int
	LastAt        time.Time
}

// traffic counts requests by route, outcome, and response time. Nothing else
// observes status codes, so an operator asking "is anything failing, and how
// slow is it" had to read container logs line by line. It is deliberately
// process-local and resets on restart: it answers what this instance is doing
// now, which is the question during an incident.
type traffic struct {
	mutex     sync.Mutex
	routes    map[routeKey]*routeStat
	inFlight  int64
	maxRoutes int
}

// maxTrackedRoutes bounds the table even if the route list grows. Requests
// matching no route already share one series, so this is a backstop rather
// than the primary defence against unbounded series.
const maxTrackedRoutes = 512

func newTraffic() *traffic {
	return &traffic{routes: make(map[routeKey]*routeStat), maxRoutes: maxTrackedRoutes}
}

// observe wraps the routed handler. ServeMux records the matched pattern on
// the request itself, so the route is read after the handler returns rather
// than by matching the request a second time.
func (t *traffic) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		started := time.Now()
		t.begin()
		// Deferred so a handler that panics is still counted and its
		// failure still shows up as a 5xx.
		defer func() { t.finish(r.Method, r.Pattern, recorder.status, time.Since(started)) }()
		next.ServeHTTP(recorder, r)
	})
}

func (t *traffic) begin() {
	t.mutex.Lock()
	t.inFlight++
	t.mutex.Unlock()
}

// finish records one completed request.
func (t *traffic) finish(method, pattern string, status int, elapsed time.Duration) {
	key := newRouteKey(method, pattern)
	milliseconds := elapsed.Milliseconds()
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.inFlight--
	stat := t.routes[key]
	if stat == nil {
		if len(t.routes) >= t.maxRoutes {
			key = routeKey{Method: "*", Pattern: "overflow"}
			stat = t.routes[key]
		}
		if stat == nil {
			stat = &routeStat{ByStatusClass: make(map[string]int64, 4), Buckets: make([]int64, len(latencyBoundsMS)+1)}
			t.routes[key] = stat
		}
	}
	stat.Requests++
	stat.ByStatusClass[statusClass(status)]++
	stat.TotalMS += milliseconds
	if milliseconds > stat.MaxMS {
		stat.MaxMS = milliseconds
	}
	stat.Buckets[bucketIndex(milliseconds)]++
	stat.LastStatus = status
	stat.LastAt = time.Now().UTC()
}

// newRouteKey splits the matched pattern into its method and path. A pattern
// registered without a method keeps the request's own, so one route table
// entry serving several methods still reports them apart.
func newRouteKey(method, pattern string) routeKey {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return routeKey{Method: method, Pattern: "unrouted"}
	}
	if verb, path, found := strings.Cut(pattern, " "); found {
		return routeKey{Method: verb, Pattern: path}
	}
	return routeKey{Method: method, Pattern: pattern}
}

func statusClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	default:
		return "1xx"
	}
}

func bucketIndex(milliseconds int64) int {
	for index, bound := range latencyBoundsMS {
		if milliseconds <= bound {
			return index
		}
	}
	return len(latencyBoundsMS)
}

// trafficRecord is one route as reported to an operator.
type trafficRecord struct {
	Method        string           `json:"method"`
	Pattern       string           `json:"pattern"`
	Requests      int64            `json:"requests"`
	ByStatusClass map[string]int64 `json:"by_status_class"`
	MeanMS        int64            `json:"mean_ms"`
	MaxMS         int64            `json:"max_ms"`
	P95MS         int64            `json:"p95_ms"`
	LastStatus    int              `json:"last_status"`
	LastAt        time.Time        `json:"last_at"`
}

// trafficReport is everything this instance has served since it started.
type trafficReport struct {
	Routes        []trafficRecord  `json:"routes"`
	Requests      int64            `json:"requests"`
	ByStatusClass map[string]int64 `json:"by_status_class"`
	InFlight      int64            `json:"in_flight"`
	LatencyBounds []int64          `json:"latency_bounds_ms"`
	Goroutines    int              `json:"goroutines"`
	HeapBytes     uint64           `json:"heap_bytes"`
}

// report snapshots the counters. Routes are ordered by traffic so the busiest
// are at the top of the list an operator actually reads.
func (t *traffic) report() trafficReport {
	t.mutex.Lock()
	records := make([]trafficRecord, 0, len(t.routes))
	overall := map[string]int64{}
	var total int64
	for key, stat := range t.routes {
		byClass := make(map[string]int64, len(stat.ByStatusClass))
		for class, count := range stat.ByStatusClass {
			byClass[class] = count
			overall[class] += count
		}
		total += stat.Requests
		record := trafficRecord{
			Method: key.Method, Pattern: key.Pattern, Requests: stat.Requests,
			ByStatusClass: byClass, MaxMS: stat.MaxMS,
			P95MS:      percentileMS(stat.Buckets, stat.Requests, 95, stat.MaxMS),
			LastStatus: stat.LastStatus, LastAt: stat.LastAt,
		}
		if stat.Requests > 0 {
			record.MeanMS = stat.TotalMS / stat.Requests
		}
		records = append(records, record)
	}
	inFlight := t.inFlight
	t.mutex.Unlock()

	sort.Slice(records, func(i, j int) bool {
		if records[i].Requests != records[j].Requests {
			return records[i].Requests > records[j].Requests
		}
		if records[i].Pattern != records[j].Pattern {
			return records[i].Pattern < records[j].Pattern
		}
		return records[i].Method < records[j].Method
	})
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return trafficReport{
		Routes: records, Requests: total, ByStatusClass: overall, InFlight: inFlight,
		LatencyBounds: latencyBoundsMS, Goroutines: runtime.NumGoroutine(), HeapBytes: memory.HeapAlloc,
	}
}

// percentileMS reports the upper edge of the bucket the requested percentile
// falls in, and the slowest observed response once that is past the last
// bound. It never interpolates, so it claims no more precision than the
// counters hold.
func percentileMS(buckets []int64, requests int64, percentile int, maxMS int64) int64 {
	if requests == 0 {
		return 0
	}
	target := requests * int64(percentile) / 100
	if target < 1 {
		target = 1
	}
	var seen int64
	for index, count := range buckets {
		seen += count
		if seen < target {
			continue
		}
		if index < len(latencyBoundsMS) {
			return latencyBoundsMS[index]
		}
		break
	}
	return maxMS
}

// FailureRate reports server failures per hundred requests, which is the one
// number worth putting on a page rather than in a table.
func (report trafficReport) FailureRate() string {
	if report.Requests == 0 {
		return "0.0"
	}
	return fmt.Sprintf("%.1f", float64(report.ByStatusClass["5xx"])*100/float64(report.Requests))
}

// Busiest reports the routes worth showing on the monitoring page.
func (report trafficReport) Busiest(limit int) []trafficRecord {
	if len(report.Routes) <= limit {
		return report.Routes
	}
	return report.Routes[:limit]
}

// statusRecorder remembers the status a handler wrote. A handler that never
// calls WriteHeader wrote 200, which is the value it starts with.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (recorder *statusRecorder) WriteHeader(status int) {
	if !recorder.written {
		recorder.status = status
		recorder.written = true
	}
	recorder.ResponseWriter.WriteHeader(status)
}

func (recorder *statusRecorder) Write(body []byte) (int, error) {
	recorder.written = true
	return recorder.ResponseWriter.Write(body)
}

// Flush keeps a streaming or proxied response working through the recorder.
func (recorder *statusRecorder) Flush() {
	if flusher, ok := recorder.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer, so
// hijacking and deadlines still work through the recorder.
func (recorder *statusRecorder) Unwrap() http.ResponseWriter { return recorder.ResponseWriter }
