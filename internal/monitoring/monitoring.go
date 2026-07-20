// SPDX-License-Identifier: AGPL-3.0-or-later

// Package monitoring consumes deployment-neutral infrastructure observations.
package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const SchemaVersion = "e6qu.monitoring/v1"
const PricingBasis = "public-on-demand"
const maximumResponseBytes = 1 << 20

var requiredPricingExclusions = []string{"credits", "free_tier", "reservations", "savings_plans", "taxes"}

type Source struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	BearerToken string `json:"bearer_token"`
}

type Snapshot struct {
	SchemaVersion string       `json:"schema_version"`
	ObservedAt    time.Time    `json:"observed_at"`
	Resources     []Resource   `json:"resources"`
	CostEstimate  CostEstimate `json:"cost_estimate"`
}

type Resource struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	Health  string   `json:"health"`
	Metrics []Metric `json:"metrics"`
}

type Metric struct {
	Name   string   `json:"name"`
	Label  string   `json:"label"`
	Value  *float64 `json:"value,omitempty"`
	Unit   string   `json:"unit"`
	Status string   `json:"status"`
}

func (metric Metric) DisplayValue() string {
	if metric.Status != "available" || metric.Value == nil {
		return metric.Status
	}
	return fmt.Sprintf("%.3f %s", *metric.Value, metric.Unit)
}

type CostEstimate struct {
	Currency      string         `json:"currency"`
	Basis         string         `json:"basis"`
	HoursPerMonth float64        `json:"hours_per_month"`
	Hourly        float64        `json:"hourly"`
	Daily         float64        `json:"daily"`
	Monthly       float64        `json:"monthly"`
	Excludes      []string       `json:"excludes"`
	Limitations   []string       `json:"limitations"`
	LineItems     []CostLineItem `json:"line_items"`
}

type CostLineItem struct {
	Name    string  `json:"name"`
	Hourly  float64 `json:"hourly"`
	Monthly float64 `json:"monthly"`
}

type Result struct {
	SourceName string
	Snapshot   Snapshot
	Error      string
	Stale      bool
}

type Client struct {
	httpClient *http.Client
	now        func() time.Time
}

func NewClient() *Client {
	return &Client{httpClient: &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, now: time.Now}
}

func ValidateSources(sources []Source) error {
	seen := make(map[string]struct{}, len(sources))
	for index, source := range sources {
		source.Name = strings.TrimSpace(source.Name)
		if source.Name == "" {
			return fmt.Errorf("monitoring source %d has no name", index+1)
		}
		if _, exists := seen[source.Name]; exists {
			return fmt.Errorf("monitoring source name %q is duplicated", source.Name)
		}
		seen[source.Name] = struct{}{}
		endpoint, err := url.ParseRequestURI(strings.TrimSpace(source.URL))
		if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" {
			return fmt.Errorf("monitoring source %q URL must be absolute and contain no user information or fragment", source.Name)
		}
		host := strings.Trim(strings.ToLower(endpoint.Hostname()), "[]")
		if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && (host == "localhost" || host == "::1" || net.ParseIP(host).IsLoopback())) {
			return fmt.Errorf("monitoring source %q URL must use HTTPS unless it targets loopback", source.Name)
		}
		if len(source.BearerToken) < 32 || strings.IndexFunc(source.BearerToken, func(character rune) bool {
			return character <= ' ' || character == '\u007f'
		}) >= 0 {
			return fmt.Errorf("monitoring source %q bearer token must contain at least 32 non-whitespace characters", source.Name)
		}
	}
	return nil
}

func (client *Client) FetchAll(ctx context.Context, sources []Source) []Result {
	results := make([]Result, len(sources))
	var group sync.WaitGroup
	group.Add(len(sources))
	for index, source := range sources {
		go func() {
			defer group.Done()
			results[index] = Result{SourceName: source.Name}
			snapshot, err := client.fetch(ctx, source)
			if err != nil {
				results[index].Error = err.Error()
				return
			}
			results[index].Snapshot = snapshot
			results[index].Stale = client.now().Sub(snapshot.ObservedAt) > 5*time.Minute
		}()
	}
	group.Wait()
	return results
}

func (client *Client) fetch(ctx context.Context, source Source) (Snapshot, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return Snapshot{}, fmt.Errorf("create observation request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+source.BearerToken)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return Snapshot{}, fmt.Errorf("request observation: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Snapshot{}, fmt.Errorf("observation endpoint returned HTTP %d", response.StatusCode)
	}
	if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])); mediaType != "application/json" {
		return Snapshot{}, fmt.Errorf("observation endpoint returned %q instead of application/json", mediaType)
	}
	limited := &io.LimitedReader{R: response.Body, N: maximumResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode observation: %w", err)
	}
	if limited.N <= 0 {
		return Snapshot{}, fmt.Errorf("observation exceeds %d bytes", maximumResponseBytes)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Snapshot{}, fmt.Errorf("observation contains trailing JSON")
	}
	if err := snapshot.validate(client.now()); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func (snapshot Snapshot) Validate() error {
	return snapshot.validate(time.Now())
}

func (snapshot Snapshot) validate(now time.Time) error {
	if snapshot.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported monitoring schema %q", snapshot.SchemaVersion)
	}
	if snapshot.ObservedAt.IsZero() {
		return fmt.Errorf("monitoring observation time is required")
	}
	if snapshot.ObservedAt.After(now.Add(time.Minute)) {
		return fmt.Errorf("monitoring observation time is more than one minute in the future")
	}
	if len(snapshot.Resources) == 0 {
		return fmt.Errorf("monitoring observation contains no resources")
	}
	seen := make(map[string]struct{}, len(snapshot.Resources))
	for _, resource := range snapshot.Resources {
		if strings.TrimSpace(resource.ID) == "" || strings.TrimSpace(resource.Name) == "" || strings.TrimSpace(resource.Kind) == "" {
			return fmt.Errorf("monitoring resource ID, name, and kind are required")
		}
		if _, exists := seen[resource.ID]; exists {
			return fmt.Errorf("monitoring resource ID %q is duplicated", resource.ID)
		}
		seen[resource.ID] = struct{}{}
		if resource.Health != "healthy" && resource.Health != "degraded" && resource.Health != "unhealthy" && resource.Health != "unknown" {
			return fmt.Errorf("monitoring resource %q has invalid health %q", resource.ID, resource.Health)
		}
		metricNames := make(map[string]struct{}, len(resource.Metrics))
		for _, metric := range resource.Metrics {
			if strings.TrimSpace(metric.Name) == "" || strings.TrimSpace(metric.Label) == "" || strings.TrimSpace(metric.Unit) == "" || (metric.Status != "available" && metric.Status != "unavailable" && metric.Status != "not_applicable") {
				return fmt.Errorf("monitoring resource %q contains an invalid metric", resource.ID)
			}
			if metric.Status == "available" && (metric.Value == nil || math.IsNaN(*metric.Value) || math.IsInf(*metric.Value, 0) || *metric.Value < 0) {
				return fmt.Errorf("monitoring resource %q contains an invalid available metric", resource.ID)
			}
			if metric.Status != "available" && metric.Value != nil {
				return fmt.Errorf("monitoring resource %q contains a value for an unavailable metric", resource.ID)
			}
			if _, exists := metricNames[metric.Name]; exists {
				return fmt.Errorf("monitoring resource %q metric %q is duplicated", resource.ID, metric.Name)
			}
			metricNames[metric.Name] = struct{}{}
		}
	}
	return snapshot.CostEstimate.validate()
}

func (estimate CostEstimate) validate() error {
	if estimate.Currency != "USD" || estimate.Basis != PricingBasis || estimate.HoursPerMonth <= 0 {
		return fmt.Errorf("cost estimate must use USD public on-demand pricing and a positive monthly hour count")
	}
	for _, value := range []float64{estimate.Hourly, estimate.Daily, estimate.Monthly} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return fmt.Errorf("cost estimate contains an invalid total")
		}
	}
	exclusions := append([]string(nil), estimate.Excludes...)
	sort.Strings(exclusions)
	if !equalStrings(exclusions, requiredPricingExclusions) {
		return fmt.Errorf("cost estimate exclusions must be credits, free_tier, reservations, savings_plans, and taxes")
	}
	if len(estimate.LineItems) == 0 {
		return fmt.Errorf("cost estimate contains no line items")
	}
	if len(estimate.Limitations) == 0 {
		return fmt.Errorf("cost estimate must disclose unpriced or unmeasured components")
	}
	for _, limitation := range estimate.Limitations {
		if strings.TrimSpace(limitation) == "" {
			return fmt.Errorf("cost estimate contains an empty limitation")
		}
	}
	var hourlyTotal float64
	var monthlyTotal float64
	for _, item := range estimate.LineItems {
		if strings.TrimSpace(item.Name) == "" || item.Hourly < 0 || item.Monthly < 0 || math.IsNaN(item.Hourly) || math.IsNaN(item.Monthly) || math.IsInf(item.Hourly, 0) || math.IsInf(item.Monthly, 0) {
			return fmt.Errorf("cost estimate contains an invalid line item")
		}
		hourlyTotal += item.Hourly
		monthlyTotal += item.Monthly
	}
	if !nearlyEqual(estimate.Hourly, hourlyTotal) || !nearlyEqual(estimate.Daily, estimate.Hourly*24) || !nearlyEqual(estimate.Monthly, monthlyTotal) {
		return fmt.Errorf("cost estimate totals do not match its line items and pricing period")
	}
	return nil
}

func nearlyEqual(left, right float64) bool {
	tolerance := math.Max(0.000001, math.Max(math.Abs(left), math.Abs(right))*0.000001)
	return math.Abs(left-right) <= tolerance
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
