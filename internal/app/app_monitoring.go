// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/e6qu/shauth/internal/identity"
	"github.com/e6qu/shauth/internal/monitoring"
	"github.com/e6qu/shauth/internal/observe"
)

// Monitoring published by the deployed applications themselves.
//
// managed_apps has carried a monitoring_url column since migration 000003. The
// store writes it, the upsert compares it, the admin API accepts and returns
// it -- and nothing ever read it to fetch anything. FetchAll was only ever
// given config.MonitoringSources, the hand-written list, so every application
// could register a monitoring endpoint, have it stored and echoed back, and be
// silently never asked for an observation.
//
// That is why a container could sit against its memory ceiling for five days,
// throttling its own sockets eighteen thousand times a second, while every
// surface an operator looks at reported healthy. Nothing was collecting from
// the applications, and the field that says otherwise was decorative.
//
// An application that publishes no endpoint is reported as degraded rather than
// omitted. Absent monitoring is a defect to fix in that application, not a
// quiet gap in the page.

// applicationMonitoringSources turns every registered application that
// publishes an observation endpoint into a monitoring source, and names the
// ones that do not.
func (s *Server) applicationMonitoringSources(ctx context.Context) (sources []monitoring.Source, unpublished []string, err error) {
	apps, err := s.store.ListManagedApps(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("list managed apps: %w", err)
	}
	tokens := make(map[string]string, len(s.config.BootstrapApps))
	for _, bootstrap := range s.config.BootstrapApps {
		tokens[bootstrap.Slug] = strings.TrimSpace(bootstrap.MonitoringToken)
	}
	sources, unpublished = applicationMonitoringSources(apps, tokens)
	return sources, unpublished, nil
}

// applicationMonitoringSources is the mapping on its own, so it can be tested
// without a database behind it.
func applicationMonitoringSources(apps []identity.ManagedApp, tokens map[string]string) (sources []monitoring.Source, unpublished []string) {
	for _, managed := range apps {
		endpoint := strings.TrimSpace(managed.MonitoringURL)
		if endpoint == "" {
			unpublished = append(unpublished, managed.Name)
			continue
		}
		token := tokens[managed.Slug]
		if token == "" {
			// Registered an endpoint but no credential to read it with. Naming
			// it as unpublished would claim the application is at fault for a
			// deployment omission, so it is reported separately.
			unpublished = append(unpublished, managed.Name+" (no monitoring credential is deployed)")
			continue
		}
		sources = append(sources, monitoring.Source{
			Name:        managed.Name,
			URL:         endpoint,
			BearerToken: token,
		})
	}
	sort.Slice(sources, func(left, right int) bool { return sources[left].Name < sources[right].Name })
	sort.Strings(unpublished)
	return sources, unpublished
}

// monitoringSources is every source to collect from: the configured
// infrastructure observers plus the applications themselves.
func (s *Server) monitoringSources(ctx context.Context) []monitoring.Source {
	sources := append([]monitoring.Source(nil), s.config.MonitoringSources...)
	applications, _, err := s.applicationMonitoringSources(ctx)
	if err != nil {
		observe.Errorf("application monitoring sources: %v", err)
		return sources
	}
	return append(sources, applications...)
}

// checkApplicationMonitoring reports applications that publish no observation
// endpoint. It is degraded, not unhealthy: single sign-on still works, but the
// deployment cannot see inside those applications, and that is drift an
// operator has to fix.
func (s *Server) checkApplicationMonitoring(ctx context.Context) (string, string) {
	sources, unpublished, err := s.applicationMonitoringSources(ctx)
	if err != nil {
		return healthUnhealthy, "the application catalog could not be listed"
	}
	if len(unpublished) > 0 {
		return healthDegraded, fmt.Sprintf(
			"%d of %d applications publish no monitoring observation: %s",
			len(unpublished), len(sources)+len(unpublished), strings.Join(unpublished, ", "),
		)
	}
	if len(sources) == 0 {
		return healthDegraded, "no application publishes a monitoring observation"
	}
	return healthHealthy, ""
}
