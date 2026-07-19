// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import "testing"

func TestValidateManagedApp(t *testing.T) {
	valid := ManagedApp{
		Slug:          "bleephub-dev",
		Name:          "Bleephub",
		Description:   "A real deployed service.",
		LaunchURL:     "https://bleephub.dev.e6qu.dev",
		OIDCClientID:  "bleephub-dev",
		HealthURL:     "https://bleephub.dev.e6qu.dev/health",
		MonitoringURL: "https://bleephub.dev.e6qu.dev/monitoring",
	}
	if err := ValidateManagedApp(valid); err != nil {
		t.Fatalf("ValidateManagedApp(valid) error = %v", err)
	}

	for name, app := range map[string]ManagedApp{
		"uppercase slug":     withManagedApp(valid, func(app *ManagedApp) { app.Slug = "Bleephub" }),
		"invalid launch URL": withManagedApp(valid, func(app *ManagedApp) { app.LaunchURL = "http://bleephub.dev.e6qu.dev" }),
		"invalid health URL": withManagedApp(valid, func(app *ManagedApp) { app.HealthURL = "http://bleephub.dev.e6qu.dev/health" }),
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateManagedApp(app); err == nil {
				t.Fatal("ValidateManagedApp() succeeded for invalid app")
			}
		})
	}
}

func TestValidateManagedAppAllowsLoopbackHTTPForLocalIntegration(t *testing.T) {
	app := ManagedApp{
		Slug:         "local-app",
		Name:         "Local app",
		Description:  "A real local integration service.",
		LaunchURL:    "http://localhost:5556/",
		OIDCClientID: "local-app",
		HealthURL:    "http://127.0.0.1:5556/healthz",
	}
	if err := ValidateManagedApp(app); err != nil {
		t.Fatalf("ValidateManagedApp(loopback) error = %v", err)
	}
}

func withManagedApp(app ManagedApp, mutate func(*ManagedApp)) ManagedApp {
	mutate(&app)
	return app
}
