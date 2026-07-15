// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import "testing"

func TestValidateManagedApp(t *testing.T) {
	valid := ManagedApp{
		Slug:               "bleephub-dev",
		Name:               "Bleephub",
		Description:        "A real deployed service.",
		LaunchURL:          "https://bleephub.dev.e6qu.dev",
		OIDCClientID:       "bleephub-dev",
		ECSServiceName:     "bleephub",
		CloudWatchLogGroup: "/e6qu/bleephub",
	}
	if err := validateManagedApp(valid); err != nil {
		t.Fatalf("validateManagedApp(valid) error = %v", err)
	}

	for name, app := range map[string]ManagedApp{
		"uppercase slug":     withManagedApp(valid, func(app *ManagedApp) { app.Slug = "Bleephub" }),
		"invalid launch URL": withManagedApp(valid, func(app *ManagedApp) { app.LaunchURL = "http://bleephub.dev.e6qu.dev" }),
		"invalid log group":  withManagedApp(valid, func(app *ManagedApp) { app.CloudWatchLogGroup = "/aws/ecs/bleephub" }),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateManagedApp(app); err == nil {
				t.Fatal("validateManagedApp() succeeded for invalid app")
			}
		})
	}
}

func withManagedApp(app ManagedApp, mutate func(*ManagedApp)) ManagedApp {
	mutate(&app)
	return app
}
