// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import "testing"

const testOIDCContractHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestValidateManagedApp(t *testing.T) {
	valid := ManagedApp{
		Slug:             "bleephub-dev",
		Name:             "Bleephub",
		Description:      "A real deployed service.",
		LaunchURL:        "https://bleephub.dev.e6qu.dev",
		OIDCClientID:     "bleephub-dev",
		OIDCContractHash: testOIDCContractHash,
		HealthURL:        "https://bleephub.dev.e6qu.dev/health",
		MonitoringURL:    "https://bleephub.dev.e6qu.dev/monitoring",
		ValidationURL:    "https://bleephub.dev.e6qu.dev/ui/",
		SignedOutURL:     "https://bleephub.dev.e6qu.dev/ui/signed-out",
		ReleaseRevision:  "0123456789ab",
	}
	if err := ValidateManagedApp(valid); err != nil {
		t.Fatalf("ValidateManagedApp(valid) error = %v", err)
	}

	for name, app := range map[string]ManagedApp{
		"uppercase slug":             withManagedApp(valid, func(app *ManagedApp) { app.Slug = "Bleephub" }),
		"missing OIDC contract hash": withManagedApp(valid, func(app *ManagedApp) { app.OIDCContractHash = "" }),
		"invalid OIDC contract hash": withManagedApp(valid, func(app *ManagedApp) { app.OIDCContractHash = "ABC" }),
		"invalid launch URL":         withManagedApp(valid, func(app *ManagedApp) { app.LaunchURL = "http://bleephub.dev.e6qu.dev" }),
		"invalid health URL":         withManagedApp(valid, func(app *ManagedApp) { app.HealthURL = "http://bleephub.dev.e6qu.dev/health" }),
		"health origin mismatch": withManagedApp(valid, func(app *ManagedApp) {
			app.HealthURL = "https://health.example.test/health"
		}),
		"monitoring origin mismatch": withManagedApp(valid, func(app *ManagedApp) {
			app.MonitoringURL = "https://monitoring.example.test/monitoring"
		}),
		"missing validation URL": withManagedApp(valid, func(app *ManagedApp) {
			app.ValidationURL = ""
		}),
		"validation origin mismatch": withManagedApp(valid, func(app *ManagedApp) {
			app.ValidationURL = "https://attacker.example.test/me"
		}),
		"signed-out origin mismatch": withManagedApp(valid, func(app *ManagedApp) {
			app.SignedOutURL = "https://attacker.example.test/signed-out"
		}),
		"missing release revision": withManagedApp(valid, func(app *ManagedApp) {
			app.ReleaseRevision = ""
		}),
		"mutable release tag": withManagedApp(valid, func(app *ManagedApp) {
			app.ReleaseRevision = "latest"
		}),
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
		Slug:             "local-app",
		Name:             "Local app",
		Description:      "A real local integration service.",
		LaunchURL:        "http://gateway.localhost:5556/",
		OIDCClientID:     "local-app",
		OIDCContractHash: testOIDCContractHash,
		HealthURL:        "http://gateway.localhost:5556/healthz",
		ValidationURL:    "http://gateway.localhost:5556/me",
		SignedOutURL:     "http://gateway.localhost:5556/auth/signed-out",
		ReleaseRevision:  "0123456789ab",
	}
	if err := ValidateManagedApp(app); err != nil {
		t.Fatalf("ValidateManagedApp(loopback) error = %v", err)
	}
}

func TestManagedAppValidationContractDetectsEveryMaterialUpdate(t *testing.T) {
	base := ManagedApp{
		Name: "Bleephub", Description: "Git hosting", LaunchURL: "https://bleephub.example.test/",
		OIDCClientID: "bleephub", HealthURL: "https://bleephub.example.test/health",
		OIDCContractHash: testOIDCContractHash,
		MonitoringURL:    "https://bleephub.example.test/monitoring", ValidationURL: "https://bleephub.example.test/me",
		SignedOutURL: "https://bleephub.example.test/signed-out", ReleaseRevision: "0123456789ab",
	}
	if !sameManagedAppValidationContract(base, base) {
		t.Fatal("identical validation contracts differed")
	}
	for name, mutate := range map[string]func(*ManagedApp){
		"name":        func(app *ManagedApp) { app.Name = "Bleephub renamed" },
		"description": func(app *ManagedApp) { app.Description = "Updated" },
		"launch URL":  func(app *ManagedApp) { app.LaunchURL += "ui" },
		"OIDC client": func(app *ManagedApp) { app.OIDCClientID += "-v2" },
		"OIDC registration": func(app *ManagedApp) {
			app.OIDCContractHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		},
		"health URL":       func(app *ManagedApp) { app.HealthURL += "z" },
		"monitoring URL":   func(app *ManagedApp) { app.MonitoringURL += "/details" },
		"validation URL":   func(app *ManagedApp) { app.ValidationURL += "/details" },
		"signed-out URL":   func(app *ManagedApp) { app.SignedOutURL += "/complete" },
		"release revision": func(app *ManagedApp) { app.ReleaseRevision = "abcdef012345" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if sameManagedAppValidationContract(base, changed) {
				t.Fatal("material validation contract update was ignored")
			}
			if managedAppValidationContractHash(base, nil) == managedAppValidationContractHash(changed, nil) {
				t.Fatal("material validation contract update retained its queue fingerprint")
			}
		})
	}
	witness := ManagedApp{ID: "witness-id", Slug: "sharecrop", Name: "Sharecrop", OIDCClientID: "sharecrop", OIDCContractHash: testOIDCContractHash, LaunchURL: "https://sharecrop.example.test/", ValidationURL: "https://sharecrop.example.test/me", SignedOutURL: "https://sharecrop.example.test/signed-out", ReleaseRevision: "0123456789ab"}
	if managedAppValidationContractHash(base, nil) == managedAppValidationContractHash(base, &witness) {
		t.Fatal("adding a global logout witness retained the queue fingerprint")
	}
	updatedWitness := witness
	updatedWitness.ReleaseRevision = "abcdef012345"
	if managedAppValidationContractHash(base, &witness) == managedAppValidationContractHash(base, &updatedWitness) {
		t.Fatal("witness deployment update retained the queue fingerprint")
	}
	updatedWitness = witness
	updatedWitness.OIDCContractHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if managedAppValidationContractHash(base, &witness) == managedAppValidationContractHash(base, &updatedWitness) {
		t.Fatal("witness OIDC registration update retained the queue fingerprint")
	}
}

func withManagedApp(app ManagedApp, mutate func(*ManagedApp)) ManagedApp {
	mutate(&app)
	return app
}

func TestValidationWitnessRequiresDistinctClientAndOrigin(t *testing.T) {
	target := ManagedApp{ID: "target", OIDCClientID: "target-client", LaunchURL: "https://target.example.test/"}
	apps := []ManagedApp{
		target,
		{ID: "same-client", OIDCClientID: "target-client", LaunchURL: "https://other.example.test/"},
		{ID: "same-origin", OIDCClientID: "other-client", LaunchURL: "https://target.example.test/other"},
		{ID: "witness", OIDCClientID: "witness-client", LaunchURL: "https://witness.example.test/"},
	}
	selected := validationWitness(target, apps)
	if selected == nil || selected.ID != "witness" {
		t.Fatalf("validationWitness() = %#v, want distinct witness", selected)
	}
	if validationWitness(target, apps[:3]) != nil {
		t.Fatal("validationWitness() invented a witness without a distinct client and origin")
	}
}

func TestValidationWitnessCyclesAcrossEligibleApps(t *testing.T) {
	apps := []ManagedApp{
		{ID: "alpha", OIDCClientID: "alpha-client", LaunchURL: "https://alpha.example.test/"},
		{ID: "beta", OIDCClientID: "beta-client", LaunchURL: "https://beta.example.test/"},
		{ID: "gamma", OIDCClientID: "gamma-client", LaunchURL: "https://gamma.example.test/"},
	}

	for index, expectedWitnessID := range []string{"beta", "gamma", "alpha"} {
		selected := validationWitness(apps[index], apps)
		if selected == nil || selected.ID != expectedWitnessID {
			t.Fatalf("validationWitness(%q) = %#v, want %q", apps[index].ID, selected, expectedWitnessID)
		}
	}
}
