// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"testing"
)

func TestLoadRejectsMissingRequiredConfiguration(t *testing.T) {
	_, err := Load(func(string) string { return "" })
	if err == nil {
		t.Fatal("Load succeeded without required configuration")
	}
}

func TestLoadReadsBootstrapApps(t *testing.T) {
	values := map[string]string{
		"SHAUTH_PUBLIC_URL": "https://auth.dev.e6qu.dev", "HYDRA_ADMIN_URL": "http://hydra:4445", "HYDRA_PUBLIC_INTERNAL_URL": "http://hydra:4444",
		"DATABASE_URL": "postgres://shauth:password@postgres/shauth", "GITHUB_CLIENT_ID": "client-id", "GITHUB_CLIENT_SECRET": "client-secret",
		"GITHUB_DEVELOPER_TEAM": "e6qu-org/e6qu-org-members", "GITHUB_ADMIN_TEAM": "e6qu-org/e6qu-org-admins", "SHAUTH_SES_REGION": "eu-west-1", "SHAUTH_INVITATION_EMAIL_FROM": "no-reply@auth.dev.e6qu.dev",
		"SHAUTH_BOOTSTRAP_APPS_JSON": `[{"slug":"intraktible","name":"Intraktible","description":"Decision platform","launch_url":"https://intraktible.dev.e6qu.dev","health_url":"https://intraktible.dev.e6qu.dev/health","oidc_client_id":"intraktible-dev","oidc_client_secret":"0123456789abcdef0123456789abcdef","redirect_uris":["https://intraktible.dev.e6qu.dev/v1/auth/oidc/shauth/callback"],"post_logout_redirect_uris":["https://intraktible.dev.e6qu.dev/"],"frontchannel_logout_uri":"https://intraktible.dev.e6qu.dev/v1/auth/oidc/shauth/frontchannel-logout","backchannel_logout_uri":"https://intraktible.dev.e6qu.dev/v1/auth/oidc/shauth/backchannel-logout"}]`,
	}
	config, err := Load(func(key string) string { return values[key] })
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(config.BootstrapApps) != 1 || config.BootstrapApps[0].OIDCClientID != "intraktible-dev" || config.BootstrapApps[0].BackChannelLogoutURI == "" {
		t.Fatalf("BootstrapApps = %#v", config.BootstrapApps)
	}
}

func TestLoadRejectsInvalidBootstrapAppsJSON(t *testing.T) {
	values := map[string]string{
		"SHAUTH_PUBLIC_URL": "https://auth.dev.e6qu.dev", "HYDRA_ADMIN_URL": "http://hydra:4445", "HYDRA_PUBLIC_INTERNAL_URL": "http://hydra:4444",
		"DATABASE_URL": "postgres://shauth:password@postgres/shauth", "GITHUB_CLIENT_ID": "client-id", "GITHUB_CLIENT_SECRET": "client-secret",
		"GITHUB_DEVELOPER_TEAM": "e6qu-org/e6qu-org-members", "GITHUB_ADMIN_TEAM": "e6qu-org/e6qu-org-admins", "SHAUTH_SES_REGION": "eu-west-1", "SHAUTH_INVITATION_EMAIL_FROM": "no-reply@auth.dev.e6qu.dev", "SHAUTH_BOOTSTRAP_APPS_JSON": "{",
	}
	if _, err := Load(func(key string) string { return values[key] }); err == nil {
		t.Fatal("Load accepted invalid bootstrap app JSON")
	}
}

func TestLoadAcceptsCompleteConfiguration(t *testing.T) {
	values := map[string]string{
		"SHAUTH_PUBLIC_URL":            "https://auth.dev.e6qu.dev",
		"HYDRA_ADMIN_URL":              "http://hydra:4445",
		"HYDRA_PUBLIC_INTERNAL_URL":    "http://hydra:4444",
		"DATABASE_URL":                 "postgres://shauth:password@postgres/shauth",
		"GITHUB_CLIENT_ID":             "client-id",
		"GITHUB_CLIENT_SECRET":         "client-secret",
		"GITHUB_DEVELOPER_TEAM":        "e6qu-org/e6qu-org-members",
		"GITHUB_ADMIN_TEAM":            "e6qu-org/e6qu-org-admins",
		"SHAUTH_SES_REGION":            "eu-west-1",
		"SHAUTH_INVITATION_EMAIL_FROM": "no-reply@auth.dev.e6qu.dev",
	}
	config, err := Load(func(key string) string { return values[key] })
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.Address != ":8080" {
		t.Fatalf("Address = %q, want default", config.Address)
	}
}

func TestLoadAcceptsSpecificMicrosoftEntraIDTenant(t *testing.T) {
	values := map[string]string{
		"SHAUTH_PUBLIC_URL": "https://auth.dev.e6qu.dev", "HYDRA_ADMIN_URL": "http://hydra:4445", "HYDRA_PUBLIC_INTERNAL_URL": "http://hydra:4444",
		"DATABASE_URL": "postgres://shauth:password@postgres/shauth", "GITHUB_CLIENT_ID": "client-id", "GITHUB_CLIENT_SECRET": "client-secret",
		"GITHUB_DEVELOPER_TEAM": "e6qu-org/e6qu-org-members", "GITHUB_ADMIN_TEAM": "e6qu-org/e6qu-org-admins", "SHAUTH_SES_REGION": "eu-west-1", "SHAUTH_INVITATION_EMAIL_FROM": "no-reply@auth.dev.e6qu.dev",
		"ENTRA_TENANT_ID": "12345678-1234-4234-8234-123456789abc", "ENTRA_CLIENT_ID": "entra-client", "ENTRA_CLIENT_SECRET": "entra-secret",
	}
	config, err := Load(func(key string) string { return values[key] })
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.EntraTenantID != values["ENTRA_TENANT_ID"] {
		t.Fatalf("EntraTenantID = %q", config.EntraTenantID)
	}
}

func TestLoadRejectsPartialOrNonSpecificMicrosoftEntraIDConfiguration(t *testing.T) {
	base := map[string]string{
		"SHAUTH_PUBLIC_URL": "https://auth.dev.e6qu.dev", "HYDRA_ADMIN_URL": "http://hydra:4445", "HYDRA_PUBLIC_INTERNAL_URL": "http://hydra:4444",
		"DATABASE_URL": "postgres://shauth:password@postgres/shauth", "GITHUB_CLIENT_ID": "client-id", "GITHUB_CLIENT_SECRET": "client-secret",
		"GITHUB_DEVELOPER_TEAM": "e6qu-org/e6qu-org-members", "GITHUB_ADMIN_TEAM": "e6qu-org/e6qu-org-admins", "SHAUTH_SES_REGION": "eu-west-1", "SHAUTH_INVITATION_EMAIL_FROM": "no-reply@auth.dev.e6qu.dev",
	}
	for name, entra := range map[string]map[string]string{
		"partial":       {"ENTRA_TENANT_ID": "12345678-1234-4234-8234-123456789abc"},
		"common tenant": {"ENTRA_TENANT_ID": "common", "ENTRA_CLIENT_ID": "client", "ENTRA_CLIENT_SECRET": "secret"},
	} {
		t.Run(name, func(t *testing.T) {
			values := make(map[string]string, len(base)+len(entra))
			for key, value := range base {
				values[key] = value
			}
			for key, value := range entra {
				values[key] = value
			}
			if _, err := Load(func(key string) string { return values[key] }); err == nil {
				t.Fatal("Load() accepted unsafe Microsoft Entra ID configuration")
			}
		})
	}
}
