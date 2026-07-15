// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import "testing"

func TestLoadRejectsMissingRequiredConfiguration(t *testing.T) {
	_, err := Load(func(string) string { return "" })
	if err == nil {
		t.Fatal("Load succeeded without required configuration")
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
