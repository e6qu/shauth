// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
)

// Config contains the runtime coordinates required by the Shauth login and
// administration application. Secrets are supplied solely through the runtime
// environment, normally from AWS Secrets Manager.
type Config struct {
	Address                string
	PublicURL              *url.URL
	DatabaseURL            string
	HydraAdminURL          *url.URL
	HydraPublicURL         *url.URL
	GitHubClientID         string
	GitHubClientSecret     string
	GitHubDeveloperTeam    string
	GitHubAdminTeam        string
	BootstrapAdminEmail    string
	BootstrapAdminPassword string
	AllowInsecureCookies   bool
	SESRegion              string
	InvitationEmailFrom    string
	BootstrapApps          []BootstrapApp
}

// BootstrapApp is a confidential OpenID Connect client and its corresponding
// deployed service. Deployment supplies this only through a Secrets Manager
// backed environment variable because it includes the client secret.
type BootstrapApp struct {
	Slug             string   `json:"slug"`
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	LaunchURL        string   `json:"launch_url"`
	OIDCClientID     string   `json:"oidc_client_id"`
	OIDCClientSecret string   `json:"oidc_client_secret"`
	RedirectURIs     []string `json:"redirect_uris"`
	// Optional allowlist of post-logout redirect URIs. When set, Hydra
	// honours them so a relying app's RP-initiated logout returns the
	// browser to the app instead of Shauth's default post-logout page.
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	HealthURL              string   `json:"health_url"`
	MonitoringURL          string   `json:"monitoring_url"`
}

// Load reads and validates the complete production configuration.
func Load(getenv func(string) string) (Config, error) {
	publicURL, err := requiredURL(getenv, "SHAUTH_PUBLIC_URL")
	if err != nil {
		return Config{}, err
	}
	hydraAdminURL, err := requiredURL(getenv, "HYDRA_ADMIN_URL")
	if err != nil {
		return Config{}, err
	}
	hydraPublicURL, err := requiredURL(getenv, "HYDRA_PUBLIC_INTERNAL_URL")
	if err != nil {
		return Config{}, err
	}

	config := Config{
		Address:                getenv("SHAUTH_LISTEN_ADDRESS"),
		PublicURL:              publicURL,
		DatabaseURL:            getenv("DATABASE_URL"),
		HydraAdminURL:          hydraAdminURL,
		HydraPublicURL:         hydraPublicURL,
		GitHubClientID:         getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret:     getenv("GITHUB_CLIENT_SECRET"),
		GitHubDeveloperTeam:    getenv("GITHUB_DEVELOPER_TEAM"),
		GitHubAdminTeam:        getenv("GITHUB_ADMIN_TEAM"),
		BootstrapAdminEmail:    getenv("SHAUTH_BOOTSTRAP_ADMIN_EMAIL"),
		BootstrapAdminPassword: getenv("SHAUTH_BOOTSTRAP_ADMIN_PASSWORD"),
		AllowInsecureCookies:   getenv("SHAUTH_ALLOW_INSECURE_COOKIES") == "true",
		SESRegion:              getenv("SHAUTH_SES_REGION"),
		InvitationEmailFrom:    getenv("SHAUTH_INVITATION_EMAIL_FROM"),
	}
	if (config.BootstrapAdminEmail == "") != (config.BootstrapAdminPassword == "") {
		return Config{}, fmt.Errorf("SHAUTH_BOOTSTRAP_ADMIN_EMAIL and SHAUTH_BOOTSTRAP_ADMIN_PASSWORD must be set together")
	}
	if config.BootstrapAdminPassword != "" && len(config.BootstrapAdminPassword) < 14 {
		return Config{}, fmt.Errorf("SHAUTH_BOOTSTRAP_ADMIN_PASSWORD must have at least 14 characters")
	}
	if publicURL.Scheme != "https" && !config.AllowInsecureCookies {
		return Config{}, fmt.Errorf("SHAUTH_PUBLIC_URL must use HTTPS unless SHAUTH_ALLOW_INSECURE_COOKIES=true")
	}
	if config.Address == "" {
		config.Address = ":8080"
	}
	if raw := getenv("SHAUTH_BOOTSTRAP_APPS_JSON"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &config.BootstrapApps); err != nil {
			return Config{}, fmt.Errorf("SHAUTH_BOOTSTRAP_APPS_JSON must be valid JSON: %w", err)
		}
	}
	for name, value := range map[string]string{
		"DATABASE_URL":                 config.DatabaseURL,
		"GITHUB_CLIENT_ID":             config.GitHubClientID,
		"GITHUB_CLIENT_SECRET":         config.GitHubClientSecret,
		"GITHUB_DEVELOPER_TEAM":        config.GitHubDeveloperTeam,
		"GITHUB_ADMIN_TEAM":            config.GitHubAdminTeam,
		"SHAUTH_SES_REGION":            config.SESRegion,
		"SHAUTH_INVITATION_EMAIL_FROM": config.InvitationEmailFrom,
	} {
		if value == "" {
			return Config{}, fmt.Errorf("%s must be set", name)
		}
	}
	return config, nil
}

func requiredURL(getenv func(string) string, name string) (*url.URL, error) {
	rawURL := getenv(name)
	if rawURL == "" {
		return nil, fmt.Errorf("%s must be set", name)
	}
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("%s must be an absolute URL", name)
	}
	return parsed, nil
}

// FromEnvironment loads production configuration from the process environment.
func FromEnvironment() (Config, error) {
	return Load(os.Getenv)
}
