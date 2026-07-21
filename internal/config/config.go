// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"

	"github.com/e6qu/shauth/internal/monitoring"
)

var tenantIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

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
	EntraTenantID          string
	EntraClientID          string
	EntraClientSecret      string
	BootstrapAdminEmail    string
	BootstrapAdminPassword string
	ValidationUsername     string
	ValidationEmail        string
	AllowInsecureCookies   bool
	SESRegion              string
	InvitationEmailFrom    string
	BootstrapApps          []BootstrapApp
	MonitoringSources      []monitoring.Source
	ValidatorToken         string
	ValidationStatusToken  string
}

// BootstrapApp is a confidential OpenID Connect client and its corresponding
// deployed service. Deployment supplies this only through a Secrets Manager
// backed environment variable because it includes the client secret.
type BootstrapApp struct {
	Slug                   string   `json:"slug"`
	Name                   string   `json:"name"`
	Description            string   `json:"description"`
	LaunchURL              string   `json:"launch_url"`
	OIDCClientID           string   `json:"oidc_client_id"`
	OIDCClientSecret       string   `json:"oidc_client_secret"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	FrontChannelLogoutURI  string   `json:"frontchannel_logout_uri"`
	BackChannelLogoutURI   string   `json:"backchannel_logout_uri"`
	HealthURL              string   `json:"health_url"`
	MonitoringURL          string   `json:"monitoring_url"`
	ValidationURL          string   `json:"validation_url"`
	SignedOutURL           string   `json:"signed_out_url"`
	ReleaseRevision        string   `json:"release_revision"`
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
		EntraTenantID:          getenv("ENTRA_TENANT_ID"),
		EntraClientID:          getenv("ENTRA_CLIENT_ID"),
		EntraClientSecret:      getenv("ENTRA_CLIENT_SECRET"),
		BootstrapAdminEmail:    getenv("SHAUTH_BOOTSTRAP_ADMIN_EMAIL"),
		BootstrapAdminPassword: getenv("SHAUTH_BOOTSTRAP_ADMIN_PASSWORD"),
		ValidationUsername:     getenv("SHAUTH_VALIDATION_USERNAME"),
		ValidationEmail:        getenv("SHAUTH_VALIDATION_EMAIL"),
		AllowInsecureCookies:   getenv("SHAUTH_ALLOW_INSECURE_COOKIES") == "true",
		SESRegion:              getenv("SHAUTH_SES_REGION"),
		InvitationEmailFrom:    getenv("SHAUTH_INVITATION_EMAIL_FROM"),
		ValidatorToken:         getenv("SHAUTH_VALIDATOR_TOKEN"),
		ValidationStatusToken:  getenv("SHAUTH_VALIDATION_STATUS_TOKEN"),
	}
	if (config.BootstrapAdminEmail == "") != (config.BootstrapAdminPassword == "") {
		return Config{}, fmt.Errorf("SHAUTH_BOOTSTRAP_ADMIN_EMAIL and SHAUTH_BOOTSTRAP_ADMIN_PASSWORD must be set together")
	}
	if config.BootstrapAdminPassword != "" && len(config.BootstrapAdminPassword) < 14 {
		return Config{}, fmt.Errorf("SHAUTH_BOOTSTRAP_ADMIN_PASSWORD must have at least 14 characters")
	}
	validationValues := 0
	for _, value := range []string{config.ValidationUsername, config.ValidationEmail, config.ValidatorToken} {
		if value != "" {
			validationValues++
		}
	}
	if validationValues != 0 && validationValues != 3 {
		return Config{}, fmt.Errorf("SHAUTH_VALIDATION_USERNAME, SHAUTH_VALIDATION_EMAIL, and SHAUTH_VALIDATOR_TOKEN must be set together")
	}
	entraValues := 0
	for _, value := range []string{config.EntraTenantID, config.EntraClientID, config.EntraClientSecret} {
		if value != "" {
			entraValues++
		}
	}
	if entraValues != 0 && entraValues != 3 {
		return Config{}, fmt.Errorf("ENTRA_TENANT_ID, ENTRA_CLIENT_ID, and ENTRA_CLIENT_SECRET must be set together")
	}
	if config.EntraTenantID != "" && !tenantIDPattern.MatchString(config.EntraTenantID) {
		return Config{}, fmt.Errorf("ENTRA_TENANT_ID must be a specific Microsoft Entra ID tenant UUID")
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
	if raw := getenv("SHAUTH_MONITORING_SOURCES_JSON"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &config.MonitoringSources); err != nil {
			return Config{}, fmt.Errorf("SHAUTH_MONITORING_SOURCES_JSON must be valid JSON: %w", err)
		}
		if err := monitoring.ValidateSources(config.MonitoringSources); err != nil {
			return Config{}, fmt.Errorf("SHAUTH_MONITORING_SOURCES_JSON: %w", err)
		}
	}
	if config.ValidatorToken != "" && len(config.ValidatorToken) < 32 {
		return Config{}, fmt.Errorf("SHAUTH_VALIDATOR_TOKEN must contain at least 32 characters")
	}
	if config.ValidationStatusToken != "" && len(config.ValidationStatusToken) < 32 {
		return Config{}, fmt.Errorf("SHAUTH_VALIDATION_STATUS_TOKEN must contain at least 32 characters")
	}
	if config.ValidatorToken != "" && config.ValidationStatusToken != "" && config.ValidatorToken == config.ValidationStatusToken {
		return Config{}, fmt.Errorf("SHAUTH_VALIDATION_STATUS_TOKEN must differ from SHAUTH_VALIDATOR_TOKEN")
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
