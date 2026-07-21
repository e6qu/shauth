// SPDX-License-Identifier: AGPL-3.0-or-later

// Package gateway provides a generic OpenID Connect relying-party reverse
// proxy for UI-only services that cannot own an OIDC client themselves.
package gateway

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var immutableApplicationRelease = regexp.MustCompile(`^(?:[0-9a-f]{12,64}|sha256:[0-9a-f]{64})$`)

type Config struct {
	Address         string
	Issuer          *url.URL
	ClientID        string
	ClientSecret    string
	PublicURL       *url.URL
	UpstreamURL     *url.URL
	PostLogoutURL   *url.URL
	DatabaseURL     string
	CookieSecret    string
	SessionMaxAge   time.Duration
	ReleaseRevision string
	InsecureCookie  bool
}

func FromEnvironment() (Config, error) {
	return Load(os.Getenv)
}

func Load(getenv func(string) string) (Config, error) {
	issuer, err := requiredURL(getenv, "OIDC_GATEWAY_ISSUER")
	if err != nil {
		return Config{}, err
	}
	publicURL, err := requiredURL(getenv, "OIDC_GATEWAY_PUBLIC_URL")
	if err != nil {
		return Config{}, err
	}
	upstreamURL, err := requiredURL(getenv, "OIDC_GATEWAY_UPSTREAM_URL")
	if err != nil {
		return Config{}, err
	}
	postLogoutURL, err := requiredURL(getenv, "OIDC_GATEWAY_POST_LOGOUT_URL")
	if err != nil {
		return Config{}, err
	}
	config := Config{
		Address:         strings.TrimSpace(getenv("OIDC_GATEWAY_LISTEN_ADDRESS")),
		Issuer:          issuer,
		ClientID:        strings.TrimSpace(getenv("OIDC_GATEWAY_CLIENT_ID")),
		ClientSecret:    getenv("OIDC_GATEWAY_CLIENT_SECRET"),
		PublicURL:       publicURL,
		UpstreamURL:     upstreamURL,
		PostLogoutURL:   postLogoutURL,
		DatabaseURL:     getenv("DATABASE_URL"),
		CookieSecret:    getenv("OIDC_GATEWAY_COOKIE_SECRET"),
		SessionMaxAge:   8 * time.Hour,
		ReleaseRevision: strings.TrimSpace(getenv("APPLICATION_RELEASE_REVISION")),
		InsecureCookie:  getenv("OIDC_GATEWAY_ALLOW_INSECURE_COOKIE") == "true",
	}
	if configured := strings.TrimSpace(getenv("OIDC_GATEWAY_SESSION_MAX_AGE")); configured != "" {
		config.SessionMaxAge, err = time.ParseDuration(configured)
		if err != nil || config.SessionMaxAge < 5*time.Minute || config.SessionMaxAge > 30*24*time.Hour {
			return Config{}, fmt.Errorf("OIDC_GATEWAY_SESSION_MAX_AGE must be a duration from 5m through 720h")
		}
	}
	if config.Address == "" {
		config.Address = ":4180"
	}
	for name, value := range map[string]string{
		"OIDC_GATEWAY_CLIENT_ID":       config.ClientID,
		"OIDC_GATEWAY_CLIENT_SECRET":   config.ClientSecret,
		"DATABASE_URL":                 config.DatabaseURL,
		"OIDC_GATEWAY_COOKIE_SECRET":   config.CookieSecret,
		"APPLICATION_RELEASE_REVISION": config.ReleaseRevision,
	} {
		if value == "" {
			return Config{}, fmt.Errorf("%s must be set", name)
		}
	}
	if len(config.ClientSecret) < 32 {
		return Config{}, fmt.Errorf("OIDC_GATEWAY_CLIENT_SECRET must contain at least 32 characters")
	}
	if len(config.CookieSecret) < 32 {
		return Config{}, fmt.Errorf("OIDC_GATEWAY_COOKIE_SECRET must contain at least 32 characters")
	}
	if !immutableApplicationRelease.MatchString(config.ReleaseRevision) {
		return Config{}, fmt.Errorf("APPLICATION_RELEASE_REVISION must identify an immutable deployed release")
	}
	if !config.InsecureCookie && (issuer.Scheme != "https" || publicURL.Scheme != "https" || postLogoutURL.Scheme != "https") {
		return Config{}, fmt.Errorf("OIDC gateway public coordinates must use HTTPS")
	}
	if config.InsecureCookie && (!isLoopbackURL(issuer) || !isLoopbackURL(publicURL) || !isLoopbackURL(postLogoutURL)) {
		return Config{}, fmt.Errorf("OIDC_GATEWAY_ALLOW_INSECURE_COOKIE is restricted to loopback URLs")
	}
	if postLogoutURL.Scheme != publicURL.Scheme || postLogoutURL.Host != publicURL.Host {
		return Config{}, fmt.Errorf("OIDC_GATEWAY_POST_LOGOUT_URL must use the public application origin")
	}
	if issuer.RawQuery != "" || publicURL.RawQuery != "" || (publicURL.Path != "" && publicURL.Path != "/") || upstreamURL.RawQuery != "" {
		return Config{}, fmt.Errorf("issuer, public, and upstream URLs must not contain unsupported paths or queries")
	}
	if upstreamURL.Scheme != "http" && upstreamURL.Scheme != "https" {
		return Config{}, fmt.Errorf("OIDC_GATEWAY_UPSTREAM_URL must use HTTP or HTTPS")
	}
	return config, nil
}

func isLoopbackURL(value *url.URL) bool {
	host := strings.Trim(strings.ToLower(value.Hostname()), "[]")
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || net.ParseIP(host).IsLoopback()
}

func requiredURL(getenv func(string) string, name string) (*url.URL, error) {
	value := strings.TrimSpace(getenv(name))
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s must be an absolute URL without credentials or a fragment", name)
	}
	return parsed, nil
}
