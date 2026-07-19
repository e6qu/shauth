// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"fmt"
	"time"
)

// SessionPolicy is the durable security policy shared by Shauth browser
// sessions and the OpenID Connect clients managed through Ory Hydra.
type SessionPolicy struct {
	BrowserAbsoluteLifetime time.Duration
	BrowserIdleTimeout      time.Duration
	OIDCSessionLifetime     time.Duration
	AccessTokenLifetime     time.Duration
	IDTokenLifetime         time.Duration
	RefreshTokenLifetime    time.Duration
}

func DefaultSessionPolicy() SessionPolicy {
	return SessionPolicy{
		BrowserAbsoluteLifetime: 30 * 24 * time.Hour,
		BrowserIdleTimeout:      12 * time.Hour,
		OIDCSessionLifetime:     30 * 24 * time.Hour,
		AccessTokenLifetime:     15 * time.Minute,
		IDTokenLifetime:         15 * time.Minute,
		RefreshTokenLifetime:    30 * 24 * time.Hour,
	}
}

func (policy SessionPolicy) Validate() error {
	if policy.BrowserAbsoluteLifetime < 5*time.Minute || policy.BrowserAbsoluteLifetime > 90*24*time.Hour {
		return fmt.Errorf("browser absolute lifetime must be between 5 minutes and 90 days")
	}
	if policy.BrowserIdleTimeout < 5*time.Minute || policy.BrowserIdleTimeout > policy.BrowserAbsoluteLifetime {
		return fmt.Errorf("browser idle timeout must be between 5 minutes and the absolute lifetime")
	}
	if policy.OIDCSessionLifetime < 5*time.Minute || policy.OIDCSessionLifetime > policy.BrowserAbsoluteLifetime {
		return fmt.Errorf("OpenID Connect SSO lifetime must be between 5 minutes and the browser absolute lifetime")
	}
	if policy.AccessTokenLifetime < 5*time.Minute || policy.AccessTokenLifetime > 24*time.Hour {
		return fmt.Errorf("access token lifetime must be between 5 minutes and 24 hours")
	}
	if policy.IDTokenLifetime < 5*time.Minute || policy.IDTokenLifetime > 24*time.Hour {
		return fmt.Errorf("ID token lifetime must be between 5 minutes and 24 hours")
	}
	if policy.RefreshTokenLifetime < policy.AccessTokenLifetime || policy.RefreshTokenLifetime < policy.IDTokenLifetime || policy.RefreshTokenLifetime > 90*24*time.Hour {
		return fmt.Errorf("refresh token lifetime must cover access and ID tokens and must not exceed 90 days")
	}
	return nil
}
