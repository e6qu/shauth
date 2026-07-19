// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"testing"
	"time"
)

func TestDefaultSessionPolicyIsValid(t *testing.T) {
	if err := DefaultSessionPolicy().Validate(); err != nil {
		t.Fatalf("DefaultSessionPolicy().Validate() error = %v", err)
	}
}

func TestSessionPolicyRejectsInconsistentLimits(t *testing.T) {
	valid := DefaultSessionPolicy()
	for name, mutate := range map[string]func(*SessionPolicy){
		"idle exceeds absolute":       func(policy *SessionPolicy) { policy.BrowserIdleTimeout = policy.BrowserAbsoluteLifetime + time.Minute },
		"OIDC SSO exceeds browser":    func(policy *SessionPolicy) { policy.OIDCSessionLifetime = policy.BrowserAbsoluteLifetime + time.Minute },
		"refresh shorter than access": func(policy *SessionPolicy) { policy.RefreshTokenLifetime = policy.AccessTokenLifetime - time.Minute },
		"access too short":            func(policy *SessionPolicy) { policy.AccessTokenLifetime = time.Minute },
	} {
		t.Run(name, func(t *testing.T) {
			policy := valid
			mutate(&policy)
			if err := policy.Validate(); err == nil {
				t.Fatal("Validate() accepted an inconsistent session policy")
			}
		})
	}
}
