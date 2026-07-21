// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestValidateJobPinsCredentialEntryToConfiguredShauthOrigin(t *testing.T) {
	valid := job{
		ID: "run-id", ManagedAppID: "bleephub-id", AppSlug: "bleephub", AppName: "Bleephub", OIDCClientID: "bleephub",
		LaunchURL: "https://bleephub.example.test/", ValidationURL: "https://bleephub.example.test/auth/validation",
		SignedOutURL: "https://bleephub.example.test/ui/signed-out", Direction: "from_app",
		ReleaseRevision: "0123456789ab", ShauthURL: "https://auth.example.test",
		Witness: &witness{ManagedAppID: "sharecrop-id", AppSlug: "sharecrop", AppName: "Sharecrop", OIDCClientID: "sharecrop", LaunchURL: "https://sharecrop.example.test/", ValidationURL: "https://sharecrop.example.test/me", SignedOutURL: "https://sharecrop.example.test/signed-out", ReleaseRevision: "abcdef012345"},
	}
	if err := validateJob("https://auth.example.test", valid); err != nil {
		t.Fatalf("valid job rejected: %v", err)
	}

	for name, mutate := range map[string]func(*job){
		"different Shauth origin":     func(value *job) { value.ShauthURL = "https://attacker.example.test" },
		"Shauth URL credentials":      func(value *job) { value.ShauthURL = "https://user:secret@auth.example.test" },
		"Shauth URL query":            func(value *job) { value.ShauthURL = "https://auth.example.test?next=attacker" },
		"insecure Shauth URL":         func(value *job) { value.ShauthURL = "http://auth.example.test" },
		"different validation origin": func(value *job) { value.ValidationURL = "https://attacker.example.test/auth/validation" },
		"different signed-out origin": func(value *job) { value.SignedOutURL = "https://attacker.example.test/signed-out" },
		"insecure external app": func(value *job) {
			value.LaunchURL = "http://bleephub.example.test/"
			value.ValidationURL = "http://bleephub.example.test/auth/validation"
			value.SignedOutURL = "http://bleephub.example.test/ui/signed-out"
		},
		"credentials in URL":       func(value *job) { value.LaunchURL = "https://user:secret@bleephub.example.test/" },
		"fragment":                 func(value *job) { value.SignedOutURL += "#credential-form" },
		"mutable app revision":     func(value *job) { value.ReleaseRevision = "main" },
		"mutable witness revision": func(value *job) { value.Witness.ReleaseRevision = "latest" },
		"unknown direction":        func(value *job) { value.Direction = "outside" },
		"missing witness":          func(value *job) { value.Witness = nil },
		"same witness app":         func(value *job) { value.Witness.ManagedAppID = value.ManagedAppID },
		"same witness client":      func(value *job) { value.Witness.OIDCClientID = value.OIDCClientID },
		"same witness origin": func(value *job) {
			value.Witness.LaunchURL = "https://bleephub.example.test/witness"
			value.Witness.ValidationURL = "https://bleephub.example.test/witness/me"
			value.Witness.SignedOutURL = "https://bleephub.example.test/witness/signed-out"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			witnessCopy := *valid.Witness
			candidate.Witness = &witnessCopy
			mutate(&candidate)
			if err := validateJob("https://auth.example.test", candidate); err == nil {
				t.Fatal("invalid job was accepted")
			}
		})
	}
}

func TestValidateJobAllowsLoopbackHTTP(t *testing.T) {
	value := job{
		ID: "run-id", ManagedAppID: "local-app-id", AppSlug: "local-app", AppName: "Local app", OIDCClientID: "local-app",
		LaunchURL: "http://local-app.localhost:5556/", ValidationURL: "http://local-app.localhost:5556/me",
		SignedOutURL: "http://local-app.localhost:5556/auth/signed-out", Direction: "from_shauth",
		ReleaseRevision: "0123456789ab", ShauthURL: "http://localhost:8080",
		Witness: &witness{ManagedAppID: "local-peer-id", AppSlug: "local-peer", AppName: "Local peer", OIDCClientID: "local-peer", LaunchURL: "http://local-peer.localhost:5558/", ValidationURL: "http://local-peer.localhost:5558/me", SignedOutURL: "http://local-peer.localhost:5558/auth/signed-out", ReleaseRevision: "abcdef012345"},
	}
	if err := validateJob("http://localhost:8080", value); err != nil {
		t.Fatalf("loopback validation job rejected: %v", err)
	}
}

func TestSanitizeFailureRemovesSecretsAndOAuthArtifacts(t *testing.T) {
	t.Setenv("SHAUTH_VALIDATION_USERNAME", "shauth-validator")
	t.Setenv("SHAUTH_VALIDATOR_TOKEN", "validator-token-value")
	bootstrapToken := strings.Repeat("b", 64)
	encodedBootstrap := base64.RawURLEncoding.EncodeToString([]byte(url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(bootstrapToken)))))
	encodedToken := url.QueryEscape(url.QueryEscape("validator-token-value"))
	failure := sanitizeJobFailure("shauth-validator validator-token-value "+bootstrapToken+" "+encodedBootstrap+" "+encodedToken+" https://auth.example.test/callback?code=oauth-code&state=oauth-state&id_token_hint=id-token&refresh_token=refresh-token&logout_verifier=logout-verifier", job{
		BootstrapURLs: []string{"https://auth.example.test/validator/bootstrap#" + bootstrapToken},
	})
	for _, forbidden := range []string{"shauth-validator", "validator-token-value", bootstrapToken, encodedBootstrap, encodedToken, "oauth-code", "oauth-state", "id-token", "refresh-token", "logout-verifier"} {
		if strings.Contains(failure, forbidden) {
			t.Fatalf("sanitized failure retained %q: %s", forbidden, failure)
		}
	}
	if !strings.Contains(failure, "[redacted]") {
		t.Fatalf("sanitized failure did not identify redaction: %s", failure)
	}
}

func TestValidateBootstrapURLsPinsTokensToShauth(t *testing.T) {
	first := strings.Repeat("a", 64)
	second := strings.Repeat("b", 64)
	valid := []string{
		"https://auth.example.test/validator/bootstrap#" + first,
		"https://auth.example.test/validator/bootstrap#" + second,
	}
	if err := validateBootstrapURLs("https://auth.example.test", valid); err != nil {
		t.Fatalf("valid browser bootstrap URLs rejected: %v", err)
	}
	for name, candidate := range map[string][]string{
		"wrong count":        valid[:1],
		"wrong origin":       {valid[0], "https://attacker.example.test/validator/bootstrap#" + second},
		"wrong path":         {valid[0], "https://auth.example.test/login#" + second},
		"query":              {valid[0], "https://auth.example.test/validator/bootstrap?token=no#" + second},
		"credentials":        {valid[0], "https://user:secret@auth.example.test/validator/bootstrap#" + second},
		"invalid fragment":   {valid[0], "https://auth.example.test/validator/bootstrap#short"},
		"duplicate fragment": {valid[0], valid[0]},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateBootstrapURLs("https://auth.example.test", candidate); err == nil {
				t.Fatal("unsafe browser bootstrap URLs were accepted")
			}
		})
	}
}

func TestDecodeSingleJSONRejectsTrailingData(t *testing.T) {
	for name, payload := range map[string]string{
		"trailing value": `{"status":"passed","failure":""} {}`,
		"trailing token": `{"status":"passed","failure":""} garbage`,
		"unknown field":  `{"status":"passed","failure":"","secret":"leak"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var outcome result
			if err := decodeSingleJSON(strings.NewReader(payload), &outcome); err == nil {
				t.Fatal("invalid JSON payload was accepted")
			}
		})
	}
	var outcome result
	if err := decodeSingleJSON(strings.NewReader(`{"status":"passed","failure":""}`), &outcome); err != nil {
		t.Fatalf("valid JSON payload rejected: %v", err)
	}
}
