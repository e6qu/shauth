// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/e6qu/shauth/internal/identity"
)

func TestBearerTokenMatchesRequiresExactlyOneBearerCredential(t *testing.T) {
	const token = "validation-status-token"
	request := httptest.NewRequest("GET", "/api/v1/apps/validations", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	if !bearerTokenMatches(request, token) {
		t.Fatal("exact bearer credential was rejected")
	}
	for name, values := range map[string][]string{
		"missing scheme": {token},
		"wrong scheme":   {"Basic " + token},
		"wrong token":    {"Bearer wrong"},
		"duplicate":      {"Bearer " + token, "Bearer " + token},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := httptest.NewRequest("GET", "/api/v1/apps/validations", nil)
			candidate.Header["Authorization"] = values
			if bearerTokenMatches(candidate, token) {
				t.Fatal("unsafe authorization header was accepted")
			}
		})
	}
}

func TestApplicationValidationComponentReportsBothDirections(t *testing.T) {
	pages, err := template.New("pages").Parse(pageTemplates)
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	duration := int64(1234)
	passed := identity.AppValidationRun{Status: identity.ValidationPassed, ReleaseRevision: "0123456789ab", DurationMilliseconds: &duration}
	failed := identity.AppValidationRun{Status: identity.ValidationFailed, ReleaseRevision: "0123456789ab", Failure: "logout returned to the identity service"}
	view := managedAppView{
		ManagedApp: identity.ManagedApp{ID: "00000000-0000-4000-8000-000000000001", Name: "Bleephub"},
		FromShauth: &passed,
		FromApp:    &failed,
	}
	var rendered bytes.Buffer
	if err := pages.ExecuteTemplate(&rendered, "app-validation", view); err != nil {
		t.Fatalf("render validation component: %v", err)
	}
	for _, expected := range []string{"🟢 Passed", "🔴 Failed", "From Shauth", "From app", "Run both checks again", "logout returned to the identity service"} {
		if !strings.Contains(rendered.String(), expected) {
			t.Fatalf("validation component omitted %q: %s", expected, rendered.String())
		}
	}
	if strings.Contains(rendered.String(), "hx-trigger") {
		t.Fatal("terminal validation component kept polling")
	}
	if strings.Contains(rendered.String(), `aria-busy="true"`) {
		t.Fatal("terminal validation component remained busy")
	}
}

func TestApplicationValidationComponentPollsOnlyOngoingRuns(t *testing.T) {
	pages, err := template.New("pages").Parse(pageTemplates)
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	view := managedAppView{
		ManagedApp: identity.ManagedApp{ID: "00000000-0000-4000-8000-000000000001", Name: "Bleephub"},
		NeedsPoll:  true,
	}
	var rendered bytes.Buffer
	if err := pages.ExecuteTemplate(&rendered, "app-validation", view); err != nil {
		t.Fatalf("render validation component: %v", err)
	}
	for _, expected := range []string{"🟡 Ongoing", `hx-trigger="every 5s"`, `aria-label="Bleephub sign-in and sign-out validation"`, `aria-live="polite"`, `aria-busy="true"`} {
		if !strings.Contains(rendered.String(), expected) {
			t.Fatalf("ongoing validation component omitted %q: %s", expected, rendered.String())
		}
	}
	var results bytes.Buffer
	if err := pages.ExecuteTemplate(&results, "app-validation-results", view); err != nil {
		t.Fatalf("render validation results: %v", err)
	}
	if strings.Contains(results.String(), "<form") || strings.Contains(results.String(), "<button") {
		t.Fatalf("polled validation region replaced interactive controls: %s", results.String())
	}
}

func TestValidationNeedsPoll(t *testing.T) {
	for name, run := range map[string]*identity.AppValidationRun{
		"never run": nil,
		"queued":    {Status: identity.ValidationQueued},
		"running":   {Status: identity.ValidationRunning},
	} {
		t.Run(name, func(t *testing.T) {
			if !validationNeedsPoll(run) {
				t.Fatal("ongoing validation did not poll")
			}
		})
	}
	for name, status := range map[string]string{"passed": identity.ValidationPassed, "failed": identity.ValidationFailed} {
		t.Run(name, func(t *testing.T) {
			if validationNeedsPoll(&identity.AppValidationRun{Status: status}) {
				t.Fatal("terminal validation kept polling")
			}
		})
	}
}

func TestDecodeValidatorResultRequiresExactlyOneJSONValue(t *testing.T) {
	var result validatorResult
	if err := decodeValidatorResult(strings.NewReader(`{"status":"passed","failure":""}`), &result); err != nil {
		t.Fatalf("valid validator result rejected: %v", err)
	}
	if result.Status != "passed" {
		t.Fatalf("validator result status = %q", result.Status)
	}
	for name, payload := range map[string]string{
		"trailing value": `{"status":"passed","failure":""} {}`,
		"trailing token": `{"status":"passed","failure":""} garbage`,
		"unknown field":  `{"status":"passed","failure":"","secret":"leak"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var candidate validatorResult
			if err := decodeValidatorResult(strings.NewReader(payload), &candidate); err == nil {
				t.Fatal("invalid validator result was accepted")
			}
		})
	}
}

func TestStrictRelativeNext(t *testing.T) {
	for _, value := range []string{"/", "/apps", "/oauth/login?login_challenge=opaque"} {
		if !strictRelativeNext(value) {
			t.Errorf("strictRelativeNext(%q) = false", value)
		}
	}
	for _, value := range []string{"", "apps", "https://attacker.example/", "//attacker.example/", `/\\attacker.example`, "/apps#fragment", "/apps\n"} {
		if strictRelativeNext(value) {
			t.Errorf("strictRelativeNext(%q) = true", value)
		}
	}
}
