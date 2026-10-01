// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
)

// A failed upstream sign-in offers to start again towards where the person
// was going, with that destination carried as one escaped query value.
func TestErrorPageSignInAgainKeepsTheDestination(t *testing.T) {
	pages := template.Must(template.New("pages").Funcs(templateHelpers()).Parse(pageTemplates))
	var rendered bytes.Buffer
	data := map[string]any{"Status": 502, "StatusText": "Sign-in failed", "Message": "GitHub could not be reached.", "SignedIn": false, "IsAdmin": false,
		"SignInNext": "/oauth/login?login_challenge=abc&x=1"}
	if err := pages.ExecuteTemplate(&rendered, "error", data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered.String(), `href="/login?next=%2foauth%2flogin%3flogin_challenge%3dabc%26x%3d1"`) {
		t.Fatalf("sign-in-again link did not carry the escaped destination: %s", rendered.String())
	}
}

// A rejected registration shows its message beside the field it concerns,
// tied to that field for assistive technology, and nowhere else in the form.
func TestRegistrationFormsShowRejectionsBesideTheirField(t *testing.T) {
	pages := template.Must(template.New("pages").Funcs(templateHelpers()).Parse(pageTemplates))
	var rendered bytes.Buffer
	data := map[string]any{"SignedIn": true, "IsAdmin": true, "Error": "Redirect URI must use HTTPS.", "ErrorField": "redirect_uris", "Form": oidcClientInput{}}
	if err := pages.ExecuteTemplate(&rendered, "oidc-clients", data); err != nil {
		t.Fatal(err)
	}
	page := rendered.String()
	start := strings.Index(page, `name="redirect_uris"`)
	end := strings.Index(page[start:], ">")
	if start < 0 || !strings.Contains(page[start:start+end], `aria-describedby="redirect-help redirect-uris-error"`) || !strings.Contains(page[start:start+end], `aria-invalid="true"`) {
		t.Fatalf("the redirect URI field is not marked invalid: %s", page)
	}
	if !strings.Contains(page, `<span class="field-error" id="redirect-uris-error">Redirect URI must use HTTPS.</span>`) {
		t.Fatal("the rejection is not shown beside the redirect URI field")
	}
	if strings.Count(page, `aria-invalid="true"`) != 1 || strings.Count(page, `class="field-error"`) != 1 {
		t.Fatal("other fields were marked invalid")
	}
}
