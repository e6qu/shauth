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
