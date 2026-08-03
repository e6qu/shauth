// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/e6qu/shauth/internal/identity"
	"github.com/e6qu/shauth/internal/version"
)

func parsePages(t *testing.T) *template.Template {
	t.Helper()
	pages, err := template.New("pages").Funcs(templateHelpers()).Parse(pageTemplates)
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	return pages
}

// Every browser form must carry its CSRF token from the server. Injecting it
// in the browser makes sign-in, invitation acceptance, logout and every
// administrative action depend on JavaScript having run.
func TestEveryPostFormCarriesAServerRenderedCSRFToken(t *testing.T) {
	forms := regexp.MustCompile(`(?s)<form[^>]*method="post"[^>]*>.{0,220}`)
	found := 0
	for _, form := range forms.FindAllString(pageTemplates, -1) {
		found++
		if !strings.Contains(form, `name="_csrf"`) {
			t.Errorf("a POST form does not carry a CSRF token: %s", form[:min(len(form), 160)])
		}
	}
	if found == 0 {
		t.Fatal("no POST forms were found to check")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// A destructive action must ask before it runs.
func TestDestructiveControlsAskForConfirmation(t *testing.T) {
	for _, action := range []string{
		"/admin/users/{{.UserID}}/sessions/revoke",
		"/admin/users/{{.UserID}}/disable",
		"/admin/sessions/{{.ID}}/revoke",
		"/admin/invitations/{{.ID}}/revoke",
		"/admin/apps/{{.ID}}/delete",
		"/admin/clients/{{.ID}}/delete",
		"/admin/github/{{.ID}}/delete",
	} {
		index := strings.Index(pageTemplates, `action="`+action+`"`)
		if index < 0 {
			t.Errorf("no form posts to %s", action)
			continue
		}
		form := pageTemplates[index:min(index+260, len(pageTemplates))]
		if !strings.Contains(form, "data-confirm=") {
			t.Errorf("the form posting to %s runs without confirmation: %s", action, form[:min(len(form), 160)])
		}
	}
}

// A page title identifies the page in history, in the tab strip, and to a
// screen reader. One shared title for every page identifies none of them.
func TestPagesRenderTheirOwnTitle(t *testing.T) {
	pages := parsePages(t)
	var rendered strings.Builder
	if err := pages.ExecuteTemplate(&rendered, "error", map[string]any{
		"Title": "Not found", "Status": http.StatusNotFound, "StatusText": "Not Found", "Message": "That page does not exist.",
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered.String(), "<title>Not found · Shauth</title>") {
		t.Fatalf("page did not render its own title: %s", rendered.String()[:min(400, rendered.Len())])
	}
	if !strings.Contains(rendered.String(), `href="/favicon.svg"`) {
		t.Fatal("page did not reference the favicon")
	}
}

// Timestamps are read by people. Rendering a time.Time directly prints Go
// debug syntax with microseconds and a type suffix.
func TestTimestampsRenderAsReadableText(t *testing.T) {
	helpers := templateHelpers()
	moment := helpers["moment"].(func(any) string)
	iso := helpers["iso"].(func(any) string)
	value := time.Date(2026, 7, 20, 12, 30, 0, 0, time.UTC)
	if got := moment(value); got != "20 Jul 2026 12:30 UTC" {
		t.Fatalf("moment = %q", got)
	}
	if got := iso(value); got != "2026-07-20T12:30:00Z" {
		t.Fatalf("iso = %q", got)
	}
	if got := moment(time.Time{}); got != "unknown" {
		t.Fatalf("zero time = %q, want a word rather than a zero date", got)
	}
	// A page that omits a timestamp must still render.
	if got := moment(nil); got != "unknown" {
		t.Fatalf("missing time = %q, want a word rather than a render failure", got)
	}
	if strings.Contains(moment(value), "+0000") || strings.Contains(moment(value), "m=") {
		t.Fatal("moment leaked Go time formatting")
	}
}

func TestIdentityLabelDescribesEverySource(t *testing.T) {
	label := templateHelpers()["identityLabel"].(func(string, string) string)
	for source, want := range map[string]string{
		identity.IdentitySourceLocal:  "Local account",
		identity.IdentitySourceGitHub: "GitHub: octocat",
		identity.IdentitySourceEntra:  "Microsoft Entra ID",
	} {
		if got := label(source, "octocat"); got != want {
			t.Fatalf("identityLabel(%q) = %q, want %q", source, got, want)
		}
	}
}

// The stylesheet must not contain declarations browsers discard, and must not
// pin a foreground colour that stops adapting when the theme inverts.
func TestStylesheetHasNoDiscardedOrPinnedDeclarations(t *testing.T) {
	malformed := regexp.MustCompile(`margin:\s*0\s+0:`)
	if location := malformed.FindString(pageTemplates); location != "" {
		t.Fatalf("stylesheet contains a malformed declaration browsers discard: %q", location)
	}
	for _, pinned := range []string{"color:#fff;font-weight:800", ".button-danger:hover{background:#951238}"} {
		if strings.Contains(pageTemplates, pinned) {
			t.Fatalf("a control pins a foreground colour that cannot adapt to dark mode: %q", pinned)
		}
	}
	for _, token := range []string{"--on-brand", "--on-danger", "--danger-strong"} {
		if strings.Count(pageTemplates, token) < 2 {
			t.Fatalf("token %s is not defined for both themes", token)
		}
	}
}

// A failure on a browser path renders a navigable page, not bare text.
func TestFailPageRendersNavigableErrorPage(t *testing.T) {
	server := &Server{templates: parsePages(t)}
	request := httptest.NewRequest(http.MethodGet, "/nope", nil)
	response := httptest.NewRecorder()
	server.failPage(response, request, http.StatusNotFound, "That page does not exist.")

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
	body := response.Body.String()
	for _, expected := range []string{"That page does not exist.", `id="main-content"`, `aria-label="Primary navigation"`, `href="/"`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("error page omitted %q", expected)
		}
	}
}

// Unrouted paths answer in the shape their caller parses.
func TestNotFoundAnswersJSONForMachineNamespaces(t *testing.T) {
	server := &Server{templates: parsePages(t)}
	for path, wantJSON := range map[string]bool{
		"/api/v1/nope":   true,
		"/internal/nope": true,
		"/nope":          false,
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		server.notFound(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d", path, response.Code)
		}
		isJSON := strings.Contains(response.Header().Get("Content-Type"), "application/json")
		if isJSON != wantJSON {
			t.Fatalf("%s content type = %q, want JSON = %t", path, response.Header().Get("Content-Type"), wantJSON)
		}
	}
}

// The self-disable guard is a security rule, so it must hold for every
// transport rather than only the browser that happens to know the actor.
func TestDisableUserRefusesTheActingAdministrator(t *testing.T) {
	server := &Server{}
	const id = "5f61a1a1-27b6-4e8c-9e3f-1f2e3d4c5b6a"
	if _, err := server.disableUser(t.Context(), id, actor{UserID: id}); err == nil {
		t.Fatal("an administrator disabled the account they are signed in with")
	}
	status, message := describeOperationFailure("disable account", errSelfDisable)
	if status != http.StatusConflict || !strings.Contains(message, "signed in with") {
		t.Fatalf("self-disable = %d %q", status, message)
	}
}

// Both transports classify one cause identically, which is the property that
// keeps the browser interface and the API from drifting apart.
func TestOperationFailuresClassifyIdenticallyForBothTransports(t *testing.T) {
	for name, expectation := range map[string]struct {
		err    error
		status int
	}{
		"rejection":  {identity.Invalid("slug is required"), http.StatusBadRequest},
		"duplicate":  {identity.ErrAlreadyExists, http.StatusConflict},
		"missing":    {identity.ErrUserNotFound, http.StatusNotFound},
		"conflict":   {errOIDCClientInUse, http.StatusConflict},
		"dependency": {dependencyFailure("the provider did not answer", nil), http.StatusBadGateway},
	} {
		t.Run(name, func(t *testing.T) {
			status, message := describeOperationFailure("act", expectation.err)
			if status != expectation.status {
				t.Fatalf("status = %d, want %d", status, expectation.status)
			}
			if message == "" {
				t.Fatal("failure carried no message")
			}
			if strings.Contains(message, "SQLSTATE") || strings.Contains(message, "pgx") {
				t.Fatalf("failure leaked internal detail: %q", message)
			}
		})
	}
}

// Every page must say which build produced it, so an operator reading any
// screen can tell exactly which revision is serving them.
func TestEveryPageCarriesTheBuildNotice(t *testing.T) {
	if !strings.Contains(pageTemplates, `class="build-notice"`) {
		t.Fatal("the shared footer does not carry a build notice")
	}
	for _, expected := range []string{"{{.Revision}}", "{{iso .StartedAt}}", "{{moment .StartedAt}}"} {
		if !strings.Contains(pageTemplates, expected) {
			t.Fatalf("the build notice omits %s", expected)
		}
	}
	// The notice lives in the shared footer, so every page that renders the
	// footer reports it.
	footers := strings.Count(pageTemplates, `{{template "footer" .}}`)
	if footers < 12 {
		t.Fatalf("only %d pages render the shared footer", footers)
	}
}

// A stacked table row on a narrow screen keeps the column heading that gives
// each value its meaning.
func TestTableCellsCarryTheirColumnLabel(t *testing.T) {
	// Scanned across the whole template source rather than only inside
	// <table> blocks: a row template such as "user-row" is defined apart
	// from the table that renders it, and its cells were missed that way.
	for _, cell := range regexp.MustCompile(`<td(?: [^>]*)?>`).FindAllString(pageTemplates, -1) {
		if strings.Contains(cell, "colspan") {
			continue
		}
		if !strings.Contains(cell, "data-label=") {
			t.Errorf("a table cell has no column label for narrow screens: %s", cell)
		}
	}
	// Narrow screens must stack rather than force a minimum table width.
	if !strings.Contains(pageTemplates, "@media(max-width:60rem){.table-wrap") {
		t.Fatal("tables do not stack on narrow screens")
	}
	if strings.Contains(pageTemplates, ".table-wrap table{min-width:36rem}") {
		t.Fatal("a forced table minimum width can push a narrow page wider than its viewport")
	}
}

func TestVersionReportsAShortRevisionAndStartTime(t *testing.T) {
	if version.Short() == "" {
		t.Fatal("no revision is reported")
	}
	if len(version.Short()) > 12 {
		t.Fatalf("short revision %q is longer than the display form used elsewhere", version.Short())
	}
	if version.StartedAt().IsZero() || version.StartedAt().Location() != time.UTC {
		t.Fatalf("start time = %v, want a UTC instant", version.StartedAt())
	}
}

// Shauth is reached through a gateway, so the peer address is the gateway.
// The address recorded against a session must be the person's, and must not
// be choosable by a caller that reaches the service directly.
func TestClientIPResolvesThroughATrustedProxyOnly(t *testing.T) {
	request := func(remote, forwarded string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if forwarded != "" {
			r.Header.Set("X-Forwarded-For", forwarded)
		}
		return r
	}
	for name, expectation := range map[string]struct {
		remote, forwarded, want string
	}{
		"private peer uses the nearest forwarded entry": {"10.0.1.5:44321", "203.0.113.9", "203.0.113.9"},
		"spoofed leftmost entry is ignored":             {"10.0.1.5:44321", "198.51.100.7, 203.0.113.9", "203.0.113.9"},
		"private peer without a header stays the peer":  {"10.0.1.5:44321", "", "10.0.1.5"},
		"public peer ignores a forwarded header":        {"203.0.113.4:44321", "198.51.100.7", "203.0.113.4"},
		"garbage forwarded entry falls back":            {"10.0.1.5:44321", "not-an-address", "10.0.1.5"},
	} {
		t.Run(name, func(t *testing.T) {
			got := clientIP(request(expectation.remote, expectation.forwarded))
			if got == nil || got.String() != expectation.want {
				t.Fatalf("clientIP = %v, want %s", got, expectation.want)
			}
		})
	}
}

// TestIconsAreDecorativeAndInheritColour locks the two properties that make a
// shared icon set safe to use anywhere: it is never announced twice beside
// the text it accompanies, and it takes the colour of whatever it sits in.
func TestIconsAreDecorativeAndInheritColour(t *testing.T) {
	t.Parallel()
	icons := regexp.MustCompile(`\{\{define "(icon-[a-z]+)"\}\}(.*?)\{\{end\}\}`)
	matches := icons.FindAllStringSubmatch(pageTemplates, -1)
	if len(matches) < 10 {
		t.Fatalf("found %d icons, want the whole set", len(matches))
	}
	for _, match := range matches {
		name, markup := match[1], match[2]
		if !strings.Contains(markup, `aria-hidden="true"`) {
			t.Errorf("%s is announced to a screen reader beside the text it decorates", name)
		}
		if !strings.Contains(markup, `focusable="false"`) {
			t.Errorf("%s is reachable by keyboard, which stops on a decoration", name)
		}
		if !strings.Contains(markup, "viewBox=") {
			t.Errorf("%s has no viewBox, so it cannot scale with its text", name)
		}
		switch name {
		// The Microsoft mark may not be recoloured, and the brand mark
		// carries its own gradient; every other icon takes its colour
		// from the button, link, or chip it sits in.
		case "icon-microsoft", "icon-brand":
		default:
			if !strings.Contains(markup, "currentColor") {
				t.Errorf("%s does not inherit currentColor", name)
			}
			if strings.Contains(markup, "#") {
				t.Errorf("%s hardcodes a colour: %s", name, markup)
			}
		}
	}
}

// TestSignInOffersEachProvidersOwnMark is the request this set exists for: a
// person recognises "Continue with GitHub" by the Octocat, not by a lozenge.
func TestSignInOffersEachProvidersOwnMark(t *testing.T) {
	t.Parallel()
	pages, err := template.New("pages").Funcs(templateHelpers()).Parse(pageTemplates)
	if err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	if err := pages.ExecuteTemplate(&rendered, "login", map[string]any{
		"Title": "Sign in", "EntraEnabled": true, "Next": "/", "Revision": "abc", "StartedAt": time.Now(),
	}); err != nil {
		t.Fatalf("render the sign-in page: %v", err)
	}
	page := rendered.String()
	// The Octocat's own path data, so a placeholder cannot pass for it.
	if !strings.Contains(page, "M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59") {
		t.Fatal("the GitHub button does not carry the GitHub mark")
	}
	for _, colour := range []string{"#f25022", "#7fba00", "#00a4ef", "#ffb900"} {
		if !strings.Contains(page, colour) {
			t.Fatalf("the Microsoft button is missing %s of its four brand colours", colour)
		}
	}
	for _, glyph := range []string{"◆", "◇"} {
		if strings.Contains(page, glyph) {
			t.Fatalf("the sign-in page still shows the %q placeholder", glyph)
		}
	}
}
