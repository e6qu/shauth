// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A form's outcome reaches the next page through a server-set cookie bound to
// that page, and is shown exactly once. Nothing in a URL can produce one.
func TestNoticeIsShownOnceOnItsOwnPageAndNeverFromTheURL(t *testing.T) {
	server := &Server{}
	echo := server.notices(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(noticeDone(r) + "|" + noticeError(r)))
	}))

	redirect := httptest.NewRecorder()
	server.redirectWithNotice(redirect, httptest.NewRequest(http.MethodPost, "/admin/users", nil), "/admin/sessions?state=active", false, "The session was ended.")
	if redirect.Code != http.StatusSeeOther || redirect.Header().Get("Location") != "/admin/sessions?state=active" {
		t.Fatalf("redirect = %d %q", redirect.Code, redirect.Header().Get("Location"))
	}
	cookies := redirect.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly {
		t.Fatalf("notice cookie = %#v, want one HttpOnly cookie", cookies)
	}

	elsewhere := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	elsewhere.AddCookie(cookies[0])
	response := httptest.NewRecorder()
	echo.ServeHTTP(response, elsewhere)
	if response.Body.String() != "|" || len(response.Result().Cookies()) != 0 {
		t.Fatalf("another page consumed the notice: %q", response.Body.String())
	}

	arrival := httptest.NewRequest(http.MethodGet, "/admin/sessions?state=active", nil)
	arrival.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	echo.ServeHTTP(response, arrival)
	if response.Body.String() != "The session was ended.|" {
		t.Fatalf("destination body = %q", response.Body.String())
	}
	if expired := response.Result().Cookies(); len(expired) != 1 || expired[0].MaxAge >= 0 {
		t.Fatalf("the notice was not expired after it was shown: %#v", expired)
	}

	crafted := httptest.NewRequest(http.MethodGet, "/login?error=Call+this+number&done=Verified", nil)
	response = httptest.NewRecorder()
	echo.ServeHTTP(response, crafted)
	if response.Body.String() != "|" {
		t.Fatalf("a crafted URL produced a notice: %q", response.Body.String())
	}
}
