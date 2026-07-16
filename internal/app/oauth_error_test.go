// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHydraErrorUsesBrandedSafeResponse(t *testing.T) {
	templates, err := template.New("pages").Parse(pageTemplates)
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	server := &Server{templates: templates}
	request := httptest.NewRequest(http.MethodGet, "/oauth/error?error=invalid_client&error_description=private+details", http.NoBody)
	recorder := httptest.NewRecorder()

	server.hydraError(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "We couldn’t complete that sign-in") || !strings.Contains(body, "invalid_client") {
		t.Fatalf("branded OAuth error page missing expected content: %s", body)
	}
	if strings.Contains(body, "private details") {
		t.Fatalf("OAuth error page leaked provider description: %s", body)
	}
}
