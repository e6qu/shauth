// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestEmbeddedHTMXAsset(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, htmxAssetPath, nil)
	response := httptest.NewRecorder()
	serveHTMX(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Content-Type"); got != "application/javascript; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := response.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("Cache-Control = %q", got)
	}
	digest := sha256.Sum256(response.Body.Bytes())
	if got := hex.EncodeToString(digest[:]); got != "ee971eb008b2ae65aea05b4b537b0acac3198e63767dc4f443a08164eb0ae98d" {
		t.Fatalf("SHA-256 = %q", got)
	}
}

func TestPageTemplatesUseOnlyLocalBrowserAssets(t *testing.T) {
	assetPattern := regexp.MustCompile(`(?i)<(?:script|link|img)\b[^>]*(?:src|href)="([^"]+)"`)
	matches := assetPattern.FindAllStringSubmatch(pageTemplates, -1)
	if len(matches) == 0 {
		t.Fatal("page templates did not contain browser assets")
	}
	for _, match := range matches {
		if !strings.HasPrefix(match[1], "/") || strings.HasPrefix(match[1], "//") {
			t.Errorf("browser asset is not local: %q", match[1])
		}
	}
	if !strings.Contains(pageTemplates, `src="`+htmxAssetPath+`" integrity="`+htmxAssetIntegrity+`"`) {
		t.Fatal("page templates did not use the integrity-pinned embedded HTMX asset")
	}
	externalScriptSource := regexp.MustCompile(`script-src[^;]*(?:https?:|//)`)
	if externalScriptSource.MatchString(baseContentSecurityPolicy) || externalScriptSource.MatchString(oidcContentSecurityPolicy) {
		t.Fatal("Shauth content security policy allows an external script source")
	}
}
