// SPDX-License-Identifier: AGPL-3.0-or-later

package managedapps

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/e6qu/shauth/internal/identity"
)

func TestHealthProbeReportsARedirectInsteadOfFollowingIt(t *testing.T) {
	followed := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed = true
	}))
	defer target.Close()
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer health.Close()

	status, err := New().Status(context.Background(), identity.ManagedApp{HealthURL: health.URL})
	if err != nil {
		t.Fatal(err)
	}
	if followed {
		t.Fatal("the health probe followed the redirect")
	}
	if status.Healthy || status.StatusCode != http.StatusFound {
		t.Fatalf("status = %#v, want an unhealthy 302", status)
	}
}
