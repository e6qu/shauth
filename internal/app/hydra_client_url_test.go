// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"github.com/e6qu/shauth/internal/config"
	"net/url"
	"testing"
)

// A client registered directly in Hydra may carry any identifier; Shauth
// must address exactly that client, escaped once, and nothing else.
func TestHydraClientURLEscapesOnce(t *testing.T) {
	admin, _ := url.Parse("http://hydra:4445")
	s := &Server{config: config.Config{HydraAdminURL: admin}}
	for id, want := range map[string]string{"app-client": "http://hydra:4445/admin/clients/app-client/lifespans", "50%": "http://hydra:4445/admin/clients/50%25/lifespans", "a/../b": "http://hydra:4445/admin/clients/a%2F..%2Fb/lifespans", "é": "http://hydra:4445/admin/clients/%C3%A9/lifespans"} {
		if got := s.hydraClientURL(id, "/lifespans").String(); got != want {
			t.Errorf("%q => %s want %s", id, got, want)
		}
	}
}
