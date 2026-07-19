// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/e6qu/shauth/internal/identity"
)

func TestParseSessionPolicyForm(t *testing.T) {
	policy, err := parseSessionPolicyForm(url.Values{
		"browser_absolute_hours": {"168"},
		"browser_idle_minutes":   {"60"},
		"oidc_sso_hours":         {"24"},
		"access_token_minutes":   {"10"},
		"id_token_minutes":       {"10"},
		"refresh_token_hours":    {"48"},
	})
	if err != nil {
		t.Fatalf("parseSessionPolicyForm() error = %v", err)
	}
	if policy.BrowserAbsoluteLifetime != 7*24*time.Hour || policy.BrowserIdleTimeout != time.Hour || policy.OIDCSessionLifetime != 24*time.Hour {
		t.Fatalf("browser and SSO policy = %#v", policy)
	}
	if policy.AccessTokenLifetime != 10*time.Minute || policy.IDTokenLifetime != 10*time.Minute || policy.RefreshTokenLifetime != 48*time.Hour {
		t.Fatalf("token policy = %#v", policy)
	}
}

func TestParseSessionPolicyFormRejectsDurationOverflow(t *testing.T) {
	_, err := parseSessionPolicyForm(url.Values{"browser_absolute_hours": {strconv.FormatInt(math.MaxInt64, 10)}})
	if err == nil {
		t.Fatal("parseSessionPolicyForm accepted a duration that overflows time.Duration")
	}
}

func TestNextHydraPageToken(t *testing.T) {
	header := `<http://hydra:4445/admin/clients?page_size=1000>; rel="first", <http://hydra:4445/admin/clients?page_size=1000&page_token=client-1000>; rel="next"`
	token, err := nextHydraPageToken(header)
	if err != nil {
		t.Fatal(err)
	}
	if token != "client-1000" {
		t.Fatalf("next page token = %q", token)
	}
}

func TestListHydraClientsReadsEveryPage(t *testing.T) {
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.Query().Get("page_size") != "1000" {
			t.Fatalf("page_size = %q", request.URL.Query().Get("page_size"))
		}
		header := make(http.Header)
		body := `[{"client_id":"first"}]`
		if requests == 1 {
			header.Set("Link", `</admin/clients?page_size=1000&page_token=second>; rel="next"`)
		} else {
			if token := request.URL.Query().Get("page_token"); token != "second" {
				t.Fatalf("page_token = %q", token)
			}
			body = `[{"client_id":"second"}]`
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})}
	adminURL, err := url.Parse("http://hydra.test")
	if err != nil {
		t.Fatal(err)
	}
	clients, err := listHydraClients[oidcClient](context.Background(), client, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 2 || clients[0].ID != "first" || clients[1].ID != "second" {
		t.Fatalf("clients = %#v", clients)
	}
}

func TestHydraClientLifespansChangesRealTokenLifespans(t *testing.T) {
	body, err := json.Marshal(hydraClientLifespans(identity.DefaultSessionPolicy()))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result["authorization_code_grant_access_token_lifespan"] != "15m0s" || result["authorization_code_grant_refresh_token_lifespan"] != "720h0m0s" {
		t.Fatalf("Hydra lifespans = %#v", result)
	}
}
