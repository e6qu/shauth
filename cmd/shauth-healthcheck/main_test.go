// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "testing"

func TestHealthAddressFollowsTheListenAddress(t *testing.T) {
	for listen, want := range map[string]string{
		"":               "127.0.0.1:8080",
		":8080":          "127.0.0.1:8080",
		":9090":          "127.0.0.1:9090",
		"0.0.0.0:7000":   "127.0.0.1:7000",
		"[::]:7001":      "127.0.0.1:7001",
		"127.0.0.2:7002": "127.0.0.2:7002",
	} {
		if got := healthAddress(listen); got != want {
			t.Errorf("healthAddress(%q) = %q, want %q", listen, got, want)
		}
	}
}
