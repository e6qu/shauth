// SPDX-License-Identifier: AGPL-3.0-or-later

// shauth-healthcheck verifies the task-local Shauth readiness endpoint for
// Amazon Elastic Container Service container health checks.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+healthAddress(os.Getenv("SHAUTH_LISTEN_ADDRESS"))+"/healthz", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Shauth health endpoint returned %s\n", response.Status)
		os.Exit(1)
	}
}

// healthAddress reaches the server on the address it listens on, which
// SHAUTH_LISTEN_ADDRESS configures; a wildcard host is reached on loopback.
func healthAddress(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return "127.0.0.1:8080"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}
