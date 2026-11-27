// SPDX-License-Identifier: AGPL-3.0-or-later
// container-tls-probe checks the runtime's system roots through a real HTTPS
// exchange. Run the static binary inside the image, without host CA mounts.
package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 2 || !strings.HasPrefix(os.Args[1], "https://") {
		fmt.Fprintln(os.Stderr, "usage: container-tls-probe https://host/path")
		os.Exit(2)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	response, err := client.Get(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "unexpected HTTPS response:", response.Status)
		os.Exit(1)
	}
	fmt.Println("Go HTTPS verification passed using the container trust store")
}
