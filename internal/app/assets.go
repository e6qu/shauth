// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	_ "embed"
	"net/http"
	"time"
)

const htmxAssetPath = "/assets/htmx-2.0.8.min.js"
const htmxAssetIntegrity = "sha384-LvL6Vcojcqp2iIBXpGiD8EjaxVMhlKxfJCX1ZWJtWPWF5ki0j7nfzzog6M0nzjZM"

//go:embed assets/htmx-2.0.8.min.js
var htmxAsset []byte

func serveHTMX(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	http.ServeContent(w, r, "htmx-2.0.8.min.js", time.Time{}, bytes.NewReader(htmxAsset))
}

//go:embed assets/favicon.svg
var faviconAsset []byte

// serveFavicon answers both /favicon.svg and the /favicon.ico path browsers
// request unprompted, so a page load never produces a spurious 404.
func serveFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(w, r, "favicon.svg", time.Time{}, bytes.NewReader(faviconAsset))
}
