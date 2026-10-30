package trusteddevices

import (
	"net/http"
	"strings"
)

// isNavigation reports whether r loads a page in a browser. Only those get a new token: the other requests of a page
// load arrive with the cookie by then, and some (the web app manifest, link previews, scripts) never send one, so
// minting for them would only pile up tokens that are valid for a year and never used.
func isNavigation(r *http.Request) bool {
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate"
	}
	// Browsers without fetch metadata: a GET asking for HTML.
	return r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html")
}
