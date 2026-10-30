package trusteddevices

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// servePairing handles a request when pairing is on. A device is let through only with an approved token; a trusted
// IP no longer approves by itself, it only allows starting to pair and managing devices.
func (m *Middleware) servePairing(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := getClientIP(r)
	trusted := m.trustedIPs.contains(ip)
	token := ""
	if c, err := r.Cookie(m.CookieName); err == nil {
		token = c.Value
	}
	approved := token != "" && m.tokens.isValid(token)

	if r.URL.Path == m.PairingPath || strings.HasPrefix(r.URL.Path, m.PairingPath+"/") {
		if approved && trusted {
			return m.serveAdmin(w, r, token)
		}
		if approved {
			return deny(w, "Managing devices only works from the trusted network.")
		}
	}
	if approved {
		m.tokens.touch(token, m.maxAge)
		return next.ServeHTTP(w, r)
	}
	if !isNavigation(r) {
		return deny(w, "Access denied")
	}
	if p, ok := m.tokens.pendingFor(token); ok {
		return m.renderWaiting(w, r, p)
	}
	if !trusted {
		return deny(w, "Access denied")
	}

	name := deviceName(r.UserAgent())
	if first, ok := m.tokens.addFirstDevice(name, m.maxAge); ok {
		m.setCookie(w, r, first)
		m.logger.Info("approved the first device by itself", zap.String("name", name), zap.String("ip", ip))
		return next.ServeHTTP(w, r)
	}
	newToken, p, err := m.tokens.startPairing(r.UserAgent(), ip)
	if errors.Is(err, errTooManyPending) {
		m.logger.Warn("pairing refused", zap.String("ip", ip), zap.Error(err))
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("Too many devices are waiting for approval. Try again later."))
		return nil
	}
	m.setCookie(w, r, newToken)
	m.logger.Info("device waiting for approval", zap.String("code", p.Code), zap.String("ip", ip))
	return m.renderWaiting(w, r, p)
}

func (m *Middleware) setCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(m.maxAge.Seconds()),
	})
}

func deny(w http.ResponseWriter, message string) error {
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(message))
	return nil
}

// serveAdmin shows the waiting and approved devices, and handles approving, rejecting and revoking.
func (m *Middleware) serveAdmin(w http.ResponseWriter, r *http.Request, token string) error {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return m.renderAdmin(w, token)
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}
	if !sameOrigin(r) {
		return deny(w, "Cross-site request refused")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}

	switch strings.TrimPrefix(r.URL.Path, m.PairingPath) {
	case "/approve":
		code := strings.ToUpper(strings.TrimSpace(r.PostForm.Get("code")))
		name := strings.TrimSpace(r.PostForm.Get("name"))
		if name == "" {
			name = "Device " + code
		}
		if runes := []rune(name); len(runes) > 60 {
			name = string(runes[:60])
		}
		if m.tokens.approve(code, name, m.maxAge) {
			m.logger.Info("device approved", zap.String("code", code), zap.String("name", name))
		}
	case "/reject":
		code := strings.ToUpper(strings.TrimSpace(r.PostForm.Get("code")))
		if m.tokens.reject(code) {
			m.logger.Info("pairing rejected", zap.String("code", code))
		}
	case "/revoke":
		id := r.PostForm.Get("id")
		if m.tokens.revoke(id) {
			m.logger.Info("device revoked", zap.String("id", id))
		}
	default:
		w.WriteHeader(http.StatusNotFound)
		return nil
	}
	http.Redirect(w, r, m.PairingPath, http.StatusSeeOther)
	return nil
}

// sameOrigin refuses form posts from other sites. The cookie is SameSite=Lax, which already keeps it off a
// cross-site POST; this also covers a sibling subdomain, which counts as the same site.
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin"
	}
	origin, err := url.Parse(r.Header.Get("Origin"))
	return err == nil && origin.Host != "" && origin.Host == r.Host
}

// deviceName guesses a name to suggest when approving; it's only a label, never used to decide anything.
func deviceName(userAgent string) string {
	ua := strings.ToLower(userAgent)
	kinds := []struct{ match, name string }{
		{"iphone", "iPhone"}, {"ipad", "iPad"}, {"android", "Android"}, {"windows", "Windows"},
		{"cros", "Chromebook"}, {"macintosh", "Mac"}, {"linux", "Linux"},
	}
	for _, k := range kinds {
		if strings.Contains(ua, k.match) {
			return k.name
		}
	}
	return "Device"
}

func pageHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	h.Set("Referrer-Policy", "no-referrer")
}

func (m *Middleware) renderWaiting(w http.ResponseWriter, r *http.Request, p pendingDevice) error {
	pageHeaders(w)
	w.WriteHeader(http.StatusForbidden)
	return waitingPage.Execute(w, map[string]any{
		"Code":    p.Code,
		"Address": r.Host + m.PairingPath,
		"Minutes": int(pendingTTL.Minutes()),
	})
}

func (m *Middleware) renderAdmin(w http.ResponseWriter, token string) error {
	pending := m.tokens.pendingList()
	type waiting struct {
		pendingDevice
		Suggested string
		Ago       string
	}
	list := make([]waiting, len(pending))
	for i, p := range pending {
		list[i] = waiting{p, deviceName(p.UserAgent), ago(p.Created)}
	}
	pageHeaders(w)
	return adminPage.Execute(w, map[string]any{
		"Path":    m.PairingPath,
		"Pending": list,
		"Devices": m.tokens.devices(token),
	})
}

func ago(t time.Time) string {
	switch d := time.Since(t); {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	default:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
}

const pageStyle = `<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root { color-scheme: light dark; font-family: system-ui, sans-serif; line-height: 1.5; }
body { max-width: 40rem; margin: 2rem auto; padding: 0 1rem; }
.code { font: 600 2.5rem ui-monospace, monospace; letter-spacing: .2em; }
section { border: 1px solid #8884; border-radius: .5rem; padding: 1rem; margin: 1rem 0; }
form { display: inline; }
input { font: inherit; padding: .25rem .5rem; }
button { font: inherit; padding: .25rem .75rem; cursor: pointer; }
.muted { opacity: .7; font-size: .9em; }
</style>`

var funcs = template.FuncMap{
	"date": func(t time.Time) string {
		if t.IsZero() {
			return "unknown"
		}
		return t.Local().Format("2 Jan 2006 15:04")
	},
}

var waitingPage = template.Must(template.New("waiting").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Waiting for approval</title>
<meta http-equiv="refresh" content="5">` + pageStyle + `</head><body>
<h1>This device isn't approved yet</h1>
<p>On a device that's already approved, on the trusted network, open <strong>{{.Address}}</strong> and approve this code:</p>
<p class="code">{{.Code}}</p>
<p class="muted">This page reloads by itself and opens the site once approved. The code expires after {{.Minutes}} minutes.</p>
</body></html>`))

var adminPage = template.Must(template.New("admin").Funcs(funcs).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Trusted devices</title>` + pageStyle + `</head><body>
<h1>Trusted devices</h1>
<h2>Waiting for approval</h2>
{{range .Pending}}<section>
<p class="code">{{.Code}}</p>
<p class="muted">{{.UserAgent}}<br>{{.IP}}, {{.Ago}}</p>
<form method="post" action="{{$.Path}}/approve">
<input type="hidden" name="code" value="{{.Code}}">
<label>Name <input name="name" value="{{.Suggested}}" maxlength="60" required></label>
<button>Approve</button>
</form>
<form method="post" action="{{$.Path}}/reject"><input type="hidden" name="code" value="{{.Code}}"><button>Reject</button></form>
</section>{{else}}<p class="muted">No device is waiting. Open the site on a new device on the trusted network to get a code; reload this page to see it.</p>{{end}}
<h2>Approved devices</h2>
{{range .Devices}}<section>
<strong>{{if .Name}}{{.Name}}{{else}}Unnamed device{{end}}</strong>{{if .Current}} (this device){{end}}
<p class="muted">Approved {{date .Created}} · last used {{date .LastSeen}} · expires {{date .Expires}}</p>
<form method="post" action="{{$.Path}}/revoke"><input type="hidden" name="id" value="{{.ID}}"><button>Revoke</button></form>
</section>{{end}}
</body></html>`))
