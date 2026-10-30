package trusteddevices

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule((*Middleware)(nil))
	httpcaddyfile.RegisterHandlerDirective("trusted_devices", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

// Middleware implements an HTTP middleware that enforces trusted devices.
type Middleware struct {
	TrustedIPsFile    string `json:"trusted_ips_file,omitempty"`
	TrustedTokensFile string `json:"trusted_tokens_file,omitempty"`
	CookieName        string `json:"cookie_name,omitempty"`
	MaxAge            string `json:"max_age,omitempty"`

	trustedIPs ipList
	tokens     *tokenStore
	maxAge     time.Duration
	logger     *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (*Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.trusted_devices",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision sets up the module.
func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	if m.TrustedIPsFile == "" {
		m.TrustedIPsFile = "trusted_ips.txt"
	}
	if m.TrustedTokensFile == "" {
		m.TrustedTokensFile = "trusted_tokens.json"
	}
	if m.CookieName == "" {
		m.CookieName = "trusted_device"
	}
	if m.MaxAge == "" {
		m.MaxAge = "8760h" // 1 year
	}

	var err error
	m.maxAge, err = time.ParseDuration(m.MaxAge)
	if err != nil {
		return fmt.Errorf("parsing max_age: %w", err)
	}

	// Load trusted IPs
	m.trustedIPs = nil
	if data, err := os.ReadFile(m.TrustedIPsFile); err == nil {
		var invalid []string
		m.trustedIPs, invalid = parseIPList(string(data))
		for _, line := range invalid {
			m.logger.Warn("ignoring invalid trusted IP", zap.String("line", line), zap.String("file", m.TrustedIPsFile))
		}
		m.logger.Info("loaded trusted IPs", zap.Int("count", len(m.trustedIPs)), zap.String("file", m.TrustedIPsFile))
	} else {
		m.logger.Warn("could not load trusted IPs file", zap.String("file", m.TrustedIPsFile), zap.Error(err))
	}

	m.tokens, err = acquireTokenStore(m.TrustedTokensFile, m.logger)
	if err != nil {
		return fmt.Errorf("loading tokens: %w", err)
	}

	return nil
}

// Cleanup releases the shared token store.
func (m *Middleware) Cleanup() error {
	if m.tokens != nil {
		releaseTokenStore(m.TrustedTokensFile)
	}
	return nil
}

// Validate validates that the module has a usable config.
func (m *Middleware) Validate() error {
	if m.TrustedIPsFile == "" {
		return fmt.Errorf("trusted_ips_file cannot be empty")
	}
	if m.TrustedTokensFile == "" {
		return fmt.Errorf("trusted_tokens_file cannot be empty")
	}
	if m.maxAge <= 0 {
		return fmt.Errorf("max_age must be positive")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	isTrustedIP := m.trustedIPs.contains(getClientIP(r))

	cookie, err := r.Cookie(m.CookieName)
	hasValidCookie := err == nil && m.tokens.isValid(cookie.Value)

	if hasValidCookie {
		return next.ServeHTTP(w, r)
	}
	if isTrustedIP && !isNavigation(r) {
		return next.ServeHTTP(w, r)
	}
	if isTrustedIP {
		http.SetCookie(w, &http.Cookie{
			Name:     m.CookieName,
			Value:    m.tokens.issue(m.maxAge),
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(m.maxAge.Seconds()),
		})
		return next.ServeHTTP(w, r)
	}

	// Deny
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, "Access denied")
	return nil
}

// getClientIP returns the client IP as resolved by Caddy. Caddy populates this
// from RemoteAddr, only honoring forwarding headers (X-Forwarded-For etc.) when
// the request actually arrived through a configured trusted_proxies hop. We must
// not parse those headers ourselves: they are attacker-controlled and trusting
// them would let anyone spoof a trusted IP.
func getClientIP(r *http.Request) string {
	if ip, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok && ip != "" {
		return ip
	}
	// Fallback for contexts where Caddy did not populate the var.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "trusted_ips_file":
				if !d.Args(&m.TrustedIPsFile) {
					return d.ArgErr()
				}
			case "trusted_tokens_file":
				if !d.Args(&m.TrustedTokensFile) {
					return d.ArgErr()
				}
			case "cookie_name":
				if !d.Args(&m.CookieName) {
					return d.ArgErr()
				}
			case "max_age":
				if !d.Args(&m.MaxAge) {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.CleanerUpper          = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
