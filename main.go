package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"
)

func init() {
	caddy.RegisterModule(Middleware{})
}

// Middleware implements an HTTP middleware that enforces trusted devices.
type Middleware struct {
	TrustedIPsFile     string `json:"trusted_ips_file,omitempty"`
	TrustedTokensFile  string `json:"trusted_tokens_file,omitempty"`
	CookieName         string `json:"cookie_name,omitempty"`
	MaxAge             string `json:"max_age,omitempty"`

	trustedIPs   map[string]bool
	tokens       map[string]time.Time
	maxAge       time.Duration
	mu           sync.RWMutex
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.trusted_devices",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision sets up the module.
func (m *Middleware) Provision(ctx caddy.Context) error {
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
		return err
	}

	// Load trusted IPs
	m.trustedIPs = make(map[string]bool)
	if data, err := os.ReadFile(m.TrustedIPsFile); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				m.trustedIPs[line] = true
			}
		}
	}

	// Load trusted tokens
	m.tokens = make(map[string]time.Time)
	if data, err := os.ReadFile(m.TrustedTokensFile); err == nil {
		json.Unmarshal(data, &m.tokens)
	}

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP := getClientIP(r)

	m.mu.RLock()
	isTrustedIP := m.trustedIPs[clientIP]
	m.mu.RUnlock()

	cookie, err := r.Cookie(m.CookieName)
	hasValidCookie := false
	if err == nil {
		m.mu.RLock()
		expiry, exists := m.tokens[cookie.Value]
		m.mu.RUnlock()
		if exists && time.Now().Before(expiry) {
			hasValidCookie = true
		}
	}

	if hasValidCookie || isTrustedIP {
		if isTrustedIP && !hasValidCookie {
			// Generate new token
			token := uuid.New().String()
			expiry := time.Now().Add(m.maxAge)

			m.mu.Lock()
			m.tokens[token] = expiry
			m.mu.Unlock()

			// Save to file
			m.saveTokens()

			// Set cookie
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
		return next.ServeHTTP(w, r)
	}

	// Deny
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, "Access denied")
	return nil
}

// saveTokens saves the tokens to file.
func (m *Middleware) saveTokens() {
	data, _ := json.MarshalIndent(m.tokens, "", "  ")
	os.WriteFile(m.TrustedTokensFile, data, 0644)
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	// Fallback to RemoteAddr
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
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
