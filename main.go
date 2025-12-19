package trusteddevices

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
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"
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
	TrustedIPsFile        string `json:"trusted_ips_file,omitempty"`
	TrustedUserAgentsFile string `json:"trusted_user_agents_file,omitempty"`
	TrustedTokensFile     string `json:"trusted_tokens_file,omitempty"`
	CookieName            string `json:"cookie_name,omitempty"`
	MaxAge                string `json:"max_age,omitempty"`

	trustedIPs        map[string]bool
	trustedUserAgents map[string]bool
	tokens            map[string]time.Time
	maxAge            time.Duration
	mu                sync.RWMutex
	logger            *zap.Logger
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
	if m.TrustedUserAgentsFile == "" {
		m.TrustedUserAgentsFile = "trusted_user_agents.txt"
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
	m.trustedIPs = make(map[string]bool)
	if data, err := os.ReadFile(m.TrustedIPsFile); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				m.trustedIPs[line] = true
			}
		}
		m.logger.Info("loaded trusted IPs", zap.Int("count", len(m.trustedIPs)), zap.String("file", m.TrustedIPsFile))
	} else {
		m.logger.Warn("could not load trusted IPs file", zap.String("file", m.TrustedIPsFile), zap.Error(err))
	}

	// Load trusted user agents
	m.trustedUserAgents = make(map[string]bool)
	if data, err := os.ReadFile(m.TrustedUserAgentsFile); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				m.trustedUserAgents[line] = true
			}
		}
		m.logger.Info("loaded trusted user agents", zap.Int("count", len(m.trustedUserAgents)), zap.String("file", m.TrustedUserAgentsFile))
	} else {
		m.logger.Warn("could not load trusted user agents file", zap.String("file", m.TrustedUserAgentsFile), zap.Error(err))
	}

	// Load trusted tokens
	m.tokens = make(map[string]time.Time)
	if data, err := os.ReadFile(m.TrustedTokensFile); err == nil {
		if err := json.Unmarshal(data, &m.tokens); err != nil {
			m.logger.Error("failed to parse tokens file", zap.String("file", m.TrustedTokensFile), zap.Error(err))
		} else {
			// Clean up expired tokens
			now := time.Now()
			for token, expiry := range m.tokens {
				if now.After(expiry) {
					delete(m.tokens, token)
				}
			}
			m.logger.Info("loaded trusted tokens", zap.Int("count", len(m.tokens)), zap.String("file", m.TrustedTokensFile))
		}
	} else if !os.IsNotExist(err) {
		m.logger.Warn("could not load tokens file", zap.String("file", m.TrustedTokensFile), zap.Error(err))
	} else {
		m.logger.Info("tokens file does not exist yet, will be created on first use", zap.String("file", m.TrustedTokensFile))
	}

	return nil
}

// Validate validates that the module has a usable config.
func (m *Middleware) Validate() error {
	if m.TrustedIPsFile == "" {
		return fmt.Errorf("trusted_ips_file cannot be empty")
	}
	if m.TrustedUserAgentsFile == "" {
		return fmt.Errorf("trusted_user_agents_file cannot be empty")
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
	clientIP := getClientIP(r)
	userAgent := r.UserAgent()

	m.mu.RLock()
	isTrustedIP := m.trustedIPs[clientIP]
	isTrustedUA := m.trustedUserAgents[userAgent]
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

	if hasValidCookie || isTrustedIP || isTrustedUA {
		if (isTrustedIP || isTrustedUA) && !hasValidCookie {
			// Generate new token
			token := uuid.New().String()
			expiry := time.Now().Add(m.maxAge)

			m.mu.Lock()
			m.tokens[token] = expiry
			m.mu.Unlock()

			// Save to file
			if err := m.saveTokens(); err != nil {
				m.logger.Error("failed to save token", zap.Error(err))
			}

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
func (m *Middleware) saveTokens() error {
	m.mu.RLock()
	data, err := json.MarshalIndent(m.tokens, "", "  ")
	m.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("marshaling tokens: %w", err)
	}

	if err := os.WriteFile(m.TrustedTokensFile, data, 0644); err != nil {
		return fmt.Errorf("writing tokens file: %w", err)
	}

	m.logger.Debug("saved tokens to file", zap.String("file", m.TrustedTokensFile), zap.Int("count", len(m.tokens)))
	return nil
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
			case "trusted_user_agents_file":
				if !d.Args(&m.TrustedUserAgentsFile) {
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
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
