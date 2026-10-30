package trusteddevices

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	// pendingTTL is how long a device waits for approval before it has to start again.
	pendingTTL = 15 * time.Minute
	// maxPending caps the waiting devices, so a misbehaving client on the trusted network can't fill the memory.
	maxPending = 20
	// lastSeenResolution limits how often using a device writes the tokens file.
	lastSeenResolution = time.Hour
	// codeAlphabet leaves out characters that are easily mixed up (0/O, 1/I/L).
	codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	codeLength   = 6
)

var errTooManyPending = errors.New("too many devices waiting for approval")

type pendingDevice struct {
	Code      string
	UserAgent string
	IP        string
	Created   time.Time
}

// device is an approved token as the admin page shows it; the token itself never leaves the server.
type device struct {
	ID       string
	Name     string
	Created  time.Time
	LastSeen time.Time
	Expires  time.Time
	Current  bool
}

// deviceID identifies a token on the admin page without revealing it.
func deviceID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}

func newCode() string {
	b := make([]byte, codeLength)
	_, _ = rand.Read(b) // never fails, see crypto/rand
	for i := range b {
		b[i] = codeAlphabet[int(b[i])%len(codeAlphabet)]
	}
	return string(b)
}

// hasDevices reports whether any token is valid; until one is, the first device to pair is approved by itself.
func (s *tokenStore) hasDevices() bool {
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	for _, info := range s.tokens {
		if now.Before(info.Expires) {
			return true
		}
	}
	return false
}

// addDevice approves a new token right away.
func (s *tokenStore) addDevice(name string, maxAge time.Duration) string {
	token := uuid.New().String()
	now := time.Now()
	s.mu.Lock()
	s.syncLocked()
	s.tokens[token] = tokenInfo{Expires: now.Add(maxAge), Name: name, Created: now, LastSeen: now}
	s.mu.Unlock()
	if err := s.save(); err != nil {
		s.logger.Error("failed to save token", zap.Error(err))
	}
	return token
}

// startPairing creates a token that's not valid yet, and the code an admin approves it with.
func (s *tokenStore) startPairing(userAgent, ip string) (string, pendingDevice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prunePendingLocked(time.Now())
	if len(s.pending) >= maxPending {
		return "", pendingDevice{}, errTooManyPending
	}
	code := newCode()
	for s.codeTakenLocked(code) {
		code = newCode()
	}
	p := pendingDevice{Code: code, UserAgent: userAgent, IP: ip, Created: time.Now()}
	token := uuid.New().String()
	s.pending[token] = p
	return token, p, nil
}

func (s *tokenStore) codeTakenLocked(code string) bool {
	for _, p := range s.pending {
		if p.Code == code {
			return true
		}
	}
	return false
}

func (s *tokenStore) prunePendingLocked(now time.Time) {
	for token, p := range s.pending {
		if now.Sub(p.Created) > pendingTTL {
			delete(s.pending, token)
		}
	}
}

// pendingFor returns the pairing request token belongs to, if it's still waiting.
func (s *tokenStore) pendingFor(token string) (pendingDevice, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prunePendingLocked(time.Now())
	p, ok := s.pending[token]
	return p, ok
}

// pendingList returns the waiting devices, oldest first.
func (s *tokenStore) pendingList() []pendingDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prunePendingLocked(time.Now())
	list := make([]pendingDevice, 0, len(s.pending))
	for _, p := range s.pending {
		list = append(list, p)
	}
	slices.SortFunc(list, func(a, b pendingDevice) int { return a.Created.Compare(b.Created) })
	return list
}

// approve turns the waiting device with code into an approved one.
func (s *tokenStore) approve(code, name string, maxAge time.Duration) bool {
	now := time.Now()
	s.mu.Lock()
	s.prunePendingLocked(now)
	token, found := "", false
	for t, p := range s.pending {
		if p.Code == code {
			token, found = t, true
		}
	}
	if found {
		delete(s.pending, token)
		s.syncLocked()
		s.tokens[token] = tokenInfo{Expires: now.Add(maxAge), Name: name, Created: now, LastSeen: now}
	}
	s.mu.Unlock()
	if found {
		if err := s.save(); err != nil {
			s.logger.Error("failed to save token", zap.Error(err))
		}
	}
	return found
}

// reject drops the waiting device with code.
func (s *tokenStore) reject(code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for t, p := range s.pending {
		if p.Code == code {
			delete(s.pending, t)
			return true
		}
	}
	return false
}

// revoke removes the approved device with id.
func (s *tokenStore) revoke(id string) bool {
	s.mu.Lock()
	s.syncLocked()
	found := false
	for t := range s.tokens {
		if deviceID(t) == id {
			delete(s.tokens, t)
			found = true
		}
	}
	s.mu.Unlock()
	if found {
		if err := s.save(); err != nil {
			s.logger.Error("failed to save tokens after revoking", zap.Error(err))
		}
	}
	return found
}

// devices returns the approved devices, most recently used first.
func (s *tokenStore) devices(current string) []device {
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	list := make([]device, 0, len(s.tokens))
	for t, info := range s.tokens {
		if now.Before(info.Expires) {
			list = append(list, device{
				ID: deviceID(t), Name: info.Name, Created: info.Created, LastSeen: info.LastSeen,
				Expires: info.Expires, Current: t == current,
			})
		}
	}
	slices.SortFunc(list, func(a, b device) int { return b.LastSeen.Compare(a.LastSeen) })
	return list
}

// touch records that token was used, writing the file at most once per lastSeenResolution per device.
func (s *tokenStore) touch(token string) {
	now := time.Now()
	s.mu.Lock()
	info, ok := s.tokens[token]
	changed := ok && now.Sub(info.LastSeen) >= lastSeenResolution
	if changed {
		// Read hand edits first, so writing the last use doesn't bring a revoked token back.
		s.syncLocked()
		info, ok = s.tokens[token]
		changed = ok
	}
	if changed {
		info.LastSeen = now
		s.tokens[token] = info
	}
	s.mu.Unlock()
	if changed {
		if err := s.save(); err != nil {
			s.logger.Error("failed to save last use", zap.Error(err))
		}
	}
}
