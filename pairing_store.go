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

// unbiasedByteLimit is the largest multiple of the alphabet size below 256.
const unbiasedByteLimit = 256 / len(codeAlphabet) * len(codeAlphabet)

func newCode() string {
	code := make([]byte, 0, codeLength)
	b := make([]byte, 1)
	for len(code) < codeLength {
		_, _ = rand.Read(b) // never fails, see crypto/rand
		if int(b[0]) < unbiasedByteLimit {
			code = append(code, codeAlphabet[int(b[0])%len(codeAlphabet)])
		}
	}
	return string(code)
}

// isPaired reports whether token was approved through pairing and has not expired.
func (s *tokenStore) isPaired(token string) bool {
	s.refresh()
	s.mu.RLock()
	info, exists := s.tokens[token]
	s.mu.RUnlock()
	return exists && info.Paired && time.Now().Before(info.Expires)
}

// addFirstDevice approves a device right away when no paired token is valid yet, so the first device can approve
// the others. Checking and adding happen in one step, so two devices at once can't both become the first. It
// refuses while the tokens file is missing or can't be parsed, as its tokens may only look absent then.
func (s *tokenStore) addFirstDevice(name string, maxAge time.Duration) (string, bool) {
	token := uuid.New().String()
	added := false
	err := s.update(func() bool {
		if s.unreadable {
			return false
		}
		now := time.Now()
		for _, info := range s.tokens {
			if info.Paired && now.Before(info.Expires) {
				return false
			}
		}
		s.tokens[token] = tokenInfo{Expires: now.Add(maxAge), Paired: true, Name: name, Created: now, LastSeen: now}
		added = true
		return true
	})
	if err != nil {
		s.logger.Error("failed to save token", zap.Error(err))
		return "", false
	}
	return token, added
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

// approve turns the waiting device with code into an approved one; it keeps waiting when that can't be saved.
func (s *tokenStore) approve(code, name string, maxAge time.Duration) bool {
	approved := ""
	err := s.update(func() bool {
		now := time.Now()
		s.prunePendingLocked(now)
		for token, p := range s.pending {
			if p.Code == code {
				s.tokens[token] = tokenInfo{Expires: now.Add(maxAge), Paired: true, Name: name, Created: now, LastSeen: now}
				approved = token
				return true
			}
		}
		return false
	})
	if err != nil {
		s.logger.Error("failed to save token", zap.Error(err))
		return false
	}
	if approved == "" {
		return false
	}
	s.mu.Lock()
	delete(s.pending, approved)
	s.mu.Unlock()
	return true
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

// revoke removes the paired device with id, unless it's the current device.
func (s *tokenStore) revoke(id, current string) bool {
	found := false
	err := s.update(func() bool {
		for token, info := range s.tokens {
			if info.Paired && token != current && deviceID(token) == id {
				delete(s.tokens, token)
				found = true
			}
		}
		return found
	})
	if err != nil {
		s.logger.Error("failed to save tokens after revoking", zap.Error(err))
		return false
	}
	return found
}

// devices returns the paired devices, most recently used first.
func (s *tokenStore) devices(current string) []device {
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	list := make([]device, 0, len(s.tokens))
	for t, info := range s.tokens {
		if info.Paired && now.Before(info.Expires) {
			list = append(list, device{
				ID: deviceID(t), Name: info.Name, Created: info.Created, LastSeen: info.LastSeen,
				Expires: info.Expires, Current: t == current,
			})
		}
	}
	slices.SortFunc(list, func(a, b device) int { return b.LastSeen.Compare(a.LastSeen) })
	return list
}

// touch records that token was used and extends it by maxAge from now, so a device in use never expires and devices
// paired on the same day don't all expire at once. It does so at most once per lastSeenResolution per device, and
// reports whether it did, so the cookie can be renewed with it.
func (s *tokenStore) touch(token string, maxAge time.Duration) bool {
	s.mu.RLock()
	info, ok := s.tokens[token]
	s.mu.RUnlock()
	if !ok || time.Since(info.LastSeen) < lastSeenResolution {
		return false
	}
	renewed := false
	err := s.update(func() bool {
		// Read again: the file may have changed, and another request may have just done this.
		info, ok := s.tokens[token]
		now := time.Now()
		if !ok || !info.Paired || now.Sub(info.LastSeen) < lastSeenResolution {
			return false
		}
		info.LastSeen, info.Expires = now, now.Add(maxAge)
		s.tokens[token] = info
		renewed = true
		return true
	})
	if err != nil {
		s.logger.Error("failed to save last use", zap.Error(err))
		return false
	}
	return renewed
}
