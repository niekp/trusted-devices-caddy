package trusteddevices

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const cleanupInterval = time.Hour

// reloadCheckInterval limits how often a request checks the tokens file for changes made by hand.
const reloadCheckInterval = time.Second

// tokenStores shares one store per tokens file across all handler instances and config reloads.
var tokenStores = caddy.NewUsagePool()

// tokenStore holds the tokens of one tokens file; every handler using that file shares it.
type tokenStore struct {
	path        string
	tokens      map[string]tokenInfo
	mu          sync.RWMutex
	saveMu      sync.Mutex // serializes changes that are written to the tokens file; taken before mu
	stopCleanup chan struct{}
	logger      *zap.Logger

	// What the tokens file looked like when it was last read or written, so a change made by hand (removing a
	// token, emptying the file) is picked up without a restart and not overwritten by the next save.
	fileSeen bool
	fileMod  time.Time
	fileSize int64
	// lastCheck is when a request last looked at the file, in Unix nanoseconds; read without a lock.
	lastCheck atomic.Int64
	// unreadable is set while the file is missing or can't be parsed, which is usually an editor halfway through
	// saving it. The tokens from before stay valid, and nothing is written until the file can be read again.
	unreadable bool

	// pending holds the devices waiting for approval, by the token their cookie already carries. Kept in memory
	// only: a restart asks them to pair again.
	pending map[string]pendingDevice
}

// acquireTokenStore returns the shared store for path, loading it from disk on first use.
func acquireTokenStore(path string, logger *zap.Logger) (*tokenStore, error) {
	value, _, err := tokenStores.LoadOrNew(path, func() (caddy.Destructor, error) {
		store := newTokenStore(path, logger)
		store.load()
		go store.cleanupLoop(cleanupInterval)
		return store, nil
	})
	if err != nil {
		return nil, err
	}
	return value.(*tokenStore), nil
}

// releaseTokenStore drops one reference; the last release stops the store.
func releaseTokenStore(path string) {
	_, _ = tokenStores.Delete(path)
}

func newTokenStore(path string, logger *zap.Logger) *tokenStore {
	return &tokenStore{
		path:        path,
		tokens:      make(map[string]tokenInfo),
		pending:     make(map[string]pendingDevice),
		stopCleanup: make(chan struct{}),
		logger:      logger,
	}
}

// Destruct stops the background cleanup goroutine.
func (s *tokenStore) Destruct() error {
	close(s.stopCleanup)
	return nil
}

// load reads the tokens file, dropping expired tokens.
func (s *tokenStore) load() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastCheck.Store(time.Now().UnixNano())
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		s.logger.Info("tokens file does not exist yet, will be created on first use", zap.String("file", s.path))
		return
	}
	s.syncLocked()
}

// refresh picks up changes to the tokens file, at most once per reloadCheckInterval across all requests.
func (s *tokenStore) refresh() {
	now := time.Now().UnixNano()
	last := s.lastCheck.Load()
	if now-last < int64(reloadCheckInterval) || !s.lastCheck.CompareAndSwap(last, now) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncLocked()
}

// syncLocked replaces the tokens in memory with the file's when the file changed since it was last read or
// written. The caller holds s.mu.
func (s *tokenStore) syncLocked() {
	info, err := os.Stat(s.path)
	if os.IsNotExist(err) {
		if s.fileSeen && !s.unreadable {
			s.logger.Warn("tokens file is missing; keeping the tokens in memory and not saving until it's back",
				zap.String("file", s.path))
			s.unreadable = true
		}
		return
	}
	if err != nil {
		s.logger.Warn("could not check tokens file", zap.String("file", s.path), zap.Error(err))
		return
	}
	if s.fileSeen && !s.unreadable && info.ModTime().Equal(s.fileMod) && info.Size() == s.fileSize {
		return
	}
	if s.unreadable && info.ModTime().Equal(s.fileMod) && info.Size() == s.fileSize {
		return // still the version that couldn't be parsed
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		s.logger.Warn("could not load tokens file", zap.String("file", s.path), zap.Error(err))
		return
	}
	s.fileSeen, s.fileMod, s.fileSize = true, info.ModTime(), info.Size()
	tokens := make(map[string]tokenInfo)
	if err := json.Unmarshal(data, &tokens); err != nil {
		s.logger.Error("failed to parse tokens file; keeping the tokens in memory and not saving until it's fixed",
			zap.String("file", s.path), zap.Error(err))
		s.unreadable = true
		return
	}
	s.tokens = tokens
	s.unreadable = false
	s.removeExpired(time.Now())
	s.logger.Info("loaded trusted tokens", zap.Int("count", len(s.tokens)), zap.String("file", s.path))
}

// update reads changes to the file, lets change modify the tokens, and writes them if it reports a change. Reading,
// changing and writing happen as one step towards other updates, so a hand edit is only lost if it lands in the
// moment between marshaling and replacing the file.
func (s *tokenStore) update(change func() bool) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.Lock()
	s.syncLocked()
	if !change() {
		s.mu.Unlock()
		return nil
	}
	unreadable := s.unreadable
	data, err := json.MarshalIndent(s.tokens, "", "  ")
	count := len(s.tokens)
	s.mu.Unlock()
	if unreadable {
		return fmt.Errorf("tokens file %s is missing or can't be parsed, not overwriting it", s.path)
	}
	if err != nil {
		return fmt.Errorf("marshaling tokens: %w", err)
	}

	info, err := s.write(data)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.fileSeen, s.fileMod, s.fileSize = true, info.ModTime(), info.Size()
	s.mu.Unlock()
	s.logger.Debug("saved tokens to file", zap.String("file", s.path), zap.Int("count", count))
	return nil
}

// isValid reports whether token exists and has not expired.
func (s *tokenStore) isValid(token string) bool {
	s.refresh()
	s.mu.RLock()
	info, exists := s.tokens[token]
	s.mu.RUnlock()
	return exists && time.Now().Before(info.Expires)
}

// issue creates and persists a new token valid for maxAge.
func (s *tokenStore) issue(maxAge time.Duration) string {
	token := uuid.New().String()
	err := s.update(func() bool {
		s.tokens[token] = tokenInfo{Expires: time.Now().Add(maxAge)}
		return true
	})
	if err != nil {
		s.logger.Error("failed to save token", zap.Error(err))
	}
	return token
}

// cleanupLoop periodically removes expired tokens until the store is destructed.
func (s *tokenStore) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCleanup:
			return
		case <-ticker.C:
			s.pruneExpired()
		}
	}
}

// pruneExpired removes expired tokens from memory and persists the result.
func (s *tokenStore) pruneExpired() {
	if err := s.update(func() bool { return s.removeExpired(time.Now()) }); err != nil {
		s.logger.Error("failed to save tokens after prune", zap.Error(err))
	}
}

// removeExpired deletes tokens expired at now; the caller holds the lock if needed.
func (s *tokenStore) removeExpired(now time.Time) bool {
	changed := false
	for token, info := range s.tokens {
		if now.After(info.Expires) {
			delete(s.tokens, token)
			changed = true
		}
	}
	return changed
}

// save persists the tokens in memory, after reading changes to the file.
func (s *tokenStore) save() error {
	return s.update(func() bool { return true })
}

// write atomically replaces the tokens file with data, with 0600 permissions. It returns the new file's details,
// taken before the rename so an edit landing right after it isn't mistaken for this write.
func (s *tokenStore) write(data []byte) (os.FileInfo, error) {
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".trusted_tokens-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("creating temp tokens file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if the rename succeeded

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("chmod temp tokens file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("writing temp tokens file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("closing temp tokens file: %w", err)
	}
	info, err := os.Stat(tmpName)
	if err != nil {
		return nil, fmt.Errorf("checking temp tokens file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return nil, fmt.Errorf("renaming tokens file: %w", err)
	}
	return info, nil
}
