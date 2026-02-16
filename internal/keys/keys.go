package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type KeyRecord struct {
	KID    string
	Expiry time.Time
	Priv   *rsa.PrivateKey
}

func (k KeyRecord) Expired(at time.Time) bool {
	return !k.Expiry.After(at)
}

type StoreConfig struct {
	ExpiredKeyExpiry time.Time
	ValidKeyExpiry   time.Time
}

type Store struct {
	mu   sync.RWMutex
	keys []KeyRecord
}

func NewStore(cfg StoreConfig) (*Store, error) {
	if cfg.ValidKeyExpiry.IsZero() || cfg.ExpiredKeyExpiry.IsZero() {
		return nil, errors.New("expiry timestamps must be set")
	}
	if !cfg.ValidKeyExpiry.After(cfg.ExpiredKeyExpiry) {
		// Not strictly required, but helps sanity.
	}

	expiredKey, err := genKey(cfg.ExpiredKeyExpiry)
	if err != nil {
		return nil, err
	}

	validKey, err := genKey(cfg.ValidKeyExpiry)
	if err != nil {
		return nil, err
	}

	return &Store{
		keys: []KeyRecord{expiredKey, validKey},
	}, nil
}

func genKey(expiry time.Time) (KeyRecord, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return KeyRecord{}, err
	}
	kid, err := randomKID(16)
	if err != nil {
		return KeyRecord{}, err
	}
	return KeyRecord{
		KID:    kid,
		Expiry: expiry.UTC(),
		Priv:   priv,
	}, nil
}

func randomKID(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ActiveKeys returns non-expired keys as of "now".
func (s *Store) ActiveKeys(now time.Time) []KeyRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]KeyRecord, 0, len(s.keys))
	for _, k := range s.keys {
		if !k.Expired(now) {
			out = append(out, k)
		}
	}
	return out
}

// ExpiredKey returns any expired key (used for /auth?expired=true).
func (s *Store) ExpiredKey(now time.Time) (KeyRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, k := range s.keys {
		if k.Expired(now) {
			return k, true
		}
	}
	return KeyRecord{}, false
}

// CurrentSigningKey returns the newest non-expired key.
func (s *Store) CurrentSigningKey(now time.Time) (KeyRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		best   KeyRecord
		hasBest bool
	)
	for _, k := range s.keys {
		if k.Expired(now) {
			continue
		}
		if !hasBest || k.Expiry.After(best.Expiry) {
			best = k
			hasBest = true
		}
	}
	return best, hasBest
}
