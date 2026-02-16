package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"jwks-server/internal/keys"
)

type Server struct {
	store *keys.Store
}

func New(store *keys.Store) *Server {
	return &Server{store: store}
}

// GET /jwks
// Returns only non-expired public keys in JWKS format.
func (s *Server) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now().UTC()
	active := s.store.ActiveKeys(now)
	jwks := keys.ToJWKS(active)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwks)
}

// POST /auth
// If ?expired is present, sign with an expired key and set exp to that expired time.
func (s *Server) HandleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now().UTC()

	issueExpired := r.URL.Query().Has("expired")

	var key keys.KeyRecord
	var ok bool

	if issueExpired {
		key, ok = s.store.ExpiredKey(now)
		if !ok {
			http.Error(w, "no expired key available", http.StatusInternalServerError)
			return
		}
	} else {
		key, ok = s.store.CurrentSigningKey(now)
		if !ok {
			http.Error(w, "no active key available", http.StatusInternalServerError)
			return
		}
	}

	// exp: normal token expires in 5 minutes OR expired token uses the expired key's expiry
	exp := now.Add(5 * time.Minute)
	if issueExpired {
		exp = key.Expiry // already in the past
	}

	claims := jwt.MapClaims{
		"sub": "fake-user",
		"iss": "jwks-server",
		"iat": now.Unix(),
		"exp": exp.Unix(),
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = key.KID

	signed, err := tok.SignedString(key.Priv)
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	// Return as plain text JWT (simple for the blackbox client)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(signed))
}
