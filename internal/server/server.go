package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
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

type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func validBasicAuth(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false
	}

	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}

	raw := strings.TrimPrefix(auth, prefix)
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return false
	}

	return strings.Contains(string(decoded), ":")
}

func validJSONAuth(r *http.Request) bool {
	var req authRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return false
	}

	return req.Username == "userABC" && req.Password == "password123"
}

func (s *Server) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now().UTC()
	active, err := s.store.ActiveKeys(now)
	if err != nil {
		http.Error(w, "failed to read keys", http.StatusInternalServerError)
		return
	}

	jwks := keys.ToJWKS(active)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwks)
}

func (s *Server) HandleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authorized := false

	if validBasicAuth(r) {
		authorized = true
	} else if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		authorized = validJSONAuth(r)
	}

	if !authorized {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	now := time.Now().UTC()
	useExpired := r.URL.Query().Has("expired")

	var (
		keyRecord keys.KeyRecord
		ok        bool
		err       error
	)

	if useExpired {
		keyRecord, ok, err = s.store.GetExpiredKey(now)
	} else {
		keyRecord, ok, err = s.store.GetValidKey(now)
	}

	if err != nil {
		http.Error(w, "failed to read signing key", http.StatusInternalServerError)
		return
	}

	if !ok {
		http.Error(w, "no matching key found", http.StatusInternalServerError)
		return
	}

	exp := now.Add(5 * time.Minute)
	if useExpired {
		exp = keyRecord.Expiry
	}

	claims := jwt.MapClaims{
		"sub": "userABC",
		"iss": "jwks-server",
		"iat": now.Unix(),
		"exp": exp.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = strconv.FormatInt(keyRecord.KID, 10)

	signed, err := token.SignedString(keyRecord.Priv)
	if err != nil {
		http.Error(w, "failed to sign jwt", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(signed))
}
