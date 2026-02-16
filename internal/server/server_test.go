package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"jwks-server/internal/keys"
	"jwks-server/internal/server"
)

func newTestServer(t *testing.T) *server.Server {
	t.Helper()
	now := time.Now().UTC()
	store, err := keys.NewStore(keys.StoreConfig{
		ExpiredKeyExpiry: now.Add(-1 * time.Hour),
		ValidKeyExpiry:   now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("store init: %v", err)
	}
	return server.New(store)
}

func TestJWKSOnlyReturnsActiveKeys(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	w := httptest.NewRecorder()

	srv.HandleJWKS(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var jwksResp keys.JWKS
	if err := json.NewDecoder(w.Body).Decode(&jwksResp); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}

	if len(jwksResp.Keys) != 1 {
		t.Fatalf("expected 1 active key, got %d", len(jwksResp.Keys))
	}
	if jwksResp.Keys[0].Kid == "" || jwksResp.Keys[0].N == "" || jwksResp.Keys[0].E == "" {
		t.Fatal("expected jwk to have kid, n, e")
	}
}

func TestAuthIssuesValidJWTWithKid(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	w := httptest.NewRecorder()

	srv.HandleAuth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	tokenStr := strings.TrimSpace(w.Body.String())
	parser := jwt.NewParser()

	// Parse without verifying first; we only check it is well-formed and has kid.
	tok, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}

	kid, ok := tok.Header["kid"].(string)
	if !ok || kid == "" {
		t.Fatal("expected kid in JWT header")
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("expected map claims")
	}
	if claims["sub"] != "fake-user" {
		t.Fatalf("expected sub=fake-user, got %v", claims["sub"])
	}
}

func TestAuthExpiredQueryIssuesExpiredToken(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
	w := httptest.NewRecorder()

	srv.HandleAuth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	tokenStr := strings.TrimSpace(w.Body.String())
	tok, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}

	claims := tok.Claims.(jwt.MapClaims)
	expF, ok := claims["exp"].(float64)
	if !ok {
		t.Fatal("expected exp claim")
	}

	exp := time.Unix(int64(expF), 0).UTC()
	if !exp.Before(time.Now().UTC()) {
		t.Fatalf("expected expired exp, got %v", exp)
	}
}

func TestMethodGuards(t *testing.T) {
	srv := newTestServer(t)

	// /jwks must be GET
	req := httptest.NewRequest(http.MethodPost, "/jwks", nil)
	w := httptest.NewRecorder()
	srv.HandleJWKS(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("jwks method guard expected 405, got %d", w.Code)
	}

	// /auth must be POST
	req2 := httptest.NewRequest(http.MethodGet, "/auth", nil)
	w2 := httptest.NewRecorder()
	srv.HandleAuth(w2, req2)
	if w2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("auth method guard expected 405, got %d", w2.Code)
	}
}
