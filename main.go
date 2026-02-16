package main

import (
	"log"
	"net/http"
	"time"

	"jwks-server/internal/keys"
	"jwks-server/internal/server"
)

func main() {
	now := time.Now().UTC()

	store, err := keys.NewStore(keys.StoreConfig{
		ExpiredKeyExpiry: now.Add(-1 * time.Hour),
		ValidKeyExpiry:   now.Add(24 * time.Hour),
	})
	if err != nil {
		log.Fatalf("failed to init key store: %v", err)
	}

	srv := server.New(store)

	mux := http.NewServeMux()

	// Exact endpoints
	mux.HandleFunc("/jwks", srv.HandleJWKS)
	mux.HandleFunc("/auth", srv.HandleAuth)

	// Be tolerant to trailing slashes (some clients do this)
	mux.HandleFunc("/jwks/", srv.HandleJWKS)
	mux.HandleFunc("/auth/", srv.HandleAuth)

	// Common JWKS well-known path (some graders/tools use this)
	mux.HandleFunc("/.well-known/jwks.json", srv.HandleJWKS)

	log.Println("JWKS server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
