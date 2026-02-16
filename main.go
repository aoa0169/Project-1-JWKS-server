package main

import (
	"log"
	"net/http"
	"time"

	"jwks-server/internal/keys"
	"jwks-server/internal/server"
)

func main() {
	// Create key store with:
	// - one expired key (expired 1 hour ago)
	// - one valid key (expires in 24 hours)
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
	mux.HandleFunc("/jwks", srv.HandleJWKS)
	mux.HandleFunc("/auth", srv.HandleAuth)

	log.Println("JWKS server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
