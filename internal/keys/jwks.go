package keys

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"` // RSA
	Use string `json:"use"` // sig
	Alg string `json:"alg"` // RS256
	Kid string `json:"kid"` // key id
	N   string `json:"n"`   // modulus
	E   string `json:"e"`   // exponent
}

func ToJWKS(active []KeyRecord) JWKS {
	out := JWKS{Keys: make([]JWK, 0, len(active))}
	for _, kr := range active {
		out.Keys = append(out.Keys, RSAJWK(kr.KID, &kr.Priv.PublicKey))
	}
	return out
}

func RSAJWK(kid string, pub *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}
