package keys

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strconv"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func ToJWKS(active []KeyRecord) JWKS {
	out := JWKS{Keys: make([]JWK, 0, len(active))}
	for _, kr := range active {
		out.Keys = append(out.Keys, RSAJWK(kr.KID, &kr.Priv.PublicKey))
	}
	return out
}

func RSAJWK(kid int64, pub *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: strconv.FormatInt(kid, 10),
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}
