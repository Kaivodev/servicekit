// Package servicetoken authenticates plaintext RPCs with projected ServiceAccount tokens.
package servicetoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"slices"
)

var rawURL = base64.RawURLEncoding.Strict()
var errKeys = errors.New("service token public key set is unavailable or invalid")

type keySet map[string]crypto.PublicKey

type jwk struct {
	Kid    string   `json:"kid"`
	Kty    string   `json:"kty"`
	Use    string   `json:"use"`
	Alg    string   `json:"alg"`
	KeyOps []string `json:"key_ops"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	Crv    string   `json:"crv"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
}

func parseJWKS(data []byte) (keySet, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if json.Unmarshal(data, &doc) != nil || len(doc.Keys) == 0 {
		return nil, errKeys
	}
	keys := make(keySet, len(doc.Keys))
	for _, raw := range doc.Keys {
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) != nil {
			return nil, errKeys
		}
		for _, member := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if members[member] != nil {
				return nil, errKeys
			}
		}
		var k jwk
		if json.Unmarshal(raw, &k) != nil || k.Kid == "" || keys[k.Kid] != nil || (k.Use != "" && k.Use != "sig") || (k.KeyOps != nil && !slices.Contains(k.KeyOps, "verify")) {
			return nil, errKeys
		}
		switch k.Kty {
		case "RSA":
			n, errN := rawURL.DecodeString(k.N)
			e, errE := rawURL.DecodeString(k.E)
			modulus := new(big.Int).SetBytes(n)
			exponent := new(big.Int).SetBytes(e)
			if errN != nil || errE != nil || modulus.BitLen() < 2048 || modulus.Bit(0) == 0 || exponent.BitLen() > 31 || exponent.Int64() < 3 || exponent.Bit(0) == 0 || (k.Alg != "" && k.Alg != "RS256") {
				return nil, errKeys
			}
			keys[k.Kid] = &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}
		case "EC":
			x, errX := rawURL.DecodeString(k.X)
			y, errY := rawURL.DecodeString(k.Y)
			if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 || k.Crv != "P-256" || (k.Alg != "" && k.Alg != "ES256") {
				return nil, errKeys
			}
			key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
			if err != nil {
				return nil, errKeys
			}
			keys[k.Kid] = key
		default:
			return nil, errKeys
		}
	}
	return keys, nil
}
