package signing

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"sort"
)

var (
	ErrUnknownKey   = errors.New("signing key is not registered")
	ErrBadSignature = errors.New("signature does not verify")
)

// PublicKeys is an immutable key_id → P-256 public key registry, delivered by
// deployment configuration and never updated from signed content itself.
type PublicKeys struct{ keys map[string]*ecdsa.PublicKey }

func NewPublicKeys(keys map[string]*ecdsa.PublicKey) (PublicKeys, error) {
	if len(keys) == 0 {
		return PublicKeys{}, errors.New("public key registry is empty")
	}
	copied := make(map[string]*ecdsa.PublicKey, len(keys))
	for id, key := range keys {
		if !ValidKeyID(id) || key == nil || key.Curve != elliptic.P256() {
			return PublicKeys{}, errors.New("public key registry entries must be P-256 keys with valid IDs")
		}
		raw, err := key.Bytes()
		if err != nil {
			return PublicKeys{}, errors.New("invalid public key")
		}
		parsed, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
		if err != nil {
			return PublicKeys{}, errors.New("invalid public key")
		}
		copied[id] = parsed
	}
	return PublicKeys{keys: copied}, nil
}

// Lookup returns a copy of the registered key.
func (p PublicKeys) Lookup(id string) (*ecdsa.PublicKey, bool) {
	key, ok := p.keys[id]
	if !ok {
		return nil, false
	}
	raw, _ := key.Bytes()
	copied, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	return copied, err == nil
}

func (p PublicKeys) Len() int { return len(p.keys) }

// Verify checks an ASN.1 DER ECDSA signature over SHA-256(message).
func (p PublicKeys) Verify(id string, message, signature []byte) error {
	key, ok := p.keys[id]
	if !ok {
		return ErrUnknownKey
	}
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(key, digest[:], signature) {
		return ErrBadSignature
	}
	return nil
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

// privateMembers are JWK members that carry private key material (RFC 7518).
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "k", "oth"}

// ParseJWKS reads an RFC 7517 key set of EC P-256 signing keys. A key set
// containing private key material is rejected instead of silently used.
func ParseJWKS(data []byte) (PublicKeys, error) {
	var document struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return PublicKeys{}, errors.New("public key set must be a JSON Web Key Set")
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, raw := range document.Keys {
		var members map[string]json.RawMessage
		if err := json.Unmarshal(raw, &members); err != nil {
			return PublicKeys{}, errors.New("invalid JSON Web Key")
		}
		for _, name := range privateMembers {
			if _, ok := members[name]; ok {
				return PublicKeys{}, errors.New("public key set must not contain private key material")
			}
		}
		var key jwk
		if err := json.Unmarshal(raw, &key); err != nil {
			return PublicKeys{}, errors.New("invalid JSON Web Key")
		}
		if key.Kty != "EC" || key.Crv != "P-256" || (key.Alg != "" && key.Alg != "ES256") || (key.Use != "" && key.Use != "sig") {
			return PublicKeys{}, errors.New("public keys must be EC P-256 signing keys")
		}
		x, errX := base64.RawURLEncoding.Strict().DecodeString(key.X)
		y, errY := base64.RawURLEncoding.Strict().DecodeString(key.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			return PublicKeys{}, errors.New("invalid EC public key coordinates")
		}
		public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return PublicKeys{}, errors.New("EC public key is not on P-256")
		}
		if _, exists := keys[key.Kid]; exists {
			return PublicKeys{}, errors.New("duplicate key ID in public key set")
		}
		keys[key.Kid] = public
	}
	return NewPublicKeys(keys)
}

func LoadJWKS(path string) (PublicKeys, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return PublicKeys{}, errors.New("read public key set failed")
	}
	return ParseJWKS(data)
}

// MarshalJWKS writes public keys in the format ParseJWKS reads, e.g. to hand a
// development signer's key to local receivers.
func MarshalJWKS(keys map[string]*ecdsa.PublicKey) ([]byte, error) {
	registry, err := NewPublicKeys(keys)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(registry.keys))
	for id := range registry.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	document := struct {
		Keys []jwk `json:"keys"`
	}{}
	for _, id := range ids {
		raw, _ := registry.keys[id].Bytes()
		document.Keys = append(document.Keys, jwk{Kty: "EC", Crv: "P-256", Kid: id, Alg: "ES256", Use: "sig",
			X: base64.RawURLEncoding.EncodeToString(raw[1:33]), Y: base64.RawURLEncoding.EncodeToString(raw[33:])})
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
