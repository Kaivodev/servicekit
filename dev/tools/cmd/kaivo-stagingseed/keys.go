package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/Kaivodev/servicekit/signing"
)

func pemDER(value, kind string) []byte {
	raw := bytes.TrimSpace([]byte(value))
	// pem.Decode alone skips leading text and malformed PEM blocks.
	header, _, _ := bytes.Cut(raw, []byte("\n"))
	if string(bytes.TrimSuffix(header, []byte("\r"))) != "-----BEGIN "+kind+"-----" || bytes.Count(raw, []byte("-----BEGIN ")) != 1 {
		return nil
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != kind || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil
	}
	return block.Bytes
}

func invalid(id objectID, key string) error {
	return fmt.Errorf("invalid or conflicting %s/%s %s", id.namespace, id.name, key)
}

func (m materials) published(name string) bool {
	for _, id := range registries {
		if _, ok := m[id][name]; ok {
			return true
		}
	}
	return false
}

func signingKey(old materials, id objectID, file, publicFile string) (*ecdsa.PrivateKey, string, error) {
	if value, ok := old[id][file]; ok {
		parsed, err := x509.ParsePKCS8PrivateKey(pemDER(value, "PRIVATE KEY"))
		key, ok := parsed.(*ecdsa.PrivateKey)
		if err != nil || !ok || key.Curve != elliptic.P256() {
			return nil, "", invalid(id, file)
		}
		return key, value, nil
	}
	_, localPublic := old[id][publicFile]
	if localPublic || old.published(publicFile) {
		return nil, "", fmt.Errorf("%s/%s %s missing for registered public key", id.namespace, id.name, file)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", errors.New("generate signing key failed")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", errors.New("encode signing key failed")
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func publishPEM(old, result materials, name string, key any, legacyReport *ecdsa.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return errors.New("encode public key failed")
	}
	value := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	for _, id := range registries {
		if saved, ok := old[id][name]; ok {
			savedDER := pemDER(saved, "PUBLIC KEY")
			if !bytes.Equal(savedDER, der) && !unmigratedReport(old[id], savedDER, legacyReport) {
				return invalid(id, name)
			}
		}
		result[id][name] = value
	}
	return nil
}

// Each namespace transitions independently during server-side apply. A report
// registry already containing a KMS kid rules out the legacy PEM exception.
func unmigratedReport(data fields, der []byte, legacy *ecdsa.PublicKey) bool {
	if legacy == nil {
		return false
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil || !legacy.Equal(pub) {
		return false
	}
	saved, exists := data[reportRegistry]
	if !exists {
		return true
	}
	return registrySubset(saved, publicKeys{"ledger-report-dev": legacy}, true)
}

func epayKey(old, result materials) error {
	holders := []objectID{backendPrivate, iamPrivate, paymentPrivate}
	const file = "epay.der"
	var key *rsa.PrivateKey
	var der string
	for _, id := range holders {
		value, ok := old[id][file]
		if !ok {
			continue
		}
		parsed, err := x509.ParsePKCS8PrivateKey([]byte(value))
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if err != nil || !ok || rsaKey.N.BitLen() < 2048 || rsaKey.Validate() != nil {
			return invalid(id, file)
		}
		if key != nil && der != value {
			return invalid(id, file)
		}
		key, der = rsaKey, value
	}
	if key == nil {
		if old.published("platform-public.pem") {
			return errors.New("EPay private key missing for registered public key")
		}
		var err error
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return errors.New("generate EPay key failed")
		}
		raw, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return errors.New("encode EPay key failed")
		}
		der = string(raw)
	}
	for _, id := range holders {
		result[id][file] = der
	}
	return publishPEM(old, result, "platform-public.pem", &key.PublicKey, nil)
}

var devSigningKeys = []struct {
	id                    objectID
	file, publicFile, kid string
}{
	{iamPrivate, "signing.pem", "iam.jwks", "iam-dev"},
	{paymentPrivate, "signing.pem", "payment.jwks", "payment-dev"},
	{ledgerPrivate, "signing.pem", "ledger.jwks", "ledger-dev"},
	{collectionPrivate, "signing.pem", "collection.jwks", "collection-dev"},
	{reconPrivate, "signing.pem", "reconciliation.jwks", "reconciliation-dev"},
	{ledgerPrivate, "report.pem", reportPEM, "ledger-report-dev"},
}

func seedKeys(old, result materials, kms *kmsMaterials) error {
	if err := epayKey(old, result); err != nil {
		return err
	}
	expected := map[string]publicKeys{}
	if kms != nil {
		for name, keys := range kms.registries {
			expected[name] = maps.Clone(keys)
		}
	}
	var seen []*ecdsa.PublicKey
	for _, service := range devSigningKeys {
		key, value, err := signingKey(old, service.id, service.file, service.publicFile)
		if err != nil {
			return err
		}
		for _, used := range seen {
			if used.Equal(&key.PublicKey) {
				return invalid(service.id, service.file)
			}
		}
		seen = append(seen, &key.PublicKey)
		result[service.id][service.file] = value
		name := service.publicFile
		if name == reportPEM {
			current := &key.PublicKey
			var legacy *ecdsa.PublicKey
			if kms != nil && kms.reportKID != "" {
				current = expected[reportRegistry][kms.reportKID]
				legacy = &key.PublicKey
			}
			if err := publishPEM(old, result, name, current, legacy); err != nil {
				return err
			}
			if kms == nil {
				continue
			}
			name = reportRegistry
		}
		if expected[name] == nil {
			expected[name] = publicKeys{}
		}
		expected[name][service.kid] = &key.PublicKey
	}
	return publishRegistries(old, result, expected, kms)
}

func publishRegistries(old, result materials, expected map[string]publicKeys, kms *kmsMaterials) error {
	if kms != nil {
		for _, id := range registries {
			for name := range old[id] {
				if strings.HasSuffix(name, ".jwks") && expected[name] == nil {
					return fmt.Errorf("unexpected signing registry in %s/%s", id.namespace, id.name)
				}
			}
		}
	}
	for name, keys := range expected {
		kmsRegistry := kms != nil && (kms.registries[name] != nil || name == reportRegistry)
		jwks, err := signing.MarshalJWKS(keys)
		if err != nil {
			return errors.New("encode signing registry failed")
		}
		destinations := registries
		if name == "collection.jwks" {
			destinations = append(slices.Clone(registries), collectionPrivate)
		}
		for _, id := range destinations {
			if saved, ok := old[id][name]; ok && !registrySubset(saved, keys, kmsRegistry) {
				return invalid(id, name)
			}
			result[id][name] = string(jwks)
		}
	}
	return nil
}

func registrySubset(saved string, allowed publicKeys, kmsRegistry bool) bool {
	if kmsRegistry && !jsontext.Value(saved).IsValid() {
		return false
	}
	// Receivers require at least one key. A well-formed empty set in a registry
	// being seeded from KMS can still be filled with its expected keys.
	registry, err := signing.ParseJWKS([]byte(saved))
	if err != nil {
		var set struct {
			Keys []jsontext.Value `json:"keys"`
		}
		return kmsRegistry && json.Unmarshal([]byte(saved), &set) == nil && set.Keys != nil && len(set.Keys) == 0
	}
	matched := 0
	for kid, key := range allowed {
		if existing, found := registry.Lookup(kid); found {
			if !existing.Equal(key) {
				return false
			}
			matched++
		}
	}
	return matched == registry.Len()
}

func randomBytes() []byte {
	var key [32]byte
	rand.Read(key[:])
	return key[:]
}

func encoded32(encoding *base64.Encoding, s string) bool {
	b, err := encoding.DecodeString(s)
	return err == nil && len(b) == 32 && encoding.EncodeToString(b) == s
}

func randomHex() string    { return hex.EncodeToString(randomBytes()) }
func randomURL() string    { return base64.RawURLEncoding.EncodeToString(randomBytes()) }
func randomBase64() string { return base64.StdEncoding.EncodeToString(randomBytes()) }

func opaqueKeys(old, result materials) error {
	isURL := func(s string) bool { return encoded32(base64.RawURLEncoding, s) }
	raw := func() string { return string(randomBytes()) }
	isRaw := func(s string) bool { return len(s) == 32 }
	for _, spec := range []struct {
		id       objectID
		name     string
		generate func() string
		valid    func(string) bool
	}{
		{iamPrivate, "sealer.key", raw, isRaw},
		{reconPrivate, "sealer.key", raw, isRaw},
		{iamPrivate, "data-key", randomBase64, func(s string) bool { return encoded32(base64.StdEncoding, s) }},
		{backendPrivate, "portal-cookie-key", randomURL, isURL},
		{backendPrivate, "telegram-webhook-secret", randomURL, isURL},
		{backendPrivate, "bot-token", func() string { return "10001:" + randomURL() }, func(s string) bool {
			suffix, ok := strings.CutPrefix(s, "10001:")
			return ok && isURL(suffix)
		}},
	} {
		value, ok := old[spec.id][spec.name]
		if spec.name == "bot-token" {
			if peer, exists := old[fixturePrivate][spec.name]; exists {
				if ok && value != peer {
					return invalid(fixturePrivate, spec.name)
				}
				value, ok = peer, true
			}
		}
		if !ok {
			value = spec.generate()
		}
		if !spec.valid(value) {
			return invalid(spec.id, spec.name)
		}
		result[spec.id][spec.name] = value
		if spec.name == "bot-token" {
			result[fixturePrivate][spec.name] = value
		}
	}
	if result[iamPrivate]["sealer.key"] == result[reconPrivate]["sealer.key"] {
		return errors.New("IAM and reconciliation sealer keys must be independent")
	}
	return nil
}
