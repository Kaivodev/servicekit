package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"fmt"
	"path/filepath"

	"github.com/Kaivodev/servicekit/sealing"
	"github.com/Kaivodev/servicekit/signing"
)

// Only verified public keys and the original wrapped file bytes reach the seed.
type kmsMaterials struct {
	registries      map[string]publicKeys
	reportKID       string
	platformKey     *rsa.PublicKey
	platformVersion string
	wrapped         map[string]fields // service to filename and original content
}

func loadKMSDir(dir string) (*kmsMaterials, error) {
	spec, err := readKMSSpec(filepath.Join(dir, "keys.json"))
	if err != nil {
		return nil, err
	}
	m := &kmsMaterials{registries: map[string]publicKeys{}, wrapped: map[string]fields{}}
	for service, entries := range spec.Services {
		var export kmsExport
		if err := readKMSJSON(filepath.Join(dir, "exports", service+".json"), &export); err != nil {
			return nil, fmt.Errorf("KMS %s export: %w", service, err)
		}
		if export.Format != exportFormat || export.Service != service || export.Public == nil || export.Sealing == nil ||
			len(export.Public) != len(entries.Signing) || len(export.Sealing) != len(entries.Sealing) ||
			(export.Platform != nil) != (entries.Platform.Key != "") {
			return nil, fmt.Errorf("KMS %s export does not match spec", service)
		}
		if platform := export.Platform; platform != nil {
			pub, err := x509.ParsePKIXPublicKey(pemDER(platform.Content, "PUBLIC KEY"))
			key, ok := pub.(*rsa.PublicKey)
			if platform.Key != entries.Platform.Key || err != nil || !ok || key.N.BitLen() < 2048 {
				return nil, fmt.Errorf("invalid KMS %s platform export", service)
			}
			m.platformKey, m.platformVersion = key, platform.Key
		}
		for i, entry := range export.Public {
			if entry.signingSpec != entries.Signing[i] {
				return nil, fmt.Errorf("KMS %s public[%d] does not match spec", service, i)
			}
			set, err := signing.ParseJWKS(entry.JWKS)
			key, ok := set.Lookup(entry.KID)
			if err != nil || !ok || set.Len() != 1 {
				return nil, fmt.Errorf("invalid KMS %s public[%d] JWKS", service, i)
			}
			if m.registries[entry.Registry] == nil {
				m.registries[entry.Registry] = publicKeys{}
			}
			m.registries[entry.Registry][entry.KID] = key
			if entry.PEM != "" {
				m.reportKID = entry.KID
			}
		}
		m.wrapped[service] = fields{}
		for i, entry := range export.Sealing {
			if entry.sealingSpec != entries.Sealing[i] || !validWrappedFile(entry.Content, service, entry.Purpose) {
				return nil, fmt.Errorf("invalid KMS %s sealing[%d] export", service, i)
			}
			m.wrapped[service][entry.File] = entry.Content
		}
	}
	return m, nil
}

// sealing.Load requires decryption. Validate the public envelope and use the
// sealing package's version, label and ciphertext checks for each entry offline.
func validWrappedFile(content, service, purpose string) bool {
	var f struct {
		Format  string               `json:"format"`
		Service string               `json:"service"`
		Purpose string               `json:"purpose"`
		Current uint32               `json:"current"`
		Keys    []sealing.WrappedKey `json:"keys"`
	}
	if len(content) > 64<<10 || json.Unmarshal([]byte(content), &f, json.RejectUnknownMembers(true)) != nil ||
		f.Format != "kaivo.sealing.v1" || f.Service != service || f.Purpose != purpose {
		return false
	}
	versions := map[uint32]bool{}
	for _, key := range f.Keys {
		if _, err := sealing.NewKeyFile(service, purpose, key); err != nil || versions[key.Version] {
			return false
		}
		versions[key.Version] = true
	}
	return versions[f.Current]
}

func (m *kmsMaterials) seedWrappedFiles(old, result materials) error {
	for service, policy := range kmsServices {
		for name := range policy.sealingFiles {
			content, present := m.wrapped[service][name]
			if saved, exists := old[policy.inputs][name]; exists && (!present || saved != content) {
				return invalid(policy.inputs, name)
			}
			if present {
				result[policy.inputs][name] = content
			}
		}
	}
	return nil
}
