package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/Kaivodev/servicekit/signing"
)

// Keep each service's private material in its own directory. Only public/ is shared.
func generateSigningKeys(dir string, services []string) error {
	if err := os.Mkdir(filepath.Join(dir, "public"), 0700); err != nil {
		return err
	}
	for _, name := range services {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(filepath.Join(dir, name, "signing.pem"), block, 0600); err != nil {
			return err
		}
		data, err := signing.MarshalJWKS(map[string]*ecdsa.PublicKey{name + "-dev": &key.PublicKey})
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "public", name+".jwks"), data, 0600); err != nil {
			return err
		}
	}
	return nil
}
