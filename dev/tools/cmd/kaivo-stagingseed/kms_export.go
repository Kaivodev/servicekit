package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Kaivodev/servicekit/kms/gcp"
	"github.com/Kaivodev/servicekit/sealing"
	"github.com/Kaivodev/servicekit/signing"
)

type kmsExport struct {
	Format  string          `json:"format"`
	Service string          `json:"service"`
	Public  []publicExport  `json:"public"`
	Sealing []sealingExport `json:"sealing"`
}

type publicExport struct {
	signingSpec
	JWKS json.RawMessage `json:"jwks"`
}

type sealingExport struct {
	sealingSpec
	Content string `json:"content"`
}

type publicKeys = map[string]*ecdsa.PublicKey

func exportKMS(ctx context.Context, service string, out io.Writer) error {
	path := os.Getenv("KAIVO_KMS_SPEC_FILE")
	if path == "" {
		return errors.New("KAIVO_KMS_SPEC_FILE is required")
	}
	spec, err := readKMSSpec(path)
	if err != nil {
		return err
	}
	entries, ok := spec.Services[service]
	if !ok {
		return errors.New("service missing from KMS spec")
	}
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
		return errors.New("GOOGLE_APPLICATION_CREDENTIALS is required")
	}
	client, err := gcp.New(ctx)
	if err != nil {
		return errors.New("load KMS credentials failed")
	}
	export := kmsExport{Format: exportFormat, Service: service, Public: []publicExport{}, Sealing: []sealingExport{}}
	for i, entry := range entries.Signing {
		key, err := client.SigningKey(entry.Key)
		if err != nil {
			return err
		}
		pub, err := key.PublicKey(ctx)
		if err != nil {
			return fmt.Errorf("KMS %s signing[%d]: %w", service, i, err)
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok || ec.Curve != elliptic.P256() {
			return fmt.Errorf("KMS %s signing[%d] requires P-256", service, i)
		}
		jwks, err := signing.MarshalJWKS(publicKeys{entry.KID: ec})
		if err != nil {
			return err
		}
		export.Public = append(export.Public, publicExport{entry, jwks})
	}
	for i, entry := range entries.Sealing {
		kek, err := client.SymmetricKey(entry.KEK)
		if err != nil {
			return err
		}
		wrapped, err := sealing.NewWrappedKey(ctx, kek, service, entry.Purpose, 1)
		if err != nil {
			return fmt.Errorf("KMS %s sealing[%d]: %w", service, i, err)
		}
		content, err := sealing.NewKeyFile(service, entry.Purpose, wrapped)
		if err != nil {
			return err
		}
		if err := verifyWrappedFile(ctx, content, service, entry.Purpose, kek); err != nil {
			return fmt.Errorf("KMS %s sealing[%d]: %w", service, i, err)
		}
		export.Sealing = append(export.Sealing, sealingExport{entry, string(content)})
	}
	if err := json.NewEncoder(out).Encode(export); err != nil {
		return errors.New("write KMS export failed")
	}
	return nil
}

func verifyWrappedFile(ctx context.Context, content []byte, service, purpose string, kek sealing.Unwrapper) error {
	f, err := os.CreateTemp("", "kaivo-wrapped-*")
	if err != nil {
		return errors.New("create temporary wrapped key file failed")
	}
	defer os.Remove(f.Name())
	_, err = f.Write(content)
	if closeErr := f.Close(); err != nil || closeErr != nil {
		return errors.New("write temporary wrapped key file failed")
	}
	ring, err := sealing.Load(ctx, f.Name(), service, purpose, kek)
	if err != nil {
		return err
	}
	ring.Close()
	return nil
}
