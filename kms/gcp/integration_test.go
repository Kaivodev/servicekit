package gcp_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"os"
	"testing"

	"github.com/Kaivodev/servicekit/kms/gcp"
	"github.com/Kaivodev/servicekit/signing"
)

// Each live test opts in independently and uses workload ADC.
func TestLiveSigningKey(t *testing.T) {
	name := os.Getenv("AIPAY_GCPKMS_TEST_SIGNING_KEY")
	if name == "" {
		t.Skip("AIPAY_GCPKMS_TEST_SIGNING_KEY is unset")
	}
	c, err := gcp.New(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	key, err := c.SigningKey(name)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("servicekit integration test")
	switch pub.(type) {
	case *ecdsa.PublicKey:
		s, err := signing.NewKMS(t.Context(), "test", key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.Sign(t.Context(), msg)
		if err != nil {
			t.Fatal(err)
		}
	case *rsa.PublicKey:
		s, err := signing.NewRSAKMS(t.Context(), "test", key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.Sign(t.Context(), msg)
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unexpected signing algorithm")
	}
}

func TestLiveSymmetricKey(t *testing.T) {
	name := os.Getenv("AIPAY_GCPKMS_TEST_SYMMETRIC_KEY")
	if name == "" {
		t.Skip("AIPAY_GCPKMS_TEST_SYMMETRIC_KEY is unset")
	}
	c, err := gcp.New(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	key, err := c.SymmetricKey(name)
	if err != nil {
		t.Fatal(err)
	}
	msg, aad := []byte("servicekit test key"), []byte("kaivo:sample:test:v1")
	ct, err := key.Encrypt(t.Context(), msg, aad)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := key.Decrypt(t.Context(), ct, aad)
	if err != nil || !bytes.Equal(plain, msg) {
		t.Fatal("KMS round trip failed", err)
	}
}
