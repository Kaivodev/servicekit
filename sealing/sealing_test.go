package sealing

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Kaivodev/servicekit/config"
)

const firstFile = `{"format":"kaivo.sealing.v1","service":"sample","purpose":"data","current":1,"keys":[{"version":1,"wrapped":"YQ=="}]}`

type unwrapFunc func(ciphertext, aad []byte) ([]byte, error)

func (f unwrapFunc) Decrypt(_ context.Context, ciphertext, aad []byte) ([]byte, error) {
	return f(ciphertext, aad)
}

type wrapFunc func(key, aad []byte) ([]byte, error)

func (f wrapFunc) Encrypt(_ context.Context, key, aad []byte) ([]byte, error) { return f(key, aad) }

func writeFile(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ring.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestKeyringRotation(t *testing.T) {
	material := bytes.Repeat([]byte{0x24}, 32)
	first, err := Development(config.Development, material)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(first.Close)
	msg, aad := []byte("sample"), []byte("record-7")
	old, err := first.Seal(msg, aad)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(firstFile)
	rotated, err := AppendWrappedKey(input, WrappedKey{Version: 2, Wrapped: "Yg=="})
	if err != nil || string(input) != firstFile {
		t.Fatal("append", err)
	}
	var calls int
	ring, err := Load(t.Context(), writeFile(t, rotated), "sample", "data", unwrapFunc(func(ct, aad []byte) ([]byte, error) {
		calls++
		if string(aad) != fmt.Sprintf("kaivo:sample:data:v%d", calls) || len(ct) != 1 || ct[0] != "ab"[calls-1] {
			t.Fatal("wrong unwrap request")
		}
		// Equal raw keys exercise explicit version binding in GCM and HKDF.
		return bytes.Clone(material), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	if calls != 2 || ring.Current() != 2 || !slices.Equal(ring.Versions(), []uint32{1, 2}) {
		t.Fatal("rotation lost a version")
	}
	ct, err := ring.Seal(msg, aad)
	if err != nil || len(ct) != len(msg)+5+12+16 || ct[0] != 1 || binary.BigEndian.Uint32(ct[1:5]) != 2 {
		t.Fatal("invalid seal format", err)
	}
	again, err := ring.Seal(msg, aad)
	if err != nil || bytes.Equal(ct, again) {
		t.Fatal("nonce reuse", err)
	}
	for _, data := range [][]byte{ct, old} {
		plain, err := ring.Open(data, aad)
		if err != nil || !bytes.Equal(plain, msg) {
			t.Fatal("open", err)
		}
	}
	// Verify the wire format with a separate standard-library GCM.
	block, _ := aes.NewCipher(material)
	gcm, _ := cipher.NewGCM(block)
	if plain, err := gcm.Open(nil, ct[5:17], ct[17:], slices.Concat(ct[:5], aad)); err != nil || !bytes.Equal(plain, msg) {
		t.Fatal("wire format mismatch", err)
	}
	if _, err := ring.Open(ct, []byte("record-8")); err == nil {
		t.Fatal("wrong AAD accepted")
	}
	for _, i := range []int{0, 4, 5, len(ct) - 1} {
		bad := bytes.Clone(ct)
		bad[i] ^= 3
		if _, err := ring.Open(bad, aad); err == nil {
			t.Fatalf("tampering at byte %d accepted", i)
		}
	}
	unknown := bytes.Clone(ct)
	unknown[4] = 9
	if _, err := ring.Open(unknown, aad); err == nil {
		t.Fatal("unknown version accepted")
	}
	for _, n := range []int{0, 1, 4, 5, 16, 32} {
		if _, err := ring.Open(ct[:n], aad); err == nil {
			t.Fatal("truncation accepted")
		}
	}
	derived, err := ring.Derive(1, "mac", 32)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hkdf.Key(sha256.New, material, []byte{0, 0, 0, 1}, "mac", 32)
	same, _ := first.Derive(1, "mac", 32)
	next, _ := ring.Derive(2, "mac", 32)
	other, _ := ring.Derive(1, "cursor", 32)
	if !bytes.Equal(derived, want) || !bytes.Equal(derived, same) || bytes.Equal(derived, next) || bytes.Equal(derived, other) {
		t.Fatal("HKDF domain separation failed")
	}
	for _, n := range []int{-1, 0, 8161} {
		if _, err := ring.Derive(1, "mac", n); err == nil {
			t.Fatal("invalid HKDF length accepted")
		}
	}
	if _, err := ring.Derive(3, "mac", 32); err == nil {
		t.Fatal("unknown HKDF version accepted")
	}
}

func TestWrappedFileValidation(t *testing.T) {
	invalid := map[string]string{
		"format":                   strings.ReplaceAll(firstFile, "kaivo.sealing.v1", "other"),
		"service":                  strings.ReplaceAll(firstFile, "sample", "Sample"),
		"purpose":                  strings.ReplaceAll(firstFile, `"data"`, `"-field"`),
		"long label":               strings.ReplaceAll(firstFile, "sample", strings.Repeat("s", 33)),
		"unknown":                  strings.ReplaceAll(firstFile, `"current":`, `"extra":null,"current":`),
		"nested unknown":           strings.ReplaceAll(firstFile, `"wrapped":`, `"extra":null,"wrapped":`),
		"case":                     strings.ReplaceAll(firstFile, `"version"`, `"Version"`),
		"duplicate member":         strings.ReplaceAll(firstFile, `"current":`, `"current":1,"current":`),
		"duplicate version member": strings.ReplaceAll(firstFile, `"version":`, `"version":1,"version":`),
		"duplicate key":            strings.ReplaceAll(firstFile, `"keys":[`, `"keys":[{"version":1,"wrapped":"Yg=="},`),
		"zero":                     strings.ReplaceAll(firstFile, `"version":1`, `"version":0`),
		"negative":                 strings.ReplaceAll(firstFile, `"version":1`, `"version":-1`),
		"overflow":                 strings.ReplaceAll(firstFile, `"version":1`, `"version":2147483648`),
		"no current key":           strings.ReplaceAll(firstFile, `"current":1`, `"current":2`),
		"missing current":          strings.ReplaceAll(firstFile, `"current":1,`, ""),
		"null list":                strings.ReplaceAll(firstFile, `[{"version":1,"wrapped":"YQ=="}]`, "null"),
		"base64":                   strings.ReplaceAll(firstFile, "YQ==", "-g=="),
		"noncanonical base64":      strings.ReplaceAll(firstFile, "YQ==", "YR=="),
		"empty":                    strings.ReplaceAll(firstFile, "YQ==", ""),
		"base64 newline":           strings.ReplaceAll(firstFile, "YQ==", `YQ==\n`),
		"trailing":                 firstFile + "{}",
		"oversize":                 firstFile + strings.Repeat(" ", maxFileSize),
	}
	u := unwrapFunc(func([]byte, []byte) ([]byte, error) { t.Fatal("unwrapped before validation"); return nil, nil })
	for name, doc := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(t.Context(), writeFile(t, []byte(doc)), "sample", "data", u); err == nil {
				t.Fatal("invalid file accepted")
			}
		})
	}
	path := writeFile(t, []byte(firstFile))
	for _, identity := range [][2]string{{"wrong", "data"}, {"sample", "wrong"}} {
		if _, err := Load(t.Context(), path, identity[0], identity[1], u); err == nil {
			t.Fatal("identity mismatch accepted")
		}
	}
	for _, entry := range []WrappedKey{{1, "Yg=="}, {2, ""}, {1 << 31, "YQ=="}, {2, base64.StdEncoding.EncodeToString(make([]byte, maxFileSize))}} {
		if _, err := AppendWrappedKey([]byte(firstFile), entry); err == nil {
			t.Fatal("invalid append accepted")
		}
	}
	for _, n := range []int{0, 31, 33} {
		bad := bytes.Repeat([]byte{1}, n)
		_, err := Load(t.Context(), path, "sample", "data", unwrapFunc(func([]byte, []byte) ([]byte, error) { return bad, nil }))
		if err == nil || !bytes.Equal(bad, make([]byte, n)) {
			t.Fatal("invalid key length or failed cleanup")
		}
		if _, err := Development(config.Development, bad); err == nil {
			t.Fatal("invalid development key accepted")
		}
	}
}

func TestNewWrappedKeyWipesPlaintext(t *testing.T) {
	var seen, previous []byte
	for _, fail := range []bool{false, false, true} {
		entry, err := NewWrappedKey(t.Context(), wrapFunc(func(key, aad []byte) ([]byte, error) {
			seen = key
			if len(key) != 32 || bytes.Equal(key, make([]byte, 32)) || bytes.Equal(key, previous) || string(aad) != "kaivo:sample:data:v42" {
				t.Fatal("invalid generated key or AAD")
			}
			previous = bytes.Clone(key)
			if fail {
				return nil, errors.New("private provider error")
			}
			return []byte("wrapped"), nil
		}), "sample", "data", 42)
		if !bytes.Equal(seen, make([]byte, 32)) {
			t.Fatal("generated key still in memory")
		}
		if fail {
			if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("provider error leaked")
			}
		} else if err != nil || entry != (WrappedKey{42, base64.StdEncoding.EncodeToString([]byte("wrapped"))}) {
			t.Fatal("wrong entry", err)
		}
	}
}

func TestCloseConcurrent(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	ring, err := Development(config.Development, key)
	if err != nil {
		t.Fatal(err)
	}
	retained := ring.keys[1]
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() { _, _ = ring.Seal(nil, nil); _, _ = ring.Derive(1, "mac", 32); ring.Versions(); ring.Current() })
	}
	ring.Close()
	wg.Wait()
	ring.Close()
	if _, err := ring.Seal(nil, nil); err == nil {
		t.Fatal("closed ring sealed")
	}
	if _, err := ring.Derive(1, "mac", 32); err == nil {
		t.Fatal("closed ring derived")
	}
	if ring.Current() != 0 || len(ring.Versions()) != 0 || !bytes.Equal(retained, make([]byte, 32)) || key[0] != 1 {
		t.Fatal("key ownership or cleanup failure")
	}
}

func TestDevelopmentEnvironment(t *testing.T) {
	for _, env := range []config.Environment{"", "production", "staging", config.Test} {
		if _, err := Development(env, make([]byte, 32)); err == nil {
			t.Fatalf("development key accepted for %q", env)
		}
	}
}

func TestNewKeyFile(t *testing.T) {
	entry := WrappedKey{Version: 3, Wrapped: "YQ=="}
	data, err := NewKeyFile("sample", "data", entry)
	if err != nil {
		t.Fatal(err)
	}
	file, err := parse(data)
	if err != nil || file.Current != 3 || len(file.Keys) != 1 || file.Keys[0] != entry || file.Service != "sample" || file.Purpose != "data" {
		t.Fatal("new key file does not round-trip")
	}
	for _, bad := range []struct {
		service, purpose string
		entry            WrappedKey
	}{{"Sample", "data", entry}, {"sample", "", entry}, {"sample", "data", WrappedKey{Version: 0, Wrapped: "YQ=="}}, {"sample", "data", WrappedKey{Version: 1, Wrapped: "%%"}}} {
		if _, err := NewKeyFile(bad.service, bad.purpose, bad.entry); err == nil {
			t.Fatal("invalid key file accepted")
		}
	}
}
