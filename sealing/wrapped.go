package sealing

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strings"
)

const (
	format      = "kaivo.sealing.v1"
	maxFileSize = 64 << 10
)

var (
	label   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	errFile = errors.New("invalid wrapped key file")
)

// Unwrapper transfers ownership of each returned plaintext buffer to the caller.
type Unwrapper interface {
	Decrypt(ctx context.Context, ciphertext, aad []byte) ([]byte, error)
}

// Wrapper encrypts a data key with its service, purpose and version as AAD.
type Wrapper interface {
	Encrypt(ctx context.Context, plaintext, aad []byte) ([]byte, error)
}

// WrappedKey is one entry in the keys array. Wrapped is standard padded base64.
type WrappedKey struct {
	Version uint32 `json:"version"`
	Wrapped string `json:"wrapped"`
}

type keyFile struct {
	Format  string       `json:"format"`
	Service string       `json:"service"`
	Purpose string       `json:"purpose"`
	Current uint32       `json:"current"`
	Keys    []WrappedKey `json:"keys"`
}

func keyAAD(service, purpose string, version uint32) []byte {
	return fmt.Appendf(nil, "kaivo:%s:%s:v%d", service, purpose, version)
}

func validVersion(version uint32) bool { return version >= 1 && version <= math.MaxInt32 }

func (entry WrappedKey) decode() ([]byte, error) {
	if !validVersion(entry.Version) || entry.Wrapped == "" || len(entry.Wrapped) > maxFileSize || strings.ContainsAny(entry.Wrapped, "\r\n") {
		return nil, errFile
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(entry.Wrapped)
	if err != nil {
		return nil, errFile
	}
	return ciphertext, nil
}

// object decodes exactly the named fields once each. RawMessage preserves the
// original spelling and duplicate members of nested objects for the next pass.
func object(data []byte, fields map[string]any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	if tok, err := d.Token(); err != nil || tok != json.Delim('{') {
		return errFile
	}
	for d.More() {
		tok, err := d.Token()
		name, ok := tok.(string)
		dest := fields[name]
		if err != nil || !ok || dest == nil || d.Decode(dest) != nil {
			return errFile
		}
		delete(fields, name)
	}
	if tok, err := d.Token(); err != nil || tok != json.Delim('}') || len(fields) != 0 {
		return errFile
	}
	if _, err := d.Token(); err != io.EOF {
		return errFile
	}
	return nil
}

func parse(data []byte) (*keyFile, error) {
	if len(data) > maxFileSize {
		return nil, errFile
	}
	var file keyFile
	var entries []json.RawMessage
	if err := object(data, map[string]any{"format": &file.Format, "service": &file.Service, "purpose": &file.Purpose, "current": &file.Current, "keys": &entries}); err != nil {
		return nil, err
	}
	if file.Format != format || !label.MatchString(file.Service) || !label.MatchString(file.Purpose) {
		return nil, errFile
	}
	seen := make(map[uint32]bool, len(entries))
	for _, data := range entries {
		var entry WrappedKey
		if err := object(data, map[string]any{"version": &entry.Version, "wrapped": &entry.Wrapped}); err != nil {
			return nil, err
		}
		if _, err := entry.decode(); err != nil || seen[entry.Version] {
			return nil, errFile
		}
		seen[entry.Version] = true
		file.Keys = append(file.Keys, entry)
	}
	if !seen[file.Current] {
		return nil, errFile
	}
	return &file, nil
}

// Load validates the entire file and expected identity before unwrapping keys.
func Load(ctx context.Context, path, service, purpose string, u Unwrapper) (*Keyring, error) {
	if u == nil {
		return nil, errors.New("missing key unwrapper")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open wrapped key file failed")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, errors.New("read wrapped key file failed")
	}
	file, err := parse(data)
	if err != nil {
		return nil, err
	}
	if service != file.Service || purpose != file.Purpose {
		return nil, errors.New("wrapped key file identity mismatch")
	}
	ring := &Keyring{current: file.Current, keys: make(map[uint32][]byte, len(file.Keys))}
	for _, entry := range file.Keys {
		if err := ctx.Err(); err != nil {
			ring.Close()
			return nil, err
		}
		ciphertext, _ := entry.decode() // Validated before any unwrap.
		plain, err := u.Decrypt(ctx, ciphertext, keyAAD(service, purpose, entry.Version))
		if err != nil || len(plain) != keySize || ctx.Err() != nil {
			clear(plain)
			ring.Close()
			return nil, errors.New("unwrap service key failed")
		}
		ring.keys[entry.Version] = bytes.Clone(plain)
		clear(plain)
	}
	return ring, nil
}

// NewWrappedKey generates and wraps a random 32-byte key, then clears it.
func NewWrappedKey(ctx context.Context, w Wrapper, service, purpose string, version uint32) (WrappedKey, error) {
	if w == nil || !label.MatchString(service) || !label.MatchString(purpose) || !validVersion(version) {
		return WrappedKey{}, errors.New("invalid wrapping configuration")
	}
	if err := ctx.Err(); err != nil {
		return WrappedKey{}, err
	}
	key := make([]byte, keySize)
	defer clear(key)
	if _, err := rand.Read(key); err != nil {
		return WrappedKey{}, errors.New("generate service key failed")
	}
	ciphertext, err := w.Encrypt(ctx, key, keyAAD(service, purpose, version))
	if err != nil || len(ciphertext) == 0 {
		return WrappedKey{}, errors.New("wrap service key failed")
	}
	return WrappedKey{Version: version, Wrapped: base64.StdEncoding.EncodeToString(ciphertext)}, nil
}

// NewKeyFile returns a file holding entry as its only and current key.
func NewKeyFile(service, purpose string, entry WrappedKey) ([]byte, error) {
	if !label.MatchString(service) || !label.MatchString(purpose) {
		return nil, errFile
	}
	if _, err := entry.decode(); err != nil {
		return nil, err
	}
	result, err := json.Marshal(keyFile{Format: format, Service: service, Purpose: purpose, Current: entry.Version, Keys: []WrappedKey{entry}})
	if err != nil || len(result) > maxFileSize {
		return nil, errFile
	}
	return result, nil
}

// AppendWrappedKey returns a new file with entry added and promoted to current.
// The caller owns file persistence and coordination between writers.
func AppendWrappedKey(data []byte, entry WrappedKey) ([]byte, error) {
	file, err := parse(data)
	if err != nil {
		return nil, err
	}
	if _, err := entry.decode(); err != nil {
		return nil, err
	}
	for _, old := range file.Keys {
		if old.Version == entry.Version {
			return nil, errors.New("wrapped key version already exists")
		}
	}
	file.Keys = append(file.Keys, entry)
	file.Current = entry.Version
	result, err := json.Marshal(file)
	if err != nil || len(result) > maxFileSize {
		return nil, errFile
	}
	return result, nil
}
