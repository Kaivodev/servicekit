//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if !privateDir(dir) {
		t.Fatal("0700 directory owned by the caller should be private")
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if privateDir(dir) {
		t.Fatal("group-readable directory accepted")
	}
	if privateDir(filepath.Join(dir, "missing")) {
		t.Fatal("missing directory accepted")
	}
}
