//go:build unix

package main

import (
	"os"
	"syscall"
)

// privateDir reports whether dir is a directory owned by the current user that
// no other user can read, write or traverse (mode 0700).
func privateDir(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
