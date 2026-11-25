package main

import "syscall"

func isTmpfs(dir string) bool {
	var fs syscall.Statfs_t
	return syscall.Statfs(dir, &fs) == nil && fs.Fstypename == [16]int8{'t', 'm', 'p', 'f', 's'}
}
