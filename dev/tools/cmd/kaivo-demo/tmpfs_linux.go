package main

import "syscall"

func isTmpfs(dir string) bool {
	var fs syscall.Statfs_t
	return syscall.Statfs(dir, &fs) == nil && fs.Type == 0x01021994
}
