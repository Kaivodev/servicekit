//go:build !linux && !darwin

package main

func isTmpfs(string) bool { return false }
