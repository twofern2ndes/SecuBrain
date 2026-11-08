//go:build !windows

package ui

import "os"

// Unix-like terminals recognize ANSI control sequences without extra setup.
func enableColors(_ *os.File) bool { return true }
