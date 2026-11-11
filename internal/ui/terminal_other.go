//go:build !linux && !windows

package ui

import "os"

func enterRawInput(_ *os.File) (func(), bool)  { return nil, false }
func terminalDimensions(_ *os.File) (int, int) { return 80, 30 }
