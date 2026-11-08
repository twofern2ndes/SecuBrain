//go:build windows

package ui

import (
	"os"
	"syscall"
	"unsafe"
)

const enableVirtualTerminalProcessing = 0x0004

func enableColors(f *os.File) bool {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	getMode := kernel.NewProc("GetConsoleMode")
	setMode := kernel.NewProc("SetConsoleMode")
	var mode uint32
	handle := uintptr(f.Fd())
	ok, _, _ := getMode.Call(handle, uintptr(unsafe.Pointer(&mode)))
	if ok == 0 {
		return false
	}
	ok, _, _ = setMode.Call(handle, uintptr(mode|enableVirtualTerminalProcessing))
	return ok != 0
}
