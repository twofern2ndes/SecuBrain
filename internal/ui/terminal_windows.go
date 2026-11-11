//go:build windows

package ui

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	winEnableLineInput      = 0x0002
	winEnableEchoInput      = 0x0004
	winEnableProcessedInput = 0x0001
	winEnableVTInput        = 0x0200
)

func enterRawInput(f *os.File) (func(), bool) {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	get := kernel.NewProc("GetConsoleMode")
	set := kernel.NewProc("SetConsoleMode")
	var original uint32
	ok, _, _ := get.Call(f.Fd(), uintptr(unsafe.Pointer(&original)))
	if ok == 0 {
		return nil, false
	}
	updated := (original &^ (winEnableLineInput | winEnableEchoInput | winEnableProcessedInput)) | winEnableVTInput
	ok, _, _ = set.Call(f.Fd(), uintptr(updated))
	if ok == 0 {
		// Older Windows consoles may not support VT input; still handle basic
		// printable characters and Enter without changing console modes.
		return nil, false
	}
	return func() { _, _, _ = set.Call(f.Fd(), uintptr(original)) }, true
}

func terminalDimensions(out *os.File) (int, int) {
	type coord struct{ X, Y int16 }
	type rect struct{ Left, Top, Right, Bottom int16 }
	var info struct {
		Size, Cursor coord
		Attributes   uint16
		Window       rect
		Max          coord
	}
	k := syscall.NewLazyDLL("kernel32.dll")
	ok, _, _ := k.NewProc("GetConsoleScreenBufferInfo").Call(out.Fd(), uintptr(unsafe.Pointer(&info)))
	if ok != 0 {
		return int(info.Window.Right - info.Window.Left + 1), int(info.Window.Bottom - info.Window.Top + 1)
	}
	return 80, 30
}
