//go:build linux

package ui

import (
	"os"
	"syscall"
	"unsafe"
)

func enterRawInput(f *os.File) (func(), bool) {
	fd := f.Fd()
	var old syscall.Termios
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&old))); err != 0 {
		return nil, false
	}
	raw := old
	raw.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Iflag &^= syscall.IXON | syscall.ICRNL
	raw.Oflag &^= syscall.OPOST
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&raw))); err != 0 {
		return nil, false
	}
	return func() {
		_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&old)))
	}, true
}

func terminalDimensions(out *os.File) (int, int) {
	var size struct{ row, col, xpixel, ypixel uint16 }
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, out.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&size))); err == 0 && size.col > 0 && size.row > 0 {
		return int(size.col), int(size.row)
	}
	return 80, 30
}
