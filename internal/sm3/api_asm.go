//go:build amd64 && !gmnosam
// +build amd64,!gmnosam

package sm3

import "golang.org/x/sys/cpu"

func init() {
	if cpu.X86.HasSSE2 && cpu.X86.HasBMI2 && cpu.X86.HasSSE42 && cpu.X86.HasSSE41 {
		update = update_64bit
	} else {
		update = update_32bit
	}
}

var update func(digest *[8]uint32, a []byte, b []byte)
