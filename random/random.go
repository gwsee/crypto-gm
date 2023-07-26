package random

import (
	"crypto/rand"
	"unsafe"
)

/*
func RandUint64() uint64 => randUint64_32bit
func Rand(out []byte) (n int) => rand_32bit
var Reader io.Reader => rand.Reader
*/

//nolint
func randUint64_32bit() uint64 {
	var a uint64
	_, _ = rand.Read((*[8]byte)(unsafe.Pointer(&a))[:])
	return a
}

//nolint
func rand_32bit(out []byte) (n int) {
	n, _ = rand.Read(out)
	return
}
