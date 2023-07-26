//go:build !amd64 || gmnosam
// +build !amd64 gmnosam

package random

import "crypto/rand"

/*
API
func RandUint64() uint64
func Rand(out []byte) (n int)
var Reader io.Reader
*/

func RandUint64() uint64 {
	return randUint64_32bit()
}

func Rand(out []byte) (n int) {
	return rand_32bit(out)
}

var Reader = rand.Reader
