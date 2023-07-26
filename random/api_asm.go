//go:build amd64 && !gmnosam
// +build amd64,!gmnosam

package random

import (
	"crypto/rand"
	"io"
	"runtime"

	"golang.org/x/sys/cpu"
)

/*
API
func RandUint64() uint64
func Rand(out []byte) (n int)
var Reader io.Reader
*/

//Reader reader for random
var Reader io.Reader

//RandUint64 get a random uint64
var RandUint64 func() uint64

//Rand generate random 8 bytes every time, asm
var Rand func(out []byte) (n int)

func init() {
	if cpu.X86.HasRDRAND {
		Reader = readerStruct_asm{}
		RandUint64 = randUint64_64bit
		Rand = rand_64bit

		buf = make(chan *[8]uint64, 1024)

		go func() {
			runtime.LockOSThread()
			for {
				e := pool.Get().(*[8]uint64)
				e[0], e[1], e[2], e[3] = randUint64_64bit(), randUint64_64bit(), randUint64_64bit(), randUint64_64bit()
				e[4], e[5], e[6], e[7] = randUint64_64bit(), randUint64_64bit(), randUint64_64bit(), randUint64_64bit()
				buf <- e
			}
		}()
		return
	}
	Reader = rand.Reader
	RandUint64 = randUint64_32bit
	Rand = rand_32bit
}
