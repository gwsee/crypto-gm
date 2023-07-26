package random

import (
	"sync"
	"unsafe"
)

/*
func RandUint64() uint64 => randUint64_64bit
func Rand(out []byte) (n int) => rand_64bit
var Reader io.Reader => readerStruct_asm
*/

//nolint
func randUint64_64bit() uint64

//nolint
func rand_64bit(out []byte) (n int)

//nolint
type readerStruct_asm struct {
}

var pool = sync.Pool{
	New: func() interface{} {
		return new([8]uint64)
	},
}

var buf chan *[8]uint64

//Read 使用rdrand指令生成随机数到输入的slice中
func (r readerStruct_asm) Read(out []byte) (int, error) {
	l := len(out)
	n := (l + 63) >> 6
	for n > 1 {
		s := <-buf
		t := (*[8]uint64)(unsafe.Pointer(&out[l-64 : l][0]))
		t[0], t[1], t[2], t[3] = s[0], s[1], s[2], s[3]
		t[4], t[5], t[6], t[7] = s[4], s[5], s[6], s[7]
		l -= 64
		n--
		pool.Put(s)
	}

	s := <-buf
	a := (*[64]byte)(unsafe.Pointer(s))[:]
	copy(out[:l], a[:l])
	pool.Put(s)
	return len(out), nil
}
