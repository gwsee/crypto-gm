package cuda

/*
//#cgo LDFLAGS: -L/usr/local/lib -L/usr/lib -L./ -lsm2cuda
//#cgo CFLAGS: -std=c99
#cgo linux LDFLAGS: -ldl
#include <dlfcn.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>

#include <stdio.h>

static uintptr_t pluginOpen(const char* path, char** err) {
	void* h = dlopen(path, RTLD_NOW|RTLD_GLOBAL);
	if (h == NULL) {
		*err = (char*)dlerror();
	}
	return (uintptr_t)h;
}

static void* pluginLookup(uintptr_t h, const char* name, char** err) {
	void* r = dlsym((void*)h, name);
	if (r == NULL) {
		*err = (char*)dlerror();
	}
	return r;
}

//cuda相关接口
#include <stdint.h>
#include <string.h>
typedef uint32_t xint;
#define B256N 8
typedef xint B256D[B256N];
const char * symbol_init_sm2cuda = "init_sm2cuda";
const char * symbol_sm2ver_cuda = "sm2ver_cuda";

// start
typedef int(* CUDA_INIT)(); //int init_sm2cuda();
// num: to reach the best performance, num should be n*k, where n, k is a interger
// for Tesla K40, k is 270.
typedef void(* CUDA_VERIFY)(xint*, int, unsigned char*); //void sm2ver_cuda(xint* data, int num, unsigned char* ret);
int(* global_cuda_init)();
void(* global_cuda_verify)(xint*, int, unsigned char*);
void signal_catchfunc(int);

int call_init_sm2cuda(){
	return global_cuda_init();
}

//0:success, 1:fail
void call_sm2ver_cuda(xint* data, int num, unsigned char* ret){
	global_cuda_verify(data, num, ret);
}
*/
import "C"
import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"unsafe"
)

var cudaEnable int32
var cudaEnableOnce sync.Once

func open(name string) error {
	cPath := make([]byte, C.PATH_MAX+1)
	cRelName := make([]byte, len(name)+1)
	copy(cRelName, name)
	if C.realpath(
		(*C.char)(unsafe.Pointer(&cRelName[0])),
		(*C.char)(unsafe.Pointer(&cPath[0]))) == nil {
		return errors.New(`open("` + name + `"): realpath failed`)
	}

	var cErr *C.char
	handler := C.pluginOpen((*C.char)(unsafe.Pointer(&cPath[0])), &cErr)
	if handler == 0 {
		return errors.New(`Open("` + name + `"): ` + C.GoString(cErr))
	}

	C.global_cuda_init = (C.CUDA_INIT)(C.pluginLookup(handler, C.symbol_init_sm2cuda, &cErr))
	if C.global_cuda_init == nil {
		return errors.New(`get cuda_init err: ` + C.GoString(cErr))
	}
	C.global_cuda_verify = (C.CUDA_VERIFY)(C.pluginLookup(handler, C.symbol_sm2ver_cuda, &cErr))
	if C.global_cuda_verify == nil {
		return errors.New(`get sm2ver_cuda err: ` + C.GoString(cErr))
	}
	if err := initAndSelfTest(); err != nil {
		return err
	}
	atomic.StoreInt32(&cudaEnable, 1)
	return nil
}

//IsCudaEnable query whether cuda is available
func IsCudaEnable() bool {
	return atomic.LoadInt32(&cudaEnable) == 1
}

//Init initialize environment
func Init(path string) error {
	var err error
	cudaEnableOnce.Do(func() {
		err = open(path)
	})
	return err
}

const maxSize = 1024

var dataPool = sync.Pool{
	New: func() interface{} {
		return make([]uint32, 0, maxSize<<5)
	},
}

func unMarshal(in []byte) (x []byte, y []byte) {
	defer func() {
		e := recover()
		if e != nil {
			x, y = nil, nil
		}
	}()
	xl := in[3]
	x, y = in[4:4+xl], in[6+xl:]
	offset := 0
	for ; x[offset] == 0; offset++ {
	}
	x = x[offset:]
	offset = 0
	for ; y[offset] == 0; offset++ {
	}
	y = y[offset:]

	return x, y
}

//always > 0
type bigInner struct {
	_   bool
	abs []uint // absolute value of the integer
}

const length32 = uint(0x1000000000000000) == 0

var n, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)

//VerifySignatureGPU []uint32 0==success other number=fail
func VerifySignatureGPU(sig, dgest, pubX [][]byte, ret []uint8, bigBuf *[4]big.Int) {
	//data struct is (s,r,ph,e) with length (32,32,32,32)
	num := int32(len(dgest))
	data := dataPool.Get().([]uint32)[:num<<5]
	var i int32
	var offset int
	for i = 0; i < num; i++ {
		r, s := unMarshal(sig[i])
		bigBuf[0].SetBytes(s)                 //s 0
		bigBuf[1].SetBytes(r)                 //r 1
		bigBuf[2].SetBytes(pubX[i])           //px 2
		bigBuf[3].SetBytes(dgest[i])          //e 3
		bigBuf[3].Sub(&bigBuf[1], &bigBuf[3]) //true_x = r-e 3
		bigBuf[1].Add(&bigBuf[0], &bigBuf[1]) //t = s+r 1
		if bigBuf[1].Cmp(n) == 1 {
			bigBuf[1].Sub(&bigBuf[1], n)
		}
		if bigBuf[3].Sign() == -1 {
			bigBuf[3].Add(&bigBuf[3], n)
		}

		if length32 {
			for j := 0; j < 4; j++ {
				target := (*bigInner)(unsafe.Pointer(&bigBuf[j])).abs
				copy(data[offset:offset+8], (*[8]uint32)(unsafe.Pointer(&target[0]))[:])
				offset += 8
			}
		} else {
			for j := 0; j < 4; j++ {
				target := (*bigInner)(unsafe.Pointer(&bigBuf[j])).abs
				data[offset+0], data[offset+1] = uint32(target[0]), uint32(target[0]>>32)
				data[offset+2], data[offset+3] = uint32(target[1]), uint32(target[1]>>32)
				data[offset+4], data[offset+5] = uint32(target[2]), uint32(target[2]>>32)
				data[offset+6], data[offset+7] = uint32(target[3]), uint32(target[3]>>32)
				offset += 8
			}
		}

	}
	C.call_sm2ver_cuda((*C.xint)(unsafe.Pointer(&data[0])), C.int(num), (*C.uchar)(unsafe.Pointer(&ret[0])))
	dataPool.Put(data)
}

func initAndSelfTest() (err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = fmt.Errorf("GPU is not available or the version is too low: %v", r)
		}
	}()
	ret := C.call_init_sm2cuda()
	if ret != 0 {
		panic("init gpu error")
	}
	s, _ := hex.DecodeString("3045022000d6258f35b3496a23db918df7206ef555fc228fc6dcf1b44c3dcc87260cdc55022100ab97953db95ec59764fe10af21f3adb9f5cb6624eee957fc3b5f9f9cb8086ae2")
	e, _ := hex.DecodeString("02f78613d3d4503262be1ca5752fe7fa1cb5d251bce89b73ff204c1748a433b3")
	pk, _ := hex.DecodeString("77075f12e11b2d2c567ea9b030ec77565e6f15b00cff42578127b7b03c31af63")

	r := make([]uint8, 1)
	buf := new([4]big.Int)
	VerifySignatureGPU([][]byte{s}, [][]byte{e}, [][]byte{pk}, r, buf)
	if r[0] != 0 {
		return fmt.Errorf("GPU self-test failed")
	}
	return nil
}
