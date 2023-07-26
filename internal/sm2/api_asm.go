//go:build (amd64 || arm64) && !gmnoasm
// +build amd64 arm64
// +build !gmnoasm

package sm2

import (
	"crypto/elliptic"
	"github.com/gwsee/crypto-gm/internal/sm2/internal"
	"golang.org/x/sys/cpu"
	"io"
	"math/big"
)

/*
API
func Sm2() elliptic.Curve
func Sign(dgst []byte, reader io.Reader, key []byte) ([]byte, uint8, error)
func verifySignature(sig, dgst []byte, X []byte, Y []byte) (bool, error)
func GetBatchHeap() interface{}
func PutBatchHeap(in interface{})
func BatchVerifyInit(ctxin interface{}, publicKey, signature, msg [][]byte) bool
func BatchVerifyEnd(ctxin interface{}) bool
func BatchVerify(publicKey, signature, msg [][]byte) error
*/

var Sm2 func() elliptic.Curve
var Sign func(dgst []byte, reader io.Reader, key []byte) ([]byte, uint8, error)
var VerifySignature func(sig, dgst []byte, X []byte, Y []byte) (bool, error)
var GetBatchHeap func() interface{}
var PutBatchHeap func(in interface{})
var BatchVerifyInit func(ctxin interface{}, publicKey, signature, msg [][]byte) error
var BatchVerifyEnd func(ctxin interface{}) error
var BatchVerify func(publicKey, signature, msg [][]byte) error
var ComplementCoordinates func(x *big.Int, tildeY byte) error //the result is placed in 'x'

func init() {
	if (cpu.X86.HasSSE2 && cpu.X86.HasBMI2 && cpu.X86.HasSSE42 && cpu.X86.HasSSE41) || cpu.ARM64.HasAES {
		Sm2 = sm2_64bit
		Sign = sign_64bit
		VerifySignature = verifySignature_64bit
		GetBatchHeap = getBatchHeap_64bit
		PutBatchHeap = putBatchHeap_64bit
		BatchVerifyInit = batchVerifyInit_64bit
		BatchVerifyEnd = batchVerifyEnd_64bit
		BatchVerify = batchVerify_64bit
		ComplementCoordinates = complementCoordinates_64bit
		return
	}

	Sm2 = internal.Sm2_32bit
	Sign = internal.Sign_32bit
	VerifySignature = internal.VerifySignature_32bit
	GetBatchHeap = internal.GetBatchHeap_32bit
	PutBatchHeap = internal.PutBatchHeap_32bit
	BatchVerifyInit = internal.BatchVerifyInit_32bit
	BatchVerifyEnd = internal.BatchVerifyEnd_32bit
	BatchVerify = internal.BatchVerify_32bit
	ComplementCoordinates = internal.ComplementCoordinates_32bit
}

//MarshalSig marshal signature
func MarshalSig(x, y []byte) []byte

//Unmarshal unmarshal signature
func Unmarshal(in []byte) (x []byte, y []byte)

//CompressCoordinates compress coordinates
func CompressCoordinates(in []byte, x, y *big.Int) {
	in[0] = byte(y.Bit(0)) + 2
	x.FillBytes(in[1:])
	return
}
