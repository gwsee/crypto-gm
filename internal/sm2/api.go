//go:build (!amd64 || gmnoasm) && (!arm64 || gmnoasm)
// +build !amd64 gmnoasm
// +build !arm64 gmnoasm

package sm2

import (
	"crypto/elliptic"
	"github.com/gwsee/crypto-gm/internal/sm2/internal"
	"io"
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

func Sm2() elliptic.Curve {
	return internal.Sm2_32bit()
}

func Sign(dgst []byte, reader io.Reader, key []byte) ([]byte, uint8, error) {
	return internal.Sign_32bit(dgst, reader, key)
}
func VerifySignature(sig, dgst []byte, X []byte, Y []byte) (bool, error) {
	return internal.VerifySignature_32bit(sig, dgst, X, Y)
}

func GetBatchHeap() interface{} {
	return internal.GetBatchHeap_32bit()
}

func PutBatchHeap(in interface{}) {
	internal.PutBatchHeap_32bit(in)
}
func BatchVerifyInit(ctxin interface{}, publicKey, signature, msg [][]byte) error {
	return internal.BatchVerifyInit_32bit(ctxin, publicKey, signature, msg)
}

func BatchVerifyEnd(ctxin interface{}) error {
	return internal.BatchVerifyEnd_32bit(ctxin)
}

func BatchVerify(publicKey, signature, msg [][]byte) error {
	return internal.BatchVerify_32bit(publicKey, signature, msg)
}

//MarshalSig marshal signature
func MarshalSig(x, y []byte) []byte

//Unmarshal unmarshal signature
func Unmarshal(in []byte) (x []byte, y []byte)
