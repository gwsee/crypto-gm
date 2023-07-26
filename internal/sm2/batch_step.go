//go:build (amd64 || arm64) && !gmnoasm
// +build amd64 arm64
// +build !gmnoasm

package sm2

import (
	"errors"
	"sync"
)

//batchHeapGo
type batchHeapGo struct {
	leftPoint sm2Point
	midout    []*params
}

var batchHeapPool = sync.Pool{
	New: func() interface{} {
		return &batchHeapGo{
			midout: make([]*params, 0, maxBatchSize),
		}
	},
}

//getBatchHeap_64bit get
func getBatchHeap_64bit() interface{} {
	return batchHeapPool.Get()
}

//putBatchHeap_64bit put
func putBatchHeap_64bit(in interface{}) {
	h := in.(*batchHeapGo)
	for i := range h.midout {
		putParams(h.midout[i])
		h.midout[i] = nil
	}
	h.midout = h.midout[:0]
	batchHeapPool.Put(in)
}

//batchVerifyInit_64bit BatchVerify Init
func batchVerifyInit_64bit(ctxin interface{}, publicKey, signature, msg [][]byte) error {
	ctx := ctxin.(*batchHeapGo)
	err := preStep(&ctx.midout, publicKey, signature, msg)
	if err != nil {
		return err
	}
	double, r13, r1, r3 := sm2Point{}, sm2Point{}, sm2Point{}, sm2Point{}
	r1IsZero := step1BaseScalar(&r1, ctx.midout)
	r3IsZero := step3Scalar(&r3, ctx.midout)

	isEqual := sm2PointAdd2Asm(&r13.xyz, &r1.xyz, &r3.xyz)
	sm2PointDouble2Asm(&double.xyz, &r1.xyz)
	r13.copyConditional(&double, isEqual)
	r13.copyConditional(&r1, r3IsZero)
	r13.copyConditional(&r3, r1IsZero)

	temp2 := [4]uint64{} //1/z2
	p256Invert(&r13.xyz[2], &r13.xyz[2])
	p256Sqr(&temp2, &r13.xyz[2], 1)
	p256Mul(&r13.xyz[2], &temp2, &r13.xyz[2]) //xyz[2] = 1/z3
	p256Mul(&r13.xyz[0], &r13.xyz[0], &temp2)
	p256Mul(&r13.xyz[1], &r13.xyz[1], &r13.xyz[2])
	p256Mul(&r13.xyz[0], &r13.xyz[0], &one)
	p256Mul(&r13.xyz[1], &r13.xyz[1], &one)

	ctx.leftPoint = r13
	return nil
}

//batchVerifyEnd_64bit batchVerifyEnd_64bit
func batchVerifyEnd_64bit(ctxin interface{}) error {
	ctx := ctxin.(*batchHeapGo)
	var r2 sm2Point
	err := step2Scalar(&r2, ctx.midout)
	if err != nil {
		return err
	}

	var temp2 [4]uint64 //1/z2
	p256Invert(&r2.xyz[2], &r2.xyz[2])
	p256Sqr(&temp2, &r2.xyz[2], 1)
	p256Mul(&r2.xyz[2], &temp2, &r2.xyz[2]) //xyz[2] = 1/z3
	p256Mul(&r2.xyz[0], &r2.xyz[0], &temp2)
	p256Mul(&r2.xyz[1], &r2.xyz[1], &r2.xyz[2])
	p256Mul(&r2.xyz[0], &r2.xyz[0], &one)
	p256Mul(&r2.xyz[1], &r2.xyz[1], &one)

	if !resIsEqual(&ctx.leftPoint, &r2) {
		return errors.New("invalid signature")
	}

	return nil
}
