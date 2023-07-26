package internal

import (
	"errors"
	"sync"
)

//batchHeapGo
type batchHeapGo struct {
	leftPoint point
	midout    []*params
}

var batchHeapPool = sync.Pool{
	New: func() interface{} {
		return &batchHeapGo{
			midout: make([]*params, 0, maxBatchSize),
		}
	},
}

//GetBatchHeap_32bit get
func GetBatchHeap_32bit() interface{} {
	return batchHeapPool.Get()
}

//PutBatchHeap_32bit put
func PutBatchHeap_32bit(in interface{}) {
	h := in.(*batchHeapGo)
	for i := range h.midout {
		putParams(h.midout[i])
		h.midout[i] = nil
	}
	h.midout = h.midout[:0]
	batchHeapPool.Put(in)
}

//BatchVerifyInit_32bit BatchVerify_32bit Init
//nolint
func BatchVerifyInit_32bit(ctxin interface{}, publicKey, signature, msg [][]byte) error {
	ctx := ctxin.(*batchHeapGo)
	err := preStep(&ctx.midout, publicKey, signature, msg)
	if err != nil {
		return err
	}
	var double, r13, r1, r3 point

	r1IsZero := step1BaseScalar(&r1, ctx.midout)
	r3IsZero := step3Scalar(&r3, ctx.midout)

	sm2PointAdd(&r1.x, &r1.y, &r1.z, &r3.x, &r3.y, &r3.z, &r13.x, &r13.y, &r13.z)
	sm2PointDouble(&double.x, &double.y, &double.z, &r1.x, &r1.y, &r1.z)
	copyCond(&r13, &double, resIsEqual(&r1, &r3))
	copyCond(&r13, &r3, r1IsZero)
	copyCond(&r13, &r1, r3IsZero)

	ctx.leftPoint = r13
	return nil
}

//BatchVerifyEnd_32bit BatchVerifyEnd_32bit
//nolint
func BatchVerifyEnd_32bit(ctxin interface{}) error {
	ctx := ctxin.(*batchHeapGo)
	r2 := point{}

	err := step2Scalar(&r2, ctx.midout)
	if err != nil {
		return err
	}

	if resIsEqual(&ctx.leftPoint, &r2) != 1 {
		return errors.New("invalid signature")
	}

	return nil
}
