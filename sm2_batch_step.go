package gm

import (
	"github.com/gwsee/crypto-gm/internal/sm2"
)

//GetHeap get Heap
func GetHeap() interface{} {
	return sm2.GetBatchHeap()
}

//CloseHeap close Heap
func CloseHeap(in interface{}) {
	sm2.PutBatchHeap(in)
}

//BatchVerifyInit BatchVerify Init
func BatchVerifyInit(ctx interface{}, publicKey, signature, msg [][]byte) error {
	return sm2.BatchVerifyInit(ctx, publicKey, signature, msg)
}

//BatchVerifyEnd BatchVerify End
func BatchVerifyEnd(ctx interface{}) error {
	return sm2.BatchVerifyEnd(ctx)
}
