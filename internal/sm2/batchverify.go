//go:build (amd64 || arm64) && !gmnoasm
// +build amd64 arm64
// +build !gmnoasm

package sm2

import (
	"container/heap"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gwsee/crypto-gm/internal/sm2/internal"
	"github.com/gwsee/crypto-gm/random"
	"sync"
	"unsafe"
)

const maxBatchSize = 512

var paramsPool = sync.Pool{
	New: func() interface{} {
		return new(params)
	},
}

func getParams() *params {
	return paramsPool.Get().(*params)
}

func putParams(in *params) {
	paramsPool.Put(in)
}

type params struct {
	s, t [4]uint64 //t = s + r
	q    uint64    //random
	p    sm2Point  //public key P
	r    sm2Point  //pointR = [r - e]G
}

/*
sum(s*q)*G + sum(t*q*P) = sum(q*R)
sig:(s, r)
R = (x, y)
	x = r - e
	y = getY(x)
t = s + r
P = (xp, yp)
q = rdrand.RandUint64()
*/
func batchVerify_64bit(publicKey, signature, msg [][]byte) error {
	res := make([]*params, 0, len(signature))
	//r1: step1Result, r2: step2Result, r3: step3Result, r13: r1+r3
	//toVerify: r2 == r13
	double, r13, r1, r2, r3 := sm2Point{}, sm2Point{}, sm2Point{}, sm2Point{}, sm2Point{}
	err := preStep(&res, publicKey, signature, msg)
	if err != nil {
		return err
	}

	r1IsZero := step1BaseScalar(&r1, res)

	err = step2Scalar(&r2, res)
	if err != nil {
		return err
	}

	r3IsZero := step3Scalar(&r3, res)

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

	p256Invert(&r2.xyz[2], &r2.xyz[2])
	p256Sqr(&temp2, &r2.xyz[2], 1)
	p256Mul(&r2.xyz[2], &temp2, &r2.xyz[2]) //xyz[2] = 1/z3
	p256Mul(&r2.xyz[0], &r2.xyz[0], &temp2)
	p256Mul(&r2.xyz[1], &r2.xyz[1], &r2.xyz[2])
	p256Mul(&r2.xyz[0], &r2.xyz[0], &one)
	p256Mul(&r2.xyz[1], &r2.xyz[1], &one)

	if !resIsEqual(&r13, &r2) {
		return errors.New("verification failed")
	}
	return nil
}

func resIsEqual(p1, p2 *sm2Point) bool {
	for i := 0; i < 2; i++ {
		for j := 0; j < 4; j++ {
			if p1.xyz[i][j] != p2.xyz[i][j] {
				return false
			}
		}
	}
	return true
}

//要求输入的后三个参数长度相同，小于65
//pointR = [r-e]G
func preStep(out *[]*params, publicKey, signature, digest [][]byte) error {
	var rr, e, x, y, xp, yp [4]uint64
	var buf [8]byte
	for i := range signature {
		p := getParams()
		random.Rand(buf[:])
		p.q = *(*uint64)(unsafe.Pointer(&buf[0]))

		isBigger := signature[i][0]                  //batch tag
		r, s := internal.Unmarshal(signature[i][1:]) //remove batch tag
		big2little(&rr, r)
		big2little(&p.s, s)
		if biggerThan(&rr, n) || biggerThan(&p.s, n) {
			return errors.New("r or s out of range")
		}
		big2little(&e, digest[i][:])
		orderAdd(&p.t, &p.s, &rr)
		if p.t[0]|p.t[1]|p.t[2]|p.t[3] == 0 {
			return fmt.Errorf("s + r is zero: %v", hex.EncodeToString(signature[i][1:]))
		}

		err := getP(&xp, &yp, publicKey[i])
		if err != nil {
			return err
		}

		orderSub(&x, &rr, &e) //x = r - e
		err = getY(&y, &x, int(isBigger))
		if err != nil {
			return err
		}

		maybeReduceModPASM(&x)
		maybeReduceModPASM(&y)
		p256Mul(&p.r.xyz[0], &x, &RR)
		p256Mul(&p.r.xyz[1], &y, &RR)
		// This sets Z value to 1, in the Montgomery domain.
		p.r.xyz[2] = R

		maybeReduceModPASM(&xp)
		maybeReduceModPASM(&yp)
		p256Mul(&p.p.xyz[0], &xp, &RR)
		p256Mul(&p.p.xyz[1], &yp, &RR)
		p.p.xyz[2] = R
		*out = append(*out, p)
	}
	return nil
}

func getP(xp, yp *[4]uint64, k []byte) error {
	if len(k) != 65 {
		return fmt.Errorf("public key length is %v", len(k))
	}
	var x, y [4]uint64
	//check is on Curve
	big2little(xp, k[1:33])
	big2little(yp, k[33:])
	x, y = *xp, *yp
	if !isOnCurve(&x, &y) {
		return errors.New("public key is not on curve")
	}
	return nil
}

//in, out: not Mont
func getY(out, in *[4]uint64, flag int) error {
	var x3, b, y, y2 [4]uint64
	var yy, inn [4]uint64
	p256Mul(&inn, in, &RR)
	p256Mul(&x3, &inn, &inn)
	p256Mul(&x3, &x3, &inn)
	p256Sub(&x3, &x3, &inn)
	p256Sub(&x3, &x3, &inn)
	p256Sub(&x3, &x3, &inn)
	p256Add(&x3, &x3, &curveB)

	p256Mul(&b, &x3, &one)

	//x3: g
	invertForY(&y, &x3)

	p256Mul(&y2, &y, &y)

	if y2 != x3 {
		return errors.New("invalid x value")
	}
	yy = y
	p256NegCond(&y, 1)

	p256Mul(&y, &y, &one)
	p256Mul(&yy, &yy, &one)
	if (flag == 1 && biggerThan(&yy, &y)) || (flag == 0 && !biggerThan(&yy, &y)) {
		y = yy
	}
	//p256Mul(&y, &y, &RR)
	*out = y
	return nil
}

/*

u+1:
1111111111111111111111111111111		x31:31
011111111111111111111111111111111	x32:33
11111111111111111111111111111111	x32:32
11111111111111111111111111111111	x32:32
11111111111111111111111111111111	x32:32
00000000000000000000000000000001	x1:32
00000000000000000000000000000000000000000000000000000000000000		0:62

x31 = 2^31-1
*/
// mod P , out and in are in Montgomery form
func invertForY(out, in *[4]uint64) {
	var all [40]uint64
	x1 := (*[4]uint64)(unsafe.Pointer(&all[0]))
	x2 := (*[4]uint64)(unsafe.Pointer(&all[4]))
	x4 := (*[4]uint64)(unsafe.Pointer(&all[8]))
	x6 := (*[4]uint64)(unsafe.Pointer(&all[12]))
	x7 := (*[4]uint64)(unsafe.Pointer(&all[16]))
	x8 := (*[4]uint64)(unsafe.Pointer(&all[20]))
	x15 := (*[4]uint64)(unsafe.Pointer(&all[24]))
	x30 := (*[4]uint64)(unsafe.Pointer(&all[28]))
	x31 := (*[4]uint64)(unsafe.Pointer(&all[32]))
	x32 := (*[4]uint64)(unsafe.Pointer(&all[36]))
	x1[0], x1[1], x1[2], x1[3] = in[0], in[1], in[2], in[3]
	p256Sqr(x2, in, 1)
	p256Mul(x2, x2, in)

	p256Sqr(x4, x2, 2)
	p256Mul(x4, x4, x2)

	p256Sqr(x6, x4, 2)
	p256Mul(x6, x6, x2)

	p256Sqr(x7, x6, 1)
	p256Mul(x7, x7, in)

	p256Sqr(x8, x7, 1)
	p256Mul(x8, x8, in)

	p256Sqr(x15, x8, 7)
	p256Mul(x15, x15, x7)

	p256Sqr(x30, x15, 15)
	p256Mul(x30, x30, x15)

	p256Sqr(x31, x30, 1)
	p256Mul(x31, x31, in) //x31

	p256Sqr(x32, x31, 1)
	p256Mul(x32, x32, in)

	p256Sqr(out, x31, 33)
	p256Mul(out, out, x32)

	p256Sqr(out, out, 32)
	p256Mul(out, out, x32)

	p256Sqr(out, out, 32)
	p256Mul(out, out, x32)

	p256Sqr(out, out, 32)
	p256Mul(out, out, x32)

	p256Sqr(out, out, 32)
	p256Mul(out, out, x1)

	p256Sqr(out, out, 62)
}

// out in Mont and Jacobian mode
//[r-e]G ?= [s]G + [t]P
//∑q*R ?= [∑s*q]G + ∑([t*q]P)
//求出右侧第一项 sum = ∑q*s; out = [sum]G
func step1BaseScalar(out *sm2Point, in []*params) int {
	var sum [4]uint64 //sum = ∑q*s
	for i := range in {
		var res [4]uint64                   // random q
		smallOrderMul(&res, &RRN, &in[i].q) //toMont
		orderMul(&res, &res, &in[i].s)
		//if i == 0 {
		//	copy(sum[:], res[:])
		//} else {
		orderAdd(&sum, &sum, &res)
		//}
	}
	getScalar(&sum)         //mode N
	out.sm2BaseMult(sum[:]) //out in Jacobian
	//out.toAffine()		//out in Affine
	return scalarIsZero(&sum)
}

// in and out in Mont and Jacobian mode
//∑q*R ?= [∑s*q]G + ∑([t*q]P)
//out = ∑q*R
func step2Scalar(out *sm2Point, in []*params) error {
	pq := getPriorityQueue()[:len(in)]
	for i, v := range in {
		pq[i] = pq.GetItem()
		pq[i].value = &v.r
		pq[i].priority = v.q
		pq[i].index = i
	}
	heap.Init(&pq)
	for pq.Len() > 1 {
		item1 := heap.Pop(&pq).(*Item)
		item2 := heap.Pop(&pq).(*Item)

		i1IsInfinity := uint64IsZero(item1.priority)
		i2IsInfinity := uint64IsZero(item2.priority)
		newq := item1.priority - item2.priority
		var sum, double sm2Point
		pointsEqual := sm2PointAdd2Asm(&sum.xyz, &item1.value.xyz, &item2.value.xyz)
		sm2PointDouble2Asm(&double.xyz, &item2.value.xyz)
		sum.copyConditional(&double, pointsEqual)
		sum.copyConditional(item1.value, i2IsInfinity)
		sum.copyConditional(item2.value, i1IsInfinity)
		if item2.priority > 0 {
			item2.value = &sum
			heap.Push(&pq, item2)
		} else {
			pq.PutItem(item2)
		}

		if newq > 0 {
			item1.priority = newq
			heap.Push(&pq, item1)
		} else {
			pq.PutItem(item1)
		}
	}
	if pq.Len() < 1 {
		return errors.New("step2 error")
	}
	item := heap.Pop(&pq).(*Item)
	e := item.value
	if item.priority > 1 {
		e.sm2ScalarMult([]uint64{item.priority, 0, 0, 0})
	}

	out.xyz = e.xyz
	pq.PutItem(item)
	closePriorityQueue(pq)
	return nil
}

var mapPool = sync.Pool{
	New: func() interface{} {
		return make(map[sm2Point]*[4]uint64, maxBatchSize)
	},
}

//∑q*R ?= [∑s*q]G + ∑([t*q]P)
//out = ∑([t*q]P)
func step3Scalar(out *sm2Point, in []*params) int {
	cl := mapPool.Get().(map[sm2Point]*[4]uint64)
	for _, v := range in {
		res := getInt()
		smallOrderMul(res, &RRN, &v.q) //toMont
		orderMul(res, res, &v.t)       //res = q * t
		if clvp, ok := cl[v.p]; !ok {
			cl[v.p] = res
		} else {
			orderAdd(clvp, res, clvp)
			putInt(res)
		}
	}
	preIsZero := 1
	var sum, double, sumCopy, iCopy sm2Point
	for i, v := range cl {
		nowIsZero := scalarIsZero(v)
		iCopy, sumCopy = i, sum
		iCopy.sm2ScalarMult(v[:])
		isEqual := sm2PointAdd2Asm(&sum.xyz, &sum.xyz, &iCopy.xyz)
		sm2PointDouble2Asm(&double.xyz, &iCopy.xyz)
		sum.copyConditional(&double, isEqual)
		sum.copyConditional(&iCopy, preIsZero)
		sum.copyConditional(&sumCopy, nowIsZero)
		preIsZero = preIsZero & nowIsZero

		putInt(v)
		delete(cl, i)
	}
	mapPool.Put(cl)
	out.xyz = sum.xyz
	return preIsZero
}
