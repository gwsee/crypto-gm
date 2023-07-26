package internal

import (
	"container/heap"
	"errors"
	"github.com/gwsee/crypto-gm/random"
	"math/big"
	"sync"
	"unsafe"
)

const maxBatchSize = 512

var paramsPool = sync.Pool{
	New: func() interface{} {
		return &params{}
	},
}

func getParams() *params {
	ret := paramsPool.Get().(*params)
	ret.s = GetInt()
	ret.t = GetInt()
	return ret
}

func putParams(in *params) {
	PutInt(in.s)
	PutInt(in.t)
	in.s = nil
	in.t = nil
	paramsPool.Put(in)
}

type point struct {
	x, y, z sm2FieldElement
}
type params struct {
	s, t *big.Int
	q    uint64
	p    point
	r    point
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
//BatchVerify_32bit batch verify
//nolint
func BatchVerify_32bit(publicKey, signature, msg [][]byte) error {
	res := make([]*params, 0, len(signature))
	//r1: step1Result, r2: step2Result, r3: step3Result, r13: r1+r3
	//toVerify: r2 == r13
	var r13, r1, r2, r3 point
	err := preStep(&res, publicKey, signature, msg)
	if err != nil {
		return err
	}

	preIsZero := step1BaseScalar(&r1, res)

	err = step2Scalar(&r2, res)
	if err != nil {
		return err
	}

	nowIsZero := step3Scalar(&r3, res)
	for i := range res {
		putParams(res[i])
		res[i] = nil
	}

	double := point{}
	sm2PointAdd(&r1.x, &r1.y, &r1.z, &r3.x, &r3.y, &r3.z, &r13.x, &r13.y, &r13.z)
	sm2PointDouble(&double.x, &double.y, &double.z, &r1.x, &r1.y, &r1.z)
	copyCond(&r13, &double, resIsEqual(&r1, &r3))
	copyCond(&r13, &r3, preIsZero)
	copyCond(&r13, &r1, nowIsZero)

	if resIsEqual(&r13, &r2) == 1 {
		return nil
	} else {
		return errors.New("verification failed")
	}
}

func preStep(out *[]*params, publicKey, signature, digest [][]byte) error {
	var buf [8]byte
	for i := range signature {
		p := getParams()
		random.Rand(buf[:])
		p.q = *(*uint64)(unsafe.Pointer(&buf[0]))

		isBigger := signature[i][0]         //batch tag
		r, s := Unmarshal(signature[i][1:]) //remove batch tag

		rr, e, x, y := GetInt(), GetInt(), GetInt(), GetInt()
		p.s.SetBytes(s)
		rr.SetBytes(r)
		if p.s.Cmp(Sm2_32bit().Params().N) >= 0 || rr.Cmp(Sm2_32bit().Params().N) >= 0 {
			return errors.New("invalid signature")
		}
		e.SetBytes(digest[i][:])
		p.t.Add(p.s, rr)
		p.t.Mod(p.t, Sm2_32bit().Params().N)
		if p.t.Sign() == 0 {
			return errors.New("invalid signature")
		}

		xp, yp, err := getP(publicKey[i])
		if err != nil {
			return err
		}
		p.p.x, p.p.y, p.p.z = sm2FromAffine(xp, yp)

		x.Sub(rr, e)
		x.Mod(x, sm2.N)
		y, err = getY(x, int(isBigger))
		if err != nil {
			return err
		}
		p.r.x, p.r.y, p.r.z = sm2FromAffine(x, y)
		PutInt(e)
		PutInt(x)
		PutInt(y)
		PutInt(rr)
		*out = append(*out, p)
	}
	return nil
}

func getP(k []byte) (x1, y1 *big.Int, e error) {
	if len(k) != 65 {
		return nil, nil, errors.New("invalid publicKey")
	}
	//check is on Curve
	x, y := new(big.Int).SetBytes(k[1:33]), new(big.Int).SetBytes(k[33:])
	if !Sm2_32bit().IsOnCurve(x, y) {
		return nil, nil, errors.New("invalid publicKey")
	}
	return x, y, nil
}

func getY(in *big.Int, flag int) (out *big.Int, e error) {
	a := GetInt().SetInt64(3)
	var yy, x, x3, threex, b, y, y2, a3 sm2FieldElement
	sm2FromBig(&x, in) // x = in * R mod P
	sm2FromBig(&a3, a)
	PutInt(a)
	a = nil
	sm2FromBig(&b, Sm2_32bit().Params().B)
	sm2Mul(&threex, &x, &a3)
	sm2Mul(&x3, &x, &x)
	sm2Mul(&x3, &x3, &x)
	sm2Sub(&x3, &x3, &threex)
	sm2Add(&x3, &x3, &b)
	//x3: g
	invertForY(&y, &x3)

	sm2Mul(&y2, &y, &y)

	r1 := sm2ToBig(&y2)
	r2 := sm2ToBig(&x3)
	if r1.Cmp(r2) != 0 {
		return nil, errors.New("invalid x value")
	}
	yy = y

	negCond(&y, 1)
	out1 := sm2ToBig(&y)
	o := sm2ToBig(&yy)
	if (flag == 1 && o.Cmp(out1) > 0) || (flag == 0 && o.Cmp(out1) < 0) {
		out1 = o
	}
	return out1, nil
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
func invertForY(out, in *sm2FieldElement) {
	var x1, x2, x4, x6, x7, x8, x15, x30, x31, x32 sm2FieldElement
	copy(x1[:], in[:])
	sm2Square(&x2, in)
	sm2Mul(&x2, &x2, in)

	sm2SquareTimes(&x4, &x2, 2)
	sm2Mul(&x4, &x4, &x2)

	sm2SquareTimes(&x6, &x4, 2)
	sm2Mul(&x6, &x6, &x2)

	sm2Square(&x7, &x6)
	sm2Mul(&x7, &x7, in)

	sm2SquareTimes(&x8, &x7, 1)
	sm2Mul(&x8, &x8, in)

	sm2SquareTimes(&x15, &x8, 7)
	sm2Mul(&x15, &x15, &x7)

	sm2SquareTimes(&x30, &x15, 15)
	sm2Mul(&x30, &x30, &x15)

	sm2SquareTimes(&x31, &x30, 1)
	sm2Mul(&x31, &x31, in) //x31

	sm2SquareTimes(&x32, &x31, 1)
	sm2Mul(&x32, &x32, in)

	sm2SquareTimes(out, &x31, 33)
	sm2Mul(out, out, &x32)

	sm2SquareTimes(out, out, 32)
	sm2Mul(out, out, &x32)

	sm2SquareTimes(out, out, 32)
	sm2Mul(out, out, &x32)

	sm2SquareTimes(out, out, 32)
	sm2Mul(out, out, &x32)

	sm2SquareTimes(out, out, 32)
	sm2Mul(out, out, &x1)

	sm2SquareTimes(out, out, 62)
}

// out in Jacobian mode
func step1BaseScalar(out *point, in []*params) int {
	sum := GetInt()
	for i := range in {
		tmp := big.Int{}
		tmp.Mul(new(big.Int).SetUint64(in[i].q), in[i].s)
		tmp.Mod(&tmp, sm2.N)

		sum.Add(sum, &tmp)
		sum.Mod(sum, sm2.N)
	}
	summ := [8]uint32{}
	sm2GetScalar2(&summ, sum.Bytes())
	sm2BaseMult2(&out.x, &out.y, &out.z, &summ)
	PutInt(sum)
	return scalarIsZero(&summ)
}

// in and out in Mont and Jacobian mode
func step2Scalar(out *point, in []*params) error {
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
		newq := item1.priority - item2.priority

		var sum, double point
		sm2PointAdd(&item1.value.x, &item1.value.y, &item1.value.z, &item2.value.x, &item2.value.y, &item2.value.z, &sum.x, &sum.y, &sum.z)
		sm2PointDouble(&double.x, &double.y, &double.z, &item1.value.x, &item1.value.y, &item1.value.z)
		copyCond(&sum, &double, resIsEqual(item1.value, item2.value))
		flag := 0
		if item2.priority == 0 {
			flag = 1
		}
		copyCond(&sum, item1.value, flag)
		if item1.priority > 0 {
			flag = 0
		}
		copyCond(&sum, item2.value, flag)

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

	d := [8]uint32{}
	temp := new(big.Int).SetUint64(item.priority)
	temp.Mod(temp, sm2.N)
	sm2GetScalar2(&d, temp.Bytes())
	sm2PointToAffine(&item.value.x, &item.value.y, &item.value.x, &item.value.y, &item.value.z)

	sm2ScalarMult2(&out.x, &out.y, &out.z, &item.value.x, &item.value.y, &d)
	pq.PutItem(item)

	closePriorityQueue(pq)
	return nil
}

//∑q*R ?= [∑s*q]G + ∑([t*q]P)
//out = ∑([t*q]P)
var mapPool = sync.Pool{
	New: func() interface{} {
		return make(map[point]*big.Int, maxBatchSize)
	},
}

func step3Scalar(out *point, in []*params) int {
	cl := mapPool.Get().(map[point]*big.Int)
	sum, double := point{}, point{}

	for i := range in {
		v := in[i]
		res := GetInt()
		res.Mul(new(big.Int).SetUint64(in[i].q), in[i].t)
		res.Mod(res, sm2.N)
		_, ok := cl[v.p]
		if !ok {
			cl[v.p] = res
		} else {
			cl[v.p].Add(cl[v.p], res)
			cl[v.p].Mod(cl[v.p], sm2.N)
			PutInt(res)
		}
	}
	preIsZero := 1
	for ii := range cl {
		i := point{}
		vv := [8]uint32{}
		sm2GetScalar2(&vv, cl[ii].Bytes())
		nowIsZero := scalarIsZero(&vv)
		sm2PointToAffine(&i.x, &i.y, &ii.x, &ii.y, &ii.z)
		sm2ScalarMult2(&i.x, &i.y, &i.z, &i.x, &i.y, &vv)

		j := sum
		sm2PointAdd(&sum.x, &sum.y, &sum.z, &i.x, &i.y, &i.z, &sum.x, &sum.y, &sum.z)
		sm2PointDouble(&double.x, &double.y, &double.z, &i.x, &i.y, &i.z)
		copyCond(&sum, &double, resIsEqual(&j, &i))
		copyCond(&sum, &i, preIsZero)
		copyCond(&sum, &j, nowIsZero)

		preIsZero = preIsZero & nowIsZero

		PutInt(cl[ii])
		delete(cl, ii)
	}
	out.x = sum.x
	out.y = sum.y
	out.z = sum.z
	mapPool.Put(cl)
	return preIsZero
}

func copyCond(out, in *point, f int) {
	if f == 1 {
		out.x = in.x
		out.y = in.y
		out.z = in.z
	}
}

func resIsEqual(p1, p2 *point) int {
	p1x, p1y := sm2ToAffine(&p1.x, &p1.y, &p1.z)
	p2x, p2y := sm2ToAffine(&p2.x, &p2.y, &p2.z)
	if p1x.Cmp(p2x) == 0 && p1y.Cmp(p2y) == 0 {
		return 1
	}
	return 0
}
