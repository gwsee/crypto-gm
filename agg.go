package gm

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/meshplus/crypto"
	"github.com/gwsee/crypto-gm/internal/sm2"
)

//AggContext MulSig2 context
type AggContext struct {
	self   int
	pks    []*SM2PublicKey
	apk    SM2PublicKey
	curve  elliptic.Curve
	ai     []*big.Int
	rSelfJ []*big.Int
	init   bool
	Rx, Ry *big.Int
}

//Commitment commitment
type Commitment []byte

//Signature signature
type Signature []byte

//PubKey public key
type PubKey []byte

//Init init context
func (a *AggContext) Init(self int, pub ...PubKey) (Commitment, PubKey, error) {
	a.curve = GetSm2Curve()
	// n := a.curve.Params().N
	a.self = self
	if self >= len(pub) {
		return nil, nil, fmt.Errorf("self index is too big")
	}
	//1.assign sm2 curve and pks
	var h = sha256.New()
	var tmpBuf = make([]byte, 0, 32)
	a.pks = make([]*SM2PublicKey, len(pub))
	a.ai = make([]*big.Int, len(pub))
	a.rSelfJ = make([]*big.Int, len(pub)) //r_{i,j}, i is self
	for i := range pub {
		a.pks[i] = new(SM2PublicKey)
		err := a.pks[i].FromBytes(pub[i], crypto.Sm2p256v1)
		if err != nil {
			return nil, nil, fmt.Errorf("parse public key (%v) error: %v", i, err.Error())
		}
		_, _ = h.Write(pub[i])
	}
	tmpBuf = h.Sum(tmpBuf)
	//2.compute a.ai and a.apk
	var tmpX = new(big.Int)
	var tmpY = new(big.Int)
	var apkX = new(big.Int)
	var apkY = new(big.Int)
	var tmpBuf2 = make([]byte, 0, 32)
	for i := range pub {
		h.Reset()
		_, _ = h.Write(tmpBuf)
		_, _ = h.Write(pub[i])
		hash := h.Sum(tmpBuf2[:0]) //ai
		a.ai[i] = new(big.Int).SetBytes(hash)

		tmpX.SetBytes(a.pks[i].X[:])
		tmpY.SetBytes(a.pks[i].Y[:])
		if !a.curve.IsOnCurve(tmpX, tmpY) {
			return nil, nil, fmt.Errorf("pub key (%v) it's not on curve", i)
		}

		partX, partY := a.curve.ScalarMult(tmpX, tmpY, hash)
		curveAdd(apkX, apkY, partX, partY)
	}

	apkX.FillBytes(a.apk.X[:32])
	apkY.FillBytes(a.apk.Y[:32])
	a.apk.Curve = a.curve
	apkRet, _ := a.apk.Bytes()
	if self == -1 {
		return nil, apkRet, nil
	}
	//3.commit
	var commitment = make([]byte, len(pub)*64)
	for j := range pub {
		// a.rSelfJ[j], _ = rand.Int(rand.Reader, n)
		a.rSelfJ[j] = big.NewInt(1)
		element := a.rSelfJ[j].Bytes()
		x, y := a.curve.ScalarBaseMult(element)

		flag1 := j * 64
		flag2 := flag1 + 32
		flag3 := flag2 + 32
		x.FillBytes(commitment[flag1:flag2])
		y.FillBytes(commitment[flag2:flag3])
	}

	a.init = true
	return commitment, apkRet, nil
}

//AggCommitment aggregate commitment
func (a *AggContext) AggCommitment(in ...Commitment) (Commitment, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("input is empty")
	}

	first := in[0]
	if len(first)%64 != 0 {
		return nil, fmt.Errorf("parse commitment (0) error: length is not 64X")
	}
	n := len(first) / 64
	if n != len(in) {
		return nil, fmt.Errorf("commitment length expect %v x 64, got %v", len(in), len(first))
	}

	var retX = make([]*big.Int, n)
	var retY = make([]*big.Int, n)
	var tmpBig1 = new(big.Int)
	var tmpBig2 = new(big.Int)
	for j := 0; j < n; j++ {
		if len(in[j]) != len(first) {
			return nil, fmt.Errorf("parse commitment (%v) error: length is not %v", j, len(first))
		}
		retX[j] = new(big.Int)
		retY[j] = new(big.Int)
		for i := range in {
			getPartCommitment(in[i], j, tmpBig1, tmpBig2) //r_{i,j}, 参与方i生成的第j个nonce
			curveAdd(retX[j], retY[j], tmpBig1, tmpBig2)
		}
	}

	//拼接输出
	var commitment = make([]byte, 64*n)
	for j := 0; j < n; j++ {
		flag1 := j * 64
		flag2 := flag1 + 32
		flag3 := flag2 + 32
		retX[j].FillBytes(commitment[flag1:flag2])
		retY[j].FillBytes(commitment[flag2:flag3])
	}
	return commitment, nil
}

//PartSign generate partical signature
func (a *AggContext) PartSign(key []byte, msg []byte, aggCommitment Commitment) (Signature, error) {
	if !a.init {
		return nil, fmt.Errorf("'Aggcontext' has not been initialized")
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("'key' is empty")
	}
	var tmpBig = new(big.Int)
	N := a.curve.Params().N
	x, y := a.curve.ScalarBaseMult(key)
	if tmpBig.SetBytes(a.pks[a.self].X[:]).Cmp(x) != 0 {
		return nil, fmt.Errorf("the private key and public key do not match")
	}
	if tmpBig.SetBytes(a.pks[a.self].Y[:]).Cmp(y) != 0 {
		return nil, fmt.Errorf("the private key and public key do not match")
	}

	//1.计算b
	apkBytes, err := a.apk.Bytes()
	if err != nil {
		return nil, fmt.Errorf("APK is invalied")
	}
	var H = sha256.New()
	_, _ = H.Write(apkBytes)
	for i := range a.pks {
		pksI, err := a.pks[i].Bytes()
		if err != nil {
			return nil, fmt.Errorf("pks[%v] is invalied", i)
		}
		_, _ = H.Write(pksI)
	}
	_, _ = H.Write(msg)
	b := new(big.Int).SetBytes(H.Sum(nil))
	//2.计算R
	if len(aggCommitment) == 0 || len(aggCommitment)%64 != 0 {
		return nil, fmt.Errorf("aggCommitment length is not 64X")
	}
	n := len(aggCommitment) / 64
	var RiX = new(big.Int)
	var RiY = new(big.Int)
	a.Rx = new(big.Int)
	a.Ry = new(big.Int)
	var bPower = new(big.Int).Set(b)
	getPartCommitment(aggCommitment, 0, a.Rx, a.Ry)
	for i := 1; i < n; i++ {
		getPartCommitment(aggCommitment, i, RiX, RiY)
		partX, partY := a.curve.ScalarMult(RiX, RiY, bPower.Bytes())
		bPower.Mul(bPower, b)
		bPower.Mod(bPower, N)
		curveAdd(a.Rx, a.Ry, partX, partY)
	}

	//3.计算c
	H.Reset()
	_, _ = H.Write(apkBytes)
	tmp := make([]byte, 32)
	a.Rx.FillBytes(tmp)
	_, _ = H.Write(tmp)
	a.Ry.FillBytes(tmp)
	_, _ = H.Write(tmp)
	_, _ = H.Write(msg)
	c := new(big.Int).SetBytes(H.Sum(nil))
	//4.计算s_i
	keyBig := new(big.Int).SetBytes(key)
	ai := a.ai[a.self]
	c.Mul(c, ai).Mul(c, keyBig)
	bPower.Set(b)
	var partSecondAdder = new(big.Int)
	var secondAdder = new(big.Int).Set(a.rSelfJ[0])
	for i := 1; i < n; i++ {
		partSecondAdder.Mul(a.rSelfJ[i], bPower)
		bPower.Mul(bPower, b)
		secondAdder.Add(secondAdder, partSecondAdder)
	}
	c.Add(c, secondAdder)
	c.Mod(c, N)
	//5.输出
	ret := make([]byte, 65)
	compressCoordinates(ret[:33], a.Rx, a.Ry)
	c.FillBytes(ret[33:])
	return ret, nil
}

//AggSign aggregate signature
func (a *AggContext) AggSign(signs ...Signature) (Signature, error) {
	var sAll = new(big.Int)
	var tmp = new(big.Int)
	var tmpRx = new(big.Int)
	var tmpRy = new(big.Int)
	for i := range signs {
		s, err := parseSign(signs[i], tmpRx, tmpRy)
		if err != nil {
			return nil, fmt.Errorf("parse isgnature (%v) error: %v", i, err)
		}
		if tmpRx.Cmp(a.Rx) != 0 || tmpRy.Cmp(a.Ry) != 0 {
			return nil, fmt.Errorf("'R' of signature %v is different from self", i)
		}
		tmp.SetBytes(s)
		sAll.Add(sAll, tmp)
	}
	sAll.Mod(sAll, a.curve.Params().N)
	ret := make([]byte, 65)
	compressCoordinates(ret[:33], a.Rx, a.Ry)
	sAll.FillBytes(ret[33:])
	return ret, nil
}

//Verify verify Schnorr signature
func (a *AggContext) Verify(key PubKey, msg []byte, sign Signature) error {
	return verify(key, msg, sign)
}

//GetPK get public key
//if i < 0, return aggregation key
func (a *AggContext) GetPK(i int) (PubKey, error) {
	if !a.init {
		return nil, fmt.Errorf("'Aggcontext' has not been initialized")
	}
	if i >= len(a.pks) {
		return nil, fmt.Errorf("index is too large")
	}
	if i < 0 {
		return a.apk.Bytes()
	}
	return a.pks[i].Bytes()
}

func getPartCommitment(commitment []byte, i int, retX, retY *big.Int) {
	flag1 := i * 64
	flag2 := flag1 + 32
	flag3 := flag2 + 32
	retX.SetBytes(commitment[flag1:flag2])
	retY.SetBytes(commitment[flag2:flag3])

}

func verify(key PubKey, msg []byte, sign Signature) error {
	curve := GetSm2Curve()
	//0.解析签名和公钥
	var Rx = new(big.Int)
	var Ry = new(big.Int)
	s, err := parseSign(sign, Rx, Ry)
	if err != nil {
		return err
	}
	var apk = new(SM2PublicKey)
	err = apk.FromBytes(key, crypto.Sm2p256v1)
	if err != nil {
		return fmt.Errorf("parse public key error: %v", err)
	}

	//1.计算c
	var H = sha256.New()
	apkByte, _ := apk.Bytes()
	_, _ = H.Write(apkByte)
	tmp := make([]byte, 32)
	Rx.FillBytes(tmp)
	_, _ = H.Write(tmp)
	Ry.FillBytes(tmp)
	_, _ = H.Write(tmp)
	_, _ = H.Write(msg)
	c := H.Sum(nil)
	//2.计算c·tiledX
	var tiledX = new(big.Int).SetBytes(apk.X[:])
	var tiledY = new(big.Int).SetBytes(apk.Y[:])
	tiledX, tiledY = curve.ScalarMult(tiledX, tiledY, c)
	//3.计算s·G
	expectX, expectY := curve.ScalarBaseMult(s)
	//4.比较结果
	curveAdd(Rx, Ry, tiledX, tiledY)
	if expectX.Cmp(Rx) == 0 && expectY.Cmp(Ry) == 0 {
		return nil
	}
	return fmt.Errorf("verify fail")
}

//1+32(X)
func compressCoordinates(ret []byte, X, Y *big.Int) {
	sm2.CompressCoordinates(ret, X, Y)
}

func decompressCoordinates(in []byte, X, Y *big.Int) error {
	if len(in) != 33 {
		return fmt.Errorf("it's compress formate")
	}
	X.SetBytes(in[1:])
	Y.Set(X)
	return sm2.ComplementCoordinates(Y, in[0])
}

func parseSign(sign []byte, Rx, Ry *big.Int) ([]byte, error) {
	if len(sign) != 65 {
		return nil, fmt.Errorf("signature expect 65 bytes, sign:%v", hex.EncodeToString(sign))
	}
	err := decompressCoordinates(sign[:33], Rx, Ry)
	if err != nil {
		return nil, fmt.Errorf("decompress R form signature error: %v", err)
	}
	return sign[33:], nil
}

func curveAdd(Ax, Ay, Bx, By *big.Int) {
	var c = GetSm2Curve()
	var retX, retY *big.Int
	if Bx.Sign() == 0 && By.Sign() == 0 {
		panic("second adder is empty point")
	}

	if Ax.Sign() == 0 && Ay.Sign() == 0 {
		retX = Bx
		retY = By
	} else {
		if Ax.Cmp(Bx) == 0 && Ay.Cmp(By) == 0 {
			retX, retY = c.Double(Ax, Ay)
		} else {
			retX, retY = c.Add(Ax, Ay, Bx, By)
		}
	}

	Ax.Set(retX)
	Ay.Set(retY)
}
