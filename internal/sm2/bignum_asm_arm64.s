#include "textflag.h"
#include "precomputed.h"

#define a_ptr R0
#define b_ptr R1

DATA P<>+0x00(SB) /8, $0xffffffff00000000
DATA P<>+0x08(SB) /8, $0xfffffffeffffffff
GLOBL P<>(SB), RODATA, $16

#define r0 R2
#define r1 R3
#define r2 R4
#define r3 R5
#define r4 R6
#define r5 R7
#define r6 R8
#define r7 R9
#define t0 R10
#define t1 R11
#define t2 R12
#define t3 R13
#define const0 R14
#define const1 R15
#define const2 R16
#define hlp R17
#define H R19
#define L R20

#define a R21
#define b R22
#define c R23
#define d R24
#define hlp1 R25

#define maySubP(in1, in2, in3, in4, in5) \
    MOVD P<>+0x00(SB), const0; \
    MOVD P<>+0x08(SB),const1; \
    MOVD $-1, const2; \
    SUBS const2, in1, a ; \
    SBCS const0, in2, b; \
    SBCS const2, in3, c; \
    SBCS const1, in4, d; \
    SBCS $0, in5, in5; \
    CSEL CS ,a, in1, in1; \
    CSEL CS ,b, in2, in2; \
    CSEL CS ,c, in3, in3; \
    CSEL CS ,d, in4, in4;

/* ---------------------------------------*/
//func maybeReduceModPASM(in *[4]uint64) *[4]uint64
TEXT ·maybeReduceModPASM(SB), NOSPLIT, $8-0
    MOVD in+0(FP), a_ptr
    LDP 0*16(a_ptr), (r0, r1)
    LDP 1*16(a_ptr), (r2, r3)
    EOR hlp, hlp, hlp;
    maySubP(r0, r1, r2, r3, hlp)

    STP (r0, r1), 0*16(a_ptr)
    STP (r2, r3), 1*16(a_ptr)

    RET

// REDC(~) : return (n, v1, v2, v3, v4) /e64 mod p, result in (v1, v2, v3, v4, v5)
// (v1, v2, v3, v4, v5) <= n * RInv + (v1, v2, v3, v4, v5)
// v5 should be zero
#define REDC(n, v1, v2, v3, v4, v5) \
    LSR $32,n, H; LSL $32, n, L; \
    ADDS n, v1, v1; ADCS $0, v2, v2; ADCS $0, v3, v3; ADCS n, v4, v4; ADCS $0, v5, v5; \
    SUBS L, v1, v1; SBCS H, v2, v2; SBCS L, v3, v3; SBCS H, v4, v4; SBCS $0, v5, v5;

#define single(i, v0, v1, v2, v3, v4, v5) \
    MOVD (8*i)(b_ptr), t0; \
    LDP (16*0)(a_ptr), (a, b); LDP (16*1)(a_ptr),(c, d); \
    MUL a, t0, r6; \
    UMULH a, t0, r7; \
    ADDS r6, v0, v0; \
    ADCS r7, v1, v1; \
    MUL b, t0, r6; \
    UMULH b, t0, r7; \
    ADCS $0, r7, r7; \
    ADDS r6, v1, v1; \
    ADCS r7, v2, v2; \
    MUL c, t0, r6; \
    UMULH c, t0, r7; \
    ADCS $0, r7, r7; \
    ADDS r6, v2, v2; \
    ADCS r7, v3, v3; \
    MUL d, t0, r6; \
    UMULH d, t0, r7; \
    ADCS $0, r7, r7; \
    ADCS r6, v3, v3; \
    ADCS r7, v4, v4; \
    ADDS $0, v0, v0; \
    EOR  v5, v5, v5;

// input is a_ptr b_ptr
// result r4 r5 r0 r1
#define p256MulInline() \
    EOR r2, r2, r2; EOR r3, r3, r3; EOR r4, r4, r4; EOR r5, r5, r5; \
    MOVD (8*0)(b_ptr), t0; \
    LDP (16*0)(a_ptr), (a, b); LDP (16*1)(a_ptr),(c, d); \
    MUL a, t0, r0; UMULH a, t0, r1; \
    MUL b, t0, t1; UMULH b, t0, r2;ADDS t1, r1, r1; \
    MUL c, t0, t1; UMULH c, t0, r3;ADCS t1, r2, r2; \
    MUL d, t0, t1; UMULH d, t0, r4;ADCS t1, r3, r3; ADCS $0, r4, r4; \
    REDC(r0, r1, r2, r3, r4, r5) \
    single(1, r1, r2, r3, r4, r5, r0)                        \ // x * y[1]
	REDC(r1, r2, r3, r4, r5, r0)                             \
	single(2, r2, r3, r4, r5, r0, r1)                        \ // x * y[2]
	REDC(r2, r3, r4, r5, r0, r1)                             \
	single(3, r3, r4, r5, r0, r1, r2)                        \ // x * y[3]
	REDC(r3, r4, r5, r0, r1, r2)                              \// now result in r4 r5 r0 r1 r2
	maySubP(r4, r5, r0, r1, r2)

/* ---------------------------------------*/
// func p256Mul(res, a, b *[4]uint64)
TEXT ·p256Mul(SB), NOSPLIT, $64-16
    MOVD ina+8(FP), a_ptr
    MOVD inb+16(FP), b_ptr
    p256MulInline()
    MOVD res+0(FP), a_ptr
    STP (r4, r5), (16*0)(a_ptr)
    STP (r0, r1), (16*1)(a_ptr)
    RET

// REDC(~) : return a0 /e64 mod p, result in (a0, a1, a2, a3)
// (a0, a1, a2, a3) <= a0 * RInv mod p
#define REDCForSqr(a0, a1, a2, a3) \
    LSR $32, a0, H; LSL $32, a0, L;\
    ADDS a0, a1, a1; ADCS $0, a2, a2; ADCS $0, a3, a3; ADCS $0, a0, a0; \
    SUBS L, a1, a1; SBCS H, a2, a2; SBCS L, a3, a3; SBCS H, a0, a0;

#define mayAddP(in1, in2, in3, in4, in5) \
    MOVD P<>+0x00(SB), const0;\
    MOVD P<>+0x08(SB),const1; \
    MOVD $-1, const2; \
    ADDS const2, in1, a; \
    ADCS const0, in2, b; \
    ADCS const2, in3, c; \
    ADCS const1, in4, d; \
    ANDS $1, in5; \
    CSEL	EQ, in1, a, in1 \
    CSEL	EQ, in2, b, in2 \
    CSEL	EQ, in3, c, in3 \
    CSEL	EQ, in4, d, in4
// input a_ptr
// output r0 r1 r2 r3
#define p256SqrInline() \
    LDP (16*0)(a_ptr), (a, b); LDP (16*1)(a_ptr),(c, d); \
    MUL a, b, r1; UMULH a, b, r2; \
    MUL a, c, t1; UMULH a, c, r3; ADDS t1, r2, r2; \
    MUL a, d, t1; UMULH a, d, r4; ADCS t1, r3, r3; ADCS $0, r4, r4; \
    MUL b, c, t1; UMULH b, c, t2; ADDS t1, r3, r3; ADCS t2, r4, r4; \
    MUL b, d, t1; UMULH b, d, r5; ADCS $0, r5, r5; ADDS t1, r4, r4; \
    MUL c, d, t1; UMULH c, d, r6; ADCS t1, r5, r5; ADCS $0, r6, r6; \
    EOR r7, r7, r7; \
    ADDS r1, r1, r1; ADCS r2, r2, r2; ADCS r3, r3, r3; ADCS r4, r4, r4; ADCS r5, r5, r5; ADCS r6, r6, r6; ADCS $0, r7, r7; \
    MUL a, a, r0; UMULH a, a, H; ADDS H, r1, r1; \
    MUL b, b, t1; UMULH b, b, H; ADCS t1, r2, r2; ADCS H, r3, r3; \
    MUL c, c, t1; UMULH c, c, H; ADCS t1, r4, r4;  ADCS H, r5, r5; \
    MUL d, d, t1; UMULH d, d, t2; ADCS t1, r6, r6; ADCS t2, r7, r7;\
    REDCForSqr(r0, r1, r2, r3)                                                          \
    REDCForSqr(r1, r2, r3, r0)                                                          \
    REDCForSqr(r2, r3, r0, r1)                                                          \
    REDCForSqr(r3, r0, r1, r2) \
    EOR H,H, H; ADDS r4, r0, r0; ADCS r5, r1, r1; ADCS r6, r2, r2; ADCS r7, r3, r3; ADCS $0, H, H;\
    maySubP(r0, r1, r2, r3, H)

/* ---------------------------------------*/
TEXT ·p256Sqr(SB), NOSPLIT, $0
    MOVD in+8(FP), a_ptr
    MOVD n+16(FP), b_ptr
sqrLoop:
    SUB $1, b_ptr
    p256SqrInline()
    MOVD res+0(FP), hlp
    STP (r0, r1), (16*0)(hlp)
    STP (r2, r3), (16*1)(hlp)
    MOVD hlp, a_ptr
    CBNZ b_ptr, sqrLoop;

    RET
/* ---------------------------------------*/
TEXT ·p256Add(SB), NOSPLIT, $16-0
    MOVD ina+8(FP), a_ptr
    MOVD inb+16(FP), b_ptr
    LDP 16*0(a_ptr), (r0, r1)
    LDP 16*1(a_ptr), (r2, r3)
    EOR hlp, hlp, hlp;
    LDP (16*0)(b_ptr), (a, b); LDP (16*1)(b_ptr),(c, d);
    ADDS a, r0, r0;
    ADCS b, r1, r1;
    ADCS c, r2, r2;
    ADCS d, r3, r3;
    ADCS $0, hlp, hlp;
    maySubP(r0, r1, r2, r3, hlp)
    MOVD res+0(FP), a_ptr
    STP (r0, r1), (16*0)(a_ptr)
    STP (r2, r3), (16*1)(a_ptr)
    RET
/* ---------------------------------------*/
TEXT ·p256Sub(SB), NOSPLIT, $16-0
    MOVD ina+8(FP), a_ptr
    MOVD inb+16(FP), b_ptr
    LDP 16*0(a_ptr), (r0, r1)
    LDP 16*1(a_ptr), (r2, r3)
    EOR hlp, hlp, hlp;
    LDP (16*0)(b_ptr), (a, b)
    LDP (16*1)(b_ptr), (c, d);
    SUBS a, r0, r0;
    SBCS b, r1, r1;
    SBCS c, r2, r2;
    SBCS d, r3, r3;
    SBCS $0, hlp, hlp;
    mayAddP(r0, r1, r2, r3, hlp)
    MOVD res+0(FP), a_ptr
    STP (r0, r1), (16*0)(a_ptr)
    STP (r2, r3), (16*1)(a_ptr)
    RET


//   t0, t1, t2, t3
// + r0, r1, r2, r3
//------------------
//   r0, r1, r2, r3
#define AddInternal() \
    EOR hlp, hlp, hlp; \
    ADDS t0, r0, r0; \
    ADCS t1, r1, r1; \
    ADCS t2, r2, r2; \
    ADCS t3, r3, r3; \
    ADCS $0, hlp, hlp;\
    maySubP(r0, r1, r2, r3, hlp);

//   t0, t1, t2, t3
// - r0, r1, r2, r3
//------------------
//   r0, r1, r2, r3
#define SubInternal() \
    EOR hlp, hlp, hlp; \
    SUBS r0, t0, r0; \
    SBCS r1, t1, r1; \
    SBCS r2, t2, r2; \
    SBCS r3, t3, r3; \
    SBCS $0, hlp, hlp; \
    mayAddP(r0, r1, r2, r3, hlp);

/* ---------------------------------------*/
TEXT ·sm2PointDouble2Asm(SB), NOSPLIT, $96-32
    MOVD in+8(FP), b_ptr;
    ADD $64, b_ptr, a_ptr;
    p256SqrInline()
    MOVD r0, d0-32(SP)
    MOVD r1, d0-24(SP)
    MOVD r2, d0-16(SP)
    MOVD r3, d3-8(SP) // d = z1^2

    ADD $32, b_ptr, a_ptr;
    LDP (16*0)(a_ptr), (t0, t1)
    LDP (16*1)(a_ptr), (t2, t3)
    LDP (16*0)(a_ptr), (r0, r1)
    LDP (16*1)(a_ptr), (r2, r3)

    AddInternal()
    MOVD r0, b0-64(SP)
    MOVD r1, b1-56(SP)
    MOVD r2, b2-48(SP)
    MOVD r3, b3-40(SP)
    ADDS $64, b_ptr, b_ptr; // z
    MOVD $b0-64(SP), a_ptr;
    p256MulInline()// z = 2 * y1 * z1
    //Z
    MOVD res+0(FP), a_ptr // res
    ADD $64, a_ptr
    STP (r4, r5), (16*0)(a_ptr)
    STP (r0, r1), (16*1)(a_ptr)

    MOVD in+8(FP), a_ptr
    p256SqrInline() // x1^2
    MOVD res+0(FP), b_ptr
    MOVD r0, a0-96(SP);
    MOVD r1, a1-88(SP);
    MOVD r2, a2-80(SP);
    MOVD r3, a3-72(SP); // a -> x1 ^2

    MOVD $d0-32(SP), a_ptr;
    p256SqrInline() // d^2 -> r0, r1, r2, r3

    MOVD $a0-96(SP), a_ptr
    LDP (16*0)(a_ptr),(t0, t1)
    LDP (16*1)(a_ptr),(t2, t3)
    SubInternal() // x1 ^2 - d^2
    MOVD r0, a0-96(SP);
    MOVD r1, a1-88(SP);
    MOVD r2, a2-80(SP);
    MOVD r3, a3-72(SP); // a -> x1 ^2 - d^2
    MOVD r0, t0;
    MOVD r1, t1;
    MOVD r2, t2;
    MOVD r3, t3;
    AddInternal() // 2 * (x1 ^2 - d^2 )

    MOVD $a0-96(SP), a_ptr
    LDP (16*0)(a_ptr),(t0, t1)
    LDP (16*1)(a_ptr),(t2, t3)
    AddInternal() // 3 * (x1 ^2 - d^2 )
    MOVD r0, a0-96(SP);
    MOVD r1, a1-88(SP);
    MOVD r2, a2-80(SP);
    MOVD r3, a3-72(SP); // a-> 3 *( x1 ^2 - d^2 )
    MOVD $b0-64(SP), a_ptr;
    p256SqrInline() // b^2
    MOVD r0, d0-32(SP)
    MOVD r1, d1-24(SP)
    MOVD r2, d2-16(SP)
    MOVD r3, d3-8(SP) // d = b^2 = 4*y1^2

    MOVD $d0-32(SP), a_ptr
    MOVD in+8(FP), b_ptr
    p256MulInline() // b^2 * x1
    MOVD r4, b0-64(SP)
    MOVD r5, b1-56(SP)
    MOVD r0, b2-48(SP)
    MOVD r1, b3-40(SP) // b -> b^2 * x1

    MOVD $a0-96(SP), a_ptr;
    p256SqrInline() // a^2

    MOVD r0, t0;
    MOVD r1, t1;
    MOVD r2, t2;
    MOVD r3, t3;

    MOVD $b0-64(SP), a_ptr
    LDP (16*0)(a_ptr),(r0, r1)
    LDP (16*1)(a_ptr),(r2, r3)

    SubInternal() // a^2 -b
    MOVD r0, t0;
    MOVD r1, t1;
    MOVD r2, t2;
    MOVD r3, t3;
    MOVD $b0-64(SP), a_ptr
    LDP (16*0)(a_ptr),(r0, r1)
    LDP (16*1)(a_ptr),(r2, r3)
    SubInternal() // x3 ->a^2 - 2 * b
    //x
    MOVD res+0(FP), a_ptr // res
    STP (r0, r1), (16*0)(a_ptr)
    STP (r2, r3), (16*1)(a_ptr)

    MOVD $b0-64(SP), b_ptr
    LDP (16*0)(b_ptr),(t0, t1)
    LDP (16*1)(b_ptr),(t2, t3)
    SubInternal() // b^2 *x1 - x3

    MOVD r0, b0-64(SP)
    MOVD r1, b1-56(SP)
    MOVD r2, b2-48(SP)
    MOVD r3, b3-40(SP)

    MOVD $a0-96(SP), a_ptr
    p256MulInline() // a (b^2 * x1 - x3)
    MOVD r4, a0-96(SP)
    MOVD r5, a1-88(SP)
    MOVD r0, a2-80(SP)
    MOVD r1, a3-72(SP) // a -> a (b^2 * x1 - x3)

    MOVD $d0-32(SP), a_ptr
    p256SqrInline() // d^2 = b^4 = 16*y1^4

    EOR hlp, hlp, hlp
    MOVD P<>+0x00(SB), const0
    MOVD P<>+0x08(SB),const1
    MOVD $-1, const2
    ADDS $-1, r0, t0
    ADCS const0, r1, t1
    ADCS const2, r2, t2
    ADCS const1, r3, t3
    ADCS $0, hlp, hlp

    ANDS	$1, r0, ZR
    CSEL	EQ, r0, t0, t0
    CSEL	EQ, r1, t1, t1
    CSEL	EQ, r2, t2, t2
    CSEL	EQ, r3, t3, t3
    AND	r0, hlp, hlp

    EXTR	$1, t0, t1, r0
    EXTR	$1, t1, t2, r1
    EXTR	$1, t2, t3, r2
    EXTR	$1, t3, hlp, r3

    MOVD $a0-96(SP), a_ptr
    LDP (16*0)(a_ptr), (t0, t1)
    LDP (16*1)(a_ptr), (t2, t3)

    SubInternal() //  a (b^2 * x1 - x3) - 8*y1 ^4

    MOVD res+0(FP), a_ptr
    ADD $32, a_ptr
    STP (r0, r1), (16*0)(a_ptr)
    STP (r2, r3), (16*1)(a_ptr)
    RET

//	var  1 * RRP mod P = [4]uint64{0x01, 0xffffffff, 0, 0x100000000}
DATA ·RR<>+0x10(SB) /8, $0x01
DATA ·RR<>+0x18(SB) /8, $0xffffffff
DATA ·RR<>+0x20(SB) /8, $0x0
DATA ·RR<>+0x28(SB) /8, $0x100000000
GLOBL ·RR<>(SB), RODATA, $48

/* ---------------------------------------*/
TEXT ·sm2PointDouble1Asm(SB), NOSPLIT, $96-32
    MOVD in+8(FP), a_ptr
    ADD $32, a_ptr
    LDP (16*0)(a_ptr),(t0, t1)
    LDP (16*1)(a_ptr),(t2, t3)
    MOVD t0, r0
    MOVD t1, r1
    MOVD t2, r2
    MOVD t3, r3
    AddInternal()  // 2* y
    //结果在 r0, r1, r2, r3
    MOVD r0, b0-32(SP)
    MOVD r1, b1-24(SP)
    MOVD r2, b2-16(SP)
    MOVD r3, b3-8(SP) // b = 2*y

    MOVD res+0(FP), a_ptr
    ADD $64, a_ptr
    STP (r0, r1), (16*0)(a_ptr)
    STP (r2, r3), (16*1)(a_ptr)

    MOVD in+8(FP), a_ptr
    p256SqrInline() // x1^2
    MOVD r0, t0
    MOVD r1, t1
    MOVD r2, t2
    MOVD r3, t3

    ///////////// d^2 = RR -> r0, r1, r2, r3
    MOVD ·RR<>+0x10(SB), r0
    MOVD ·RR<>+0x18(SB), r1
    MOVD ·RR<>+0x20(SB), r2
    MOVD ·RR<>+0x28(SB), r3

    SubInternal() // x1 ^2 - d^2
    MOVD r0, a0-96(SP);
    MOVD r1, a1-88(SP);
    MOVD r2, a2-80(SP);
    MOVD r3, a3-72(SP); // a -> x1 ^2 - d^2

    MOVD r0, t0;
    MOVD r1, t1;
    MOVD r2, t2;
    MOVD r3, t3;
    AddInternal() // 2 * (x1 ^2 - d^2 )

    MOVD $a0-96(SP), a_ptr;

    LDP (16*0)(a_ptr),(t0, t1)
    LDP (16*1)(a_ptr),(t2, t3)
    AddInternal() // 3 * (x1 ^2 - d^2 )
    MOVD r0, a0-96(SP);
    MOVD r1, a1-88(SP);
    MOVD r2, a2-80(SP);
    MOVD r3, a3-72(SP); // a-> 3 *( x1 ^2 - d^2 )

    MOVD $b0-32(SP), a_ptr;
    p256SqrInline() // b^2
    MOVD res+0(FP), a_ptr
    ADD $32, a_ptr
    STP (r0, r1), (16*0)(a_ptr)
    STP (r2, r3), (16*1)(a_ptr)

    MOVD in+8(FP), b_ptr
    p256MulInline() // b^2 * x1
    MOVD r4, b0-32(SP)
    MOVD r5, b1-24(SP)
    MOVD r0, b2-16(SP)
    MOVD r1, b3-8(SP) // b -> b^2 * x1

    MOVD $a0-96(SP), a_ptr;
    p256SqrInline() // a^2

    MOVD r0, t0
    MOVD r1, t1
    MOVD r2, t2
    MOVD r3, t3

    MOVD $b0-32(SP), a_ptr;
    LDP (16*0)(a_ptr), (r0, r1)
    LDP (16*1)(a_ptr), (r2, r3)
    SubInternal() // a^2 -b

    MOVD r0, t0
    MOVD r1, t1
    MOVD r2, t2
    MOVD r3, t3
    MOVD $b0-32(SP), a_ptr;
    LDP (16*0)(a_ptr), (r0, r1)
    LDP (16*1)(a_ptr), (r2, r3)
    SubInternal() // x3 ->a^2 - 2 * b
    //x
    MOVD res+0(FP), a_ptr
    STP (r0, r1), (16*0)(a_ptr)
    STP (r2, r3), (16*1)(a_ptr)

    MOVD $b0-32(SP), a_ptr;
    LDP (16*0)(a_ptr), (t0, t1)
    LDP (16*1)(a_ptr), (t2, t3)
    SubInternal() // b^2 *x1 - x3
    MOVD r0, b0-32(SP)
    MOVD r1, b1-24(SP)
    MOVD r2, b2-16(SP)
    MOVD r3, b3-8(SP)

    MOVD $a0-96(SP), a_ptr
    MOVD $b0-32(SP), b_ptr
    p256MulInline() // a (b^2 * x1 - x3)
    MOVD r4, b0-32(SP)
    MOVD r5, b1-24(SP)
    MOVD r0, b2-16(SP)
    MOVD r1, b3-8(SP) // b -> a (b^2 * x1 - x3)

    MOVD res+0(FP), a_ptr
    ADD $32, a_ptr
    p256SqrInline() // y3 = 16*y1 ^4

    EOR hlp, hlp, hlp
    MOVD P<>+0x00(SB), const0
    MOVD P<>+0x08(SB),const1
    MOVD $-1, const2
    ADDS $-1, r0, t0
    ADCS const0, r1, t1
    ADCS const2, r2, t2
    ADCS const1, r3, t3
    ADCS $0, hlp, hlp

    ANDS	$1, r0, ZR
    CSEL	EQ, r0, t0, t0
    CSEL	EQ, r1, t1, t1
    CSEL	EQ, r2, t2, t2
    CSEL	EQ, r3, t3, t3
    AND	r0, hlp, hlp

    EXTR	$1, t0, t1, r0
    EXTR	$1, t1, t2, r1
    EXTR	$1, t2, t3, r2
    EXTR	$1, t3, hlp, r3

    MOVD $b0-32(SP), a_ptr
    LDP (16*0)(a_ptr), (t0, t1)
    LDP (16*1)(a_ptr), (t2, t3)

    SubInternal() //  a (b^2 * x1 - x3) - 8*y1 ^4

    MOVD res+0(FP), a_ptr
    ADD $32, a_ptr
    STP (r0, r1), (16*0)(a_ptr)
    STP (r2, r3), (16*1)(a_ptr)
    RET
// p256IsZero returns 1 in hlp if [r0..r3] represents zero and zero
// otherwise. It writes to [r0..r3], r4 and r5.
#define IsZeroInline() \
    MOVD P<>+0x00(SB), const0; \
    MOVD P<>+0x08(SB),const1; \
    MOVD	$1, t2 \
	ORR	r0, r1, t0  \           // Check if zero mod p256
	ORR	r2, r3, t1 \
	ORR	t1, t0, t0 \
	CMP	$0, t0 \
	CSEL	EQ, t2, ZR, hlp \
	EOR	$-1, r0, t0 \
	EOR	const0, r1, t1 \
	EOR	$-1, r2, t2 \
	EOR	const1, r3, t3 \
	ORR	t0, t1, t0 \
	ORR	t2, t3, t1 \
	ORR	t1, t0, t0 \
	CMP	$0, t0 \
	CSEL	EQ, t2, hlp, hlp

/* ---------------------------------------*/
TEXT ·sm2PointAdd2Asm(SB),NOSPLIT, $192-32
    MOVD in2+16(FP), a_ptr
    ADD $64, a_ptr
    p256SqrInline()
    MOVD r0, u10-32(SP)
    MOVD r1, u11-24(SP)
    MOVD r2, u12-16(SP)
    MOVD r3, u13-8(SP) // u1 = z2 ^2

    MOVD $u10-32(SP),b_ptr
    p256MulInline()
    MOVD r4, s10-64(SP)
    MOVD r5, s11-56(SP)
    MOVD r0, s12-48(SP)
    MOVD r1, s13-40(SP) // s1 = u1 * z2 = z2^3

    MOVD in1+8(FP), a_ptr
    ADD $64, a_ptr
    p256SqrInline()
    MOVD r0, u20-96(SP)
    MOVD r1, u21-88(SP)
    MOVD r2, u22-80(SP)
    MOVD r3, u23-72(SP) // u2 = z1 ^2

    MOVD $u20-96(SP),b_ptr
    p256MulInline()
    MOVD r4, s20-128(SP)
    MOVD r5, s21-120(SP)
    MOVD r0, s22-112(SP)
    MOVD r1, s23-104(SP) // s2 = u2 * z1 = z1^3

    MOVD $u10-32(SP), a_ptr
    MOVD in1+8(FP), b_ptr
    p256MulInline()
    MOVD r4, u10-32(SP)
    MOVD r5, u11-24(SP)
    MOVD r0, u12-16(SP)
    MOVD r1, u13-8(SP) // u1 = u1 * x1

    MOVD $u20-96(SP), a_ptr
    MOVD in2+16(FP), b_ptr
    p256MulInline()
    MOVD r4, t0
    MOVD r5, t1
    MOVD r0, t2
    MOVD r1, t3 // u2 = u2 * x2

    MOVD $u10-32(SP), a_ptr
    LDP (16*0)(a_ptr), (r0, r1)
    LDP (16*1)(a_ptr), (r2, r3)
    SubInternal()
    MOVD r0, h0-160(SP)
    MOVD r1, h1-152(SP)
    MOVD r2, h2-144(SP)
    MOVD r3, h3-136(SP) // h = u2 - u1
    IsZeroInline()//r0-r3, t0-t3, hlp,
    MOVD hlp, hlp1
    MOVD in1+8(FP), a_ptr
    ADD $64, a_ptr
    MOVD in2+16(FP), b_ptr
    ADD $64, b_ptr
    p256MulInline()
    MOVD res+0(FP), a_ptr
    ADD $64, a_ptr
    STP (r4, r5), (16*0)(a_ptr)
    STP (r0, r1), (16*1)(a_ptr) // z3 = z1 * z2

    MOVD $h0-160(SP), b_ptr
    p256MulInline()
    // z
    MOVD res+0(FP), a_ptr
    ADD $64, a_ptr
    STP (r4, r5), (16*0)(a_ptr)
    STP (r0, r1), (16*1)(a_ptr) // z3 = z1 * z2 * h

    MOVD $s10-64(SP), a_ptr
    MOVD in1+8(FP), b_ptr
    ADD $32, b_ptr
    p256MulInline()
    MOVD r4, s10-64(SP)
    MOVD r5, s11-56(SP)
    MOVD r0, s12-48(SP)
    MOVD r1, s13-40(SP) // s1 = s1 * y1

    MOVD $s20-128(SP), a_ptr
    MOVD in2+16(FP), b_ptr
    ADD $32, b_ptr
    p256MulInline()
    MOVD r4, t0
    MOVD r5, t1
    MOVD r0, t2
    MOVD r1, t3 // s2 * y2

    MOVD $s10-64(SP), a_ptr
    LDP (16*0)(a_ptr), (r0, r1)
    LDP (16*1)(a_ptr), (r2, r3)
    SubInternal()
    MOVD r0, m0-192(SP)
    MOVD r1, m1-184(SP)
    MOVD r2, m2-176(SP)
    MOVD r3, m3-168(SP) // m = s2* y2 - s1 * y1

    IsZeroInline()
    AND hlp, hlp1, hlp1

    MOVD $h0-160(SP), a_ptr
    p256SqrInline()
    MOVD r0, u20-96(SP)
    MOVD r1, u21-88(SP)
    MOVD r2, u22-80(SP)
    MOVD r3, u23-72(SP) // u2 = h^2

    MOVD $u20-96(SP), a_ptr
    MOVD $u10-32(SP), b_ptr
    p256MulInline()
    MOVD r4, u10-32(SP)
    MOVD r5, u11-24(SP)
    MOVD r0, u12-16(SP)
    MOVD r1, u13-8(SP) // u1 = u2 * u1 = u1 * h^2

    MOVD $h0-160(SP), a_ptr
    MOVD $u20-96(SP), b_ptr
    p256MulInline()
    MOVD r4, h0-160(SP)
    MOVD r5, h1-152(SP)
    MOVD r0, h2-144(SP)
    MOVD r1, h3-136(SP) // h = u2 * h = h^3

    MOVD $m0-192(SP), a_ptr
    p256SqrInline()
    MOVD r0, t0
    MOVD r1, t1
    MOVD r2, t2
    MOVD r3, t3 // m^2

    MOVD $h0-160(SP), a_ptr
    LDP (16*0)(a_ptr), (r0, r1)
    LDP (16*1)(a_ptr), (r2, r3)
    SubInternal() // m^2 - h
    MOVD r0, t0
    MOVD r1, t1
    MOVD r2, t2
    MOVD r3, t3

    MOVD $u10-32(SP), a_ptr
    LDP (16*0)(a_ptr), (r0, r1)
    LDP (16*1)(a_ptr), (r2, r3)
    SubInternal() // m^2 -h - u1
    MOVD r0, t0
    MOVD r1, t1
    MOVD r2, t2
    MOVD r3, t3
    MOVD $u10-32(SP), a_ptr
    LDP (16*0)(a_ptr), (r0, r1)
    LDP (16*1)(a_ptr), (r2, r3)
    SubInternal() // m^2 -h - u1 - u1
    //x
    MOVD res+0(FP), a_ptr
    STP (r0, r1), (16*0)(a_ptr)
    STP (r2, r3), (16*1)(a_ptr)

    MOVD $u10-32(SP), a_ptr
    LDP (16*0)(a_ptr), (t0, t1)
    LDP (16*1)(a_ptr), (t2, t3)
    SubInternal()
    MOVD r0, u10-32(SP)
    MOVD r1, u11-24(SP)
    MOVD r2, u12-16(SP)
    MOVD r3, u13-8(SP) // u1 = u1 - x3

    MOVD $s10-64(SP), a_ptr
    MOVD $h0-160(SP), b_ptr
    p256MulInline()
    MOVD r4, s10-64(SP)
    MOVD r5, s11-56(SP)
    MOVD r0, s12-48(SP)
    MOVD r1, s13-40(SP) // s1 = s1 * h

    MOVD $m0-192(SP), a_ptr
    MOVD $u10-32(SP), b_ptr
    p256MulInline()
    MOVD r4, t0
    MOVD r5, t1
    MOVD r0, t2
    MOVD r1, t3 // m0 * u1

    MOVD $s10-64(SP), a_ptr
    LDP (16*0)(a_ptr), (r0, r1)
    LDP (16*1)(a_ptr), (r2, r3)
    SubInternal() //m0 * u1 - s1

    //y
    MOVD res+0(FP), a_ptr
    ADD $32, a_ptr
    STP (r0, r1), (16*0)(a_ptr)
    STP (r2, r3), (16*1)(a_ptr)

    MOVD hlp1, res+24(FP)
    RET

/* ---------------------------------------*/
TEXT ·sm2PointAdd1Asm(SB),NOSPLIT, $160-32

    MOVD in1+8(FP), a_ptr
    ADD $64, a_ptr
    p256SqrInline()
    MOVD r0, u20-32(SP)
    MOVD r1, u21-24(SP)
    MOVD r2, u22-16(SP)
    MOVD r3, u23-8(SP) // u2 = z1 ^2

    MOVD $u20-32(SP), b_ptr
    p256MulInline()
    MOVD r4, s20-64(SP)
    MOVD r5, s21-56(SP)
    MOVD r0, s22-48(SP)
    MOVD r1, s23-40(SP) // s2 = u2 * z1 = z1^3

    MOVD $u20-32(SP), a_ptr
    MOVD in2+16(FP), b_ptr
    p256MulInline()
    MOVD r4, t0
    MOVD r5, t1
    MOVD r0, t2
    MOVD r1, t3 // u2 * x2

    MOVD in1+8(FP), a_ptr
    LDP (16*0)(a_ptr), (r0, r1)
    LDP (16*1)(a_ptr), (r2, r3)
    SubInternal() // u2 - x1
    MOVD r0, h0-96(SP)
    MOVD r1, h1-88(SP)
    MOVD r2, h2-80(SP)
    MOVD r3, h3-72(SP) // h = u2 - x1


    MOVD in1+8(FP), a_ptr
    ADD $64, a_ptr

    MOVD $h0-96(SP), b_ptr
    p256MulInline()
    MOVD res+0(FP), a_ptr
    ADD $64, a_ptr
    STP (r4, r5), (16*0)(a_ptr)
    STP (r0, r1), (16*1)(a_ptr) // z3 = z1 * h

    MOVD $s20-64(SP), a_ptr
    MOVD in2+16(FP), b_ptr
    ADD $32, b_ptr
    p256MulInline()
    MOVD r4, t0
    MOVD r5, t1
    MOVD r0, t2
    MOVD r1, t3 // s2 * y2

    MOVD in1+8(FP), a_ptr
    ADD $32, a_ptr
    LDP (16*0)(a_ptr), (r0, r1)
    LDP (16*1)(a_ptr), (r2, r3)
    SubInternal()
    MOVD r0, m0-128(SP)
    MOVD r1, m1-120(SP)
    MOVD r2, m2-112(SP)
    MOVD r3, m3-104(SP) // m = s2* y2 - y1

    MOVD $h0-96(SP), a_ptr
    p256SqrInline()
    MOVD r0, u20-32(SP)
    MOVD r1, u21-24(SP)
    MOVD r2, u22-16(SP)
    MOVD r3, u23-8(SP) // u2 = h^2

    MOVD $u20-32(SP), a_ptr
    MOVD in1+8(FP), b_ptr
    p256MulInline()
    MOVD r4, u10-160(SP)
    MOVD r5, u11-152(SP)
    MOVD r0, u12-144(SP)
    MOVD r1, u13-136(SP) // u1 = u2 * x1 = x1 * h^2

    MOVD $h0-96(SP), a_ptr
    MOVD $u20-32(SP), b_ptr
    p256MulInline()
    MOVD r4, h0-96(SP)
    MOVD r5, h1-88(SP)
    MOVD r0, h2-80(SP)
    MOVD r1, h3-72(SP) // h = u2 * h = h^3

    MOVD $m0-128(SP), a_ptr
    p256SqrInline()
    MOVD r0, t0
    MOVD r1, t1
    MOVD r2, t2
    MOVD r3, t3 // m^2

    MOVD $h0-96(SP), a_ptr
    LDP (16*0)(a_ptr), (r0, r1)
    LDP (16*1)(a_ptr), (r2, r3)
    SubInternal() // m^2 - h
    MOVD r0, t0
    MOVD r1, t1
    MOVD r2, t2
    MOVD r3, t3

    MOVD $u10-160(SP), a_ptr
    LDP (16*0)(a_ptr), (r0, r1)
    LDP (16*1)(a_ptr), (r2, r3)
    SubInternal() // m^2 -h - u1
    MOVD r0, t0
    MOVD r1, t1
    MOVD r2, t2
    MOVD r3, t3

    MOVD $u10-160(SP), a_ptr
    LDP (16*0)(a_ptr), (r0, r1)
    LDP (16*1)(a_ptr), (r2, r3)
    SubInternal() // m^2 -h - u1 - u1
    //x
    MOVD res+0(FP), a_ptr
    STP (r0, r1), (16*0)(a_ptr)
    STP (r2, r3), (16*1)(a_ptr)

    MOVD $u10-160(SP), a_ptr
    LDP (16*0)(a_ptr), (t0, t1)
    LDP (16*1)(a_ptr), (t2, t3)
    SubInternal()
    MOVD r0, u10-160(SP)
    MOVD r1, u11-152(SP)
    MOVD r2, u12-144(SP)
    MOVD r3, u13-136(SP) // u1 = u1 - x3

    MOVD in1+8(FP), a_ptr
    ADD $32, a_ptr

    MOVD $h0-96(SP), b_ptr
    p256MulInline()
    MOVD r4, h0-96(SP)
    MOVD r5, h1-88(SP)
    MOVD r0, h2-80(SP)
    MOVD r1, h3-72(SP) // h = y1 * h

    MOVD $m0-128(SP), a_ptr
    MOVD $u10-160(SP), b_ptr
    p256MulInline()
    MOVD r4, t0
    MOVD r5, t1
    MOVD r0, t2
    MOVD r1, t3 // m0 * u1

    MOVD $h0-96(SP), a_ptr
    LDP (16*0)(a_ptr), (r0, r1)
    LDP (16*1)(a_ptr), (r2, r3)
    SubInternal() //m0 * u1 - h

    //y
     MOVD res+0(FP), a_ptr
     ADD $32, a_ptr
     STP (r0, r1), (16*0)(a_ptr)
     STP (r2, r3), (16*1)(a_ptr)

     RET

/* ---------------------------------------*/
// Constant time point access to arbitrary point table.
// Indexed from 1 to 15, with -1 offset
// (index 0 is implicitly point at infinity)
// func p256Select(point, table []uint64, idx int)
TEXT ·p256Select(SB),NOSPLIT,$0
	MOVD	idx+16(FP), const0
	MOVD	table+8(FP), b_ptr
	MOVD	point+0(FP), a_ptr

	EOR	r0, r0, r0 
	EOR	r1, r1, r1
	EOR	r2, r2, r2
	EOR	r3, r3, r3
	EOR	r4, r4, r4
	EOR	r5, r5, r5
	EOR	r6, r6, r6
	EOR	r7, r7, r7
	EOR	t0, t0, t0
	EOR	t1, t1, t1
	EOR	t2, t2, t2
	EOR	t3, t3, t3

	MOVD	$0, const1

loop_select:
		ADD	$1, const1
		CMP	const0, const1
		LDP.P	16(b_ptr), (a, b)
		CSEL	EQ, a, r0, r0 
		CSEL	EQ, b, r1, r1
		LDP.P	16(b_ptr), (a, b)
		CSEL	EQ, a, r2, r2
		CSEL	EQ, b, r3, r3
		LDP.P	16(b_ptr), (a, b)
		CSEL	EQ, a, r4, r4
		CSEL	EQ, b, r5, r5
		LDP.P	16(b_ptr), (a, b)
		CSEL	EQ, a, r6, r6
		CSEL	EQ, b, r7, r7
		LDP.P	16(b_ptr), (a, b)
		CSEL	EQ, a, t0, t0
		CSEL	EQ, b, t1, t1
		LDP.P	16(b_ptr), (a, b)
		CSEL	EQ, a, t2, t2
		CSEL	EQ, b, t3, t3

		CMP	$16, const1
		BNE	loop_select

	STP	(r0, r1), 0*16(a_ptr)
	STP	(r2, r3), 1*16(a_ptr)
	STP	(r4, r5), 2*16(a_ptr)
	STP	(r6, r7), 3*16(a_ptr)
	STP	(t0, t1), 4*16(a_ptr)
	STP	(t2, t3), 5*16(a_ptr)
	RET

/* ---------------------------------------*/
// func p256NegCond(val []uint64, cond int)
TEXT ·p256NegCond(SB),NOSPLIT,$0
	MOVD	val+0(FP), a_ptr
	MOVD	cond+8(FP), b_ptr
	// acc = poly
	MOVD $-1, r0
	MOVD P<>+0x00(SB), r1
    MOVD $-1, r2
    MOVD P<>+0x08(SB),r3
	// Load the original value
	LDP	0*16(a_ptr), (t0, t1)
	LDP	1*16(a_ptr), (t2, t3)
	// Speculatively subtract
	SUBS	t0, r0
	SBCS	t1, r1
	SBCS	t2, r2
	SBC	t3, r3
	// If condition is 0, keep original value
	CMP	$0, b_ptr
	CSEL	EQ, t0, r0, r0
	CSEL	EQ, t1, r1, r1
	CSEL	EQ, t2, r2, r2
	CSEL	EQ, t3, r3, r3
	// Store result
	STP	(r0, r1), 0*16(a_ptr)
	STP	(r2, r3), 1*16(a_ptr)

	RET

/* ---------------------------------------*/
// func p256MovCond(res, a, b []uint64, cond int)
// If cond == 0 res=b, else res=a
TEXT ·p256MovCond(SB),NOSPLIT,$0
	MOVD	res+0(FP), hlp1
	MOVD	ina+8(FP), a_ptr
	MOVD	inb+16(FP), b_ptr
	MOVD	cond+24(FP), R3

	CMP	$0, R3
	// Two remarks:
	// 1) Will want to revisit NEON, when support is better
	// 2) CSEL might not be constant time on all ARM processors
	LDP	0*16(a_ptr), (R4, R5)
	LDP	1*16(a_ptr), (R6, R7)
	LDP	2*16(a_ptr), (R8, R9)
	LDP	0*16(b_ptr), (R16, R17)
	LDP	1*16(b_ptr), (R19, R20)
	LDP	2*16(b_ptr), (R21, R22)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	CSEL	EQ, R21, R8, R8
	CSEL	EQ, R22, R9, R9
	STP	(R4, R5), 0*16(hlp1)
	STP	(R6, R7), 1*16(hlp1)
	STP	(R8, R9), 2*16(hlp1)

	LDP	3*16(a_ptr), (R4, R5)
	LDP	4*16(a_ptr), (R6, R7)
	LDP	5*16(a_ptr), (R8, R9)
	LDP	3*16(b_ptr), (R16, R17)
	LDP	4*16(b_ptr), (R19, R20)
	LDP	5*16(b_ptr), (R21, R22)
	CSEL	EQ, R16, R4, R4
	CSEL	EQ, R17, R5, R5
	CSEL	EQ, R19, R6, R6
	CSEL	EQ, R20, R7, R7
	CSEL	EQ, R21, R8, R8
	CSEL	EQ, R22, R9, R9
	STP	(R4, R5), 3*16(hlp1)
	STP	(R6, R7), 4*16(hlp1)
	STP	(R8, R9), 5*16(hlp1)

	RET

/* ---------------------------------------*/
// Constant time point access to base point table.
// func p256SelectBase(point, table []uint64, idx int)
TEXT ·p256SelectBase(SB),NOSPLIT,$0
	MOVD	index+8(FP), t0
	LSL $11, t0, t0
	MOVD $·precomputed<>(SB), t1
	ADD t0, t1
	MOVD point+0(FP), a_ptr
    MOVD idx+16(FP), t0

	EOR	r0, r0, r0
	EOR	r1, r1, r1
	EOR	r2, r2, r2
	EOR	r3, r3, r3
	EOR	r4, r4, r4
	EOR	r5, r5, r5
	EOR	r6, r6, r6
	EOR	r7, r7, r7

	MOVD	$0, t2

loop_select:
		ADD	$1, t2
		CMP	t0, t2
		LDP.P	16(t1), (a, b)
		CSEL	EQ, a, r0, r0
		CSEL	EQ, b, r1, r1
		LDP.P	16(t1), (a, b)
		CSEL	EQ, a, r2, r2
		CSEL	EQ, b, r3, r3
		LDP.P	16(t1), (a, b)
		CSEL	EQ, a, r4, r4
		CSEL	EQ, b, r5, r5
		LDP.P	16(t1), (hlp, hlp1)
		CSEL	EQ, hlp, r6, r6
		CSEL	EQ, hlp1, r7, r7

		CMP	$32, t2
		BNE	loop_select

	STP	(r0, r1), 0*16(a_ptr)
	STP	(r2, r3), 1*16(a_ptr)
	STP	(r4, r5), 2*16(a_ptr)
	STP	(r6, r7), 3*16(a_ptr)
	RET
/* ---------------------------------------*/

DATA N_<>+0x00(SB)/8,$0x327f9e8872350975   //R * RInv - N * N_ = 1
DATA N<>+0x00(SB)/8, $0x53bbf40939d54123
DATA N<>+0x08(SB)/8, $0x7203df6b21c6052b
DATA N<>+0x10(SB)/8, $0xffffffffffffffff   //e64 - 1
DATA N<>+0x18(SB)/8, $0xfffffffeffffffff
GLOBL N_<>(SB), 8, $8
GLOBL N<>(SB), 8, $32

#define maySubN(in1, in2, in3, in4, in5) \
    MOVD N<>+0x00(SB), const0; \
    MOVD N<>+0x08(SB), const1; \
    MOVD N<>+0x10(SB), const2; \
    MOVD N<>+0X18(SB), hlp1; \
    SUBS const0, in1, a ; \
    SBCS const1, in2, b; \
    SBCS const2, in3, c; \
    SBCS hlp1, in4, d; \
    SBCS $0, in5, in5; \
    CSEL CS ,a, in1, in1; \
    CSEL CS ,b, in2, in2; \
    CSEL CS ,c, in3, in3; \
    CSEL CS ,d, in4, in4;

#define mayAddN(in1, in2, in3, in4, in5) \
    MOVD N<>+0x00(SB), const0; \
    MOVD N<>+0x08(SB), const1; \
    MOVD N<>+0x10(SB), const2; \
    MOVD N<>+0X18(SB), hlp1; \
    ADDS const0, in1, a; \
    ADCS const1, in2, b; \
    ADCS const2, in3, c; \
    ADCS hlp1, in4, d; \
    ANDS $1, in5; \
    CSEL	EQ, in1, a, in1 \
    CSEL	EQ, in2, b, in2 \
    CSEL	EQ, in3, c, in3 \
    CSEL	EQ, in4, d, in4

#define orderREDC(v0, v1, v2, v3, v4, v5) \
    MOVD N_<>+0x00(SB), const0;\
    MUL const0, v0, hlp; \
    MOVD N<>+0x00(SB), const0; MUL const0, hlp, L; UMULH const0, hlp, H;\
    ADDS L, v0, v0; ADCS H, v1, v1; \
    MOVD N<>+0x08(SB), const0; MUL const0, hlp, L; UMULH const0, hlp, H; ADCS $0, H, H ;\
    ADDS L, v1, v1; ADCS H, v2, v2; \
    MOVD N<>+0x10(SB), const0; MUL const0, hlp, L; UMULH const0, hlp, H; ADCS $0, H, H; \
    ADDS L, v2, v2; ADCS H, v3, v3; \
    MOVD N<>+0x18(SB), const0; MUL const0, hlp, L; UMULH const0, hlp, H; ADCS $0, H, H; \
    ADDS L, v3, v3; ADCS H, v4, v4; ADCS $0, v5, v5;

#define orderREDCForSqr(v0, v1, v2, v3)\
    MOVD N_<>+0x00(SB), const0;\
    MUL const0, v0, hlp; \
    MOVD N<>+0x00(SB), const0; MUL const0, hlp, L; UMULH const0, hlp, H;\
    ADDS L, v0, v0; ADCS H, v1, v1; \
    MOVD N<>+0x08(SB), const0; MUL const0, hlp, L; UMULH const0, hlp, H; ADCS $0, H, H ;\
    ADDS L, v1, v1; ADCS H, v2, v2; \
    MOVD N<>+0x10(SB), const0; MUL const0, hlp, L; UMULH const0, hlp, H; ADCS $0, H, H; \
    ADDS L, v2, v2; ADCS H, v3, v3; \
    MOVD N<>+0x18(SB), const0; MUL const0, hlp, L; UMULH const0, hlp, H; ADCS $0, H, H; \
    ADDS L, v3, v3; ADCS H, v0, v0;


// input is a_ptr b_ptr
// result r4 r5 r0 r1
#define orderMulInline() \
    EOR r2, r2, r2; EOR r3, r3, r3; EOR r4, r4, r4; EOR r5, r5, r5; \
    MOVD (8*0)(b_ptr), t0; \
    LDP (16*0)(a_ptr), (a, b); LDP (16*1)(a_ptr),(c, d); \
    MUL a, t0, r0; UMULH a, t0, r1; \
    MUL b, t0, t1; UMULH b, t0, r2;ADDS t1, r1, r1; \
    MUL c, t0, t1; UMULH c, t0, r3;ADCS t1, r2, r2; \
    MUL d, t0, t1; UMULH d, t0, r4;ADCS t1, r3, r3; ADCS $0, r4, r4;\
    orderREDC(r0, r1, r2, r3, r4, r5) \
    single(1, r1, r2, r3, r4, r5, r0)                        \ // x * y[1]
	orderREDC(r1, r2, r3, r4, r5, r0)                             \
	single(2, r2, r3, r4, r5, r0, r1)                        \ // x * y[2]
	orderREDC(r2, r3, r4, r5, r0, r1)                             \
	single(3, r3, r4, r5, r0, r1, r2)                        \ // x * y[3]
	orderREDC(r3, r4, r5, r0, r1, r2)                              \// now result in r4 r5 r0 r1 r2
	maySubN(r4, r5, r0, r1, r2)

// result r4 r5 r0 r1
#define orderMulInlineSmall() \
    EOR r2, r2, r2; EOR r3, r3, r3; EOR r4, r4, r4; EOR r5, r5, r5; \
    MOVD (8*0)(b_ptr), t0; \
    LDP (16*0)(a_ptr), (a, b); LDP (16*1)(a_ptr),(c, d); \
    MUL a, t0, r0; UMULH a, t0, r1; \
    MUL b, t0, t1; UMULH b, t0, r2;ADDS t1, r1, r1; \
    MUL c, t0, t1; UMULH c, t0, r3;ADCS t1, r2, r2; \
    MUL d, t0, t1; UMULH d, t0, r4;ADCS t1, r3, r3; ADCS $0, r4, r4;\
    orderREDC(r0, r1, r2, r3, r4, r5) \
    orderREDC(r1, r2, r3, r4, r5, r0)                             \
	orderREDC(r2, r3, r4, r5, r0, r1)                             \
	orderREDC(r3, r4, r5, r0, r1, r2)                              \// now result in r4 r5 r0 r1 r2
	maySubN(r4, r5, r0, r1, r2)

/* ---------------------------------------*/
// func orderMul(a, b *[4]uint64)
//R * RInv - N * N_ = 1
// it's not MF, if R = e64, N_ =  327f9e8872350975
TEXT ·orderMul(SB),NOSPLIT,$0
    MOVD ina+8(FP), a_ptr
    MOVD inb+16(FP), b_ptr
    orderMulInline()
    MOVD res+0(FP), a_ptr
    STP (r4, r5), (16*0)(a_ptr)
    STP (r0, r1), (16*1)(a_ptr)
    RET

TEXT ·smallOrderMul(SB),NOSPLIT,$0
    MOVD ina+8(FP), a_ptr
    MOVD inb+16(FP), b_ptr
    orderMulInlineSmall()
    MOVD res+0(FP), a_ptr
    STP (r4, r5), (16*0)(a_ptr)
    STP (r0, r1), (16*1)(a_ptr)
    RET

// input a_ptr
// output r0 r1 r2 r3
#define orderSqrInline() \
    LDP (16*0)(a_ptr), (a, b); LDP (16*1)(a_ptr),(c, d); \
    MUL a, b, r1; UMULH a, b, r2; \
    MUL a, c, t1; UMULH a, c, r3; ADDS t1, r2, r2; \
    MUL a, d, t1; UMULH a, d, r4; ADCS t1, r3, r3; ADCS $0, r4, r4; \
    MUL b, c, t1; UMULH b, c, t2; ADDS t1, r3, r3; ADCS t2, r4, r4; \
    MUL b, d, t1; UMULH b, d, r5; ADCS $0, r5, r5; ADDS t1, r4, r4; \
    MUL c, d, t1; UMULH c, d, r6; ADCS t1, r5, r5; ADCS $0, r6, r6; \
    EOR r7, r7, r7; \
    ADDS r1, r1, r1; ADCS r2, r2, r2; ADCS r3, r3, r3; ADCS r4, r4, r4; ADCS r5, r5, r5; ADCS r6, r6, r6; ADCS $0, r7, r7; \
    MUL a, a, r0; UMULH a, a, H; ADDS H, r1, r1; \
    MUL b, b, t1; UMULH b, b, H; ADCS t1, r2, r2; ADCS H, r3, r3; \
    MUL c, c, t1; UMULH c, c, H; ADCS t1, r4, r4;  ADCS H, r5, r5; \
    MUL d, d, t1; UMULH d, d, t2; ADCS t1, r6, r6; ADCS t2, r7, r7;\
    orderREDCForSqr(r0, r1, r2, r3)                                                          \
    orderREDCForSqr(r1, r2, r3, r0)                                                          \
    orderREDCForSqr(r2, r3, r0, r1)                                                          \
    orderREDCForSqr(r3, r0, r1, r2) \
    EOR H,H, H; ADDS r4, r0, r0; ADCS r5, r1, r1; ADCS r6, r2, r2; ADCS r7, r3, r3; ADCS $0, H, H;\
    maySubN(r0, r1, r2, r3, H)

/* ---------------------------------------*/
// func orderSqr( res, in *[4]uint64, n int)
TEXT ·orderSqr(SB),NOSPLIT,$0
    MOVD in+8(FP), a_ptr
    MOVD n+16(FP), b_ptr
orderSqrLoop:
    SUB $1, b_ptr
    orderSqrInline()
    MOVD res+0(FP), hlp
    STP (r0, r1), (16*0)(hlp)
    STP (r2, r3), (16*1)(hlp)
    MOVD hlp, a_ptr
    CBNZ b_ptr, orderSqrLoop;

    RET

TEXT ·orderAdd(SB), NOSPLIT, $16-0
    MOVD ina+8(FP), a_ptr
    MOVD inb+16(FP), b_ptr
    LDP 16*0(a_ptr), (r0, r1)
    LDP 16*1(a_ptr), (r2, r3)
    EOR hlp, hlp, hlp;
    LDP (16*0)(b_ptr), (a, b); LDP (16*1)(b_ptr),(c, d);
    ADDS a, r0, r0;
    ADCS b, r1, r1;
    ADCS c, r2, r2;
    ADCS d, r3, r3;
    ADCS $0, hlp, hlp;
    maySubN(r0, r1, r2, r3, hlp)
    MOVD res+0(FP), a_ptr
    STP (r0, r1), (16*0)(a_ptr)
    STP (r2, r3), (16*1)(a_ptr)
    RET

/* ---------------------------------------*/
TEXT ·orderSub(SB), NOSPLIT, $16-0
    MOVD ina+8(FP), a_ptr
    MOVD inb+16(FP), b_ptr
    LDP 16*0(a_ptr), (r0, r1)
    LDP 16*1(a_ptr), (r2, r3)
    EOR hlp, hlp, hlp;
    LDP (16*0)(b_ptr), (a, b)
    LDP (16*1)(b_ptr), (c, d);
    SUBS a, r0, r0;
    SBCS b, r1, r1;
    SBCS c, r2, r2;
    SBCS d, r3, r3;
    SBCS $0, hlp, hlp;
    mayAddN(r0, r1, r2, r3, hlp)
    MOVD res+0(FP), a_ptr
    STP (r0, r1), (16*0)(a_ptr)
    STP (r2, r3), (16*1)(a_ptr)
    RET

/* ---------------------------------------*/
//func biggerThan(a, b *[4]uint64) bool
TEXT ·biggerThan(SB), NOSPLIT, $0
    MOVD ina+0(FP), a_ptr
    MOVD inb+8(FP), b_ptr
    MOVD $1, t1
    EOR t2, t2, t2
    LDP (16*0)(a_ptr), (r0, r1)
    LDP (16*1)(a_ptr), (r2, r3)
    LDP (16*0)(b_ptr), (r4, r5)
    LDP (16*1)(b_ptr), (r6, r7)
    SUBS r0, r4, r4;
    SBCS r1, r5, r5;
    SBCS r2, r6, r6;
    SBCS r3, r7, r7;
    CSEL CS ,t2, t1, t1;
    MOVD t1, res+16(FP)
    RET








