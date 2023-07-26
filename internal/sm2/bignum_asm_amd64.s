#include "textflag.h"
#include "precomputed.h"

#define H DI
#define L SI
#define r0 R8
#define r1 R9
#define r2 R10
#define r3 R11
#define r4 R12
#define r5 R13
#define a_ptr R14
#define b_ptr R15

#define a (8*0)(a_ptr)
#define b (8*1)(a_ptr)
#define c (8*2)(a_ptr)
#define d (8*3)(a_ptr)
#define r6 BX
#define r7 CX

// ffffffffffffffff ffffffff00000000 ffffffffffffffff fffffffeffffffff
DATA ·P<>+0x00(SB) /8, $0xffffffff00000000
DATA ·P<>+0x08(SB) /8, $0xfffffffeffffffff
GLOBL ·P<>(SB), RODATA, $16

// REDC(~) : return (n, v1, v2, v3, v4) /e64 mod p, result in (v1, v2, v3, v4, v5)
// (v1, v2, v3, v4, v5) <= n * RInv + (v1, v2, v3, v4, v5)
// v5 should be zero
#define REDC(n, v1, v2, v3, v4, v5) \
	MOVQ n, H; MOVQ n, L; SHRQ $32, H; SHLQ $32, L;                \
	ADDQ n, v1; ADCQ $0, v2; ADCQ $0, v3; ADCQ n, v4; ADCQ $0, v5; \
	SUBQ L, v1; SBBQ H, v2; SBBQ L, v3; SBBQ H, v4; SBBQ $0, v5
// todo uising mulxq
#define single(i, v0, v1, v2, v3, v4, v5) \
	MOVQ (8*i)(b_ptr), DX; \ // a[0] x b[i]
	MULXQ (8*0)(a_ptr), AX, CX; \
	ADDQ AX, v0;           \
	                       \
	ADCQ CX, v1;           \
	MULXQ (8*1)(a_ptr), AX,CX; \ // a[1] x b[i]
	ADCQ $0, CX;           \
	ADDQ AX, v1;           \
	                       \
	ADCQ CX, v2;           \
	MULXQ (8*2)(a_ptr), AX,CX;\ // a[2] x b[i]
	ADCQ $0, CX;           \
	ADDQ AX, v2;           \
	                       \
    ADCQ CX, v3;           \
    MULXQ (8*3)(a_ptr), AX,CX;\
	ADCQ $0, CX;           \
	ADCQ AX, v3;           \
	ADCQ CX, v4;           \
	ADCQ $0, v0;           \
	XORQ v5, v5

#define maySubP(in1, in2, in3, in4, in5) \
	MOVQ    in1, AX; MOVQ in2, BX; MOVQ in3, CX; MOVQ in4, DX;                                       \
	SUBQ    $-1, in1; SBBQ ·P<>+0x00(SB), in2; SBBQ $-1, in3; SBBQ ·P<>+0x08(SB), in4; SBBQ $0, in5; \
	CMOVQCS AX, in1; CMOVQCS BX, in2; CMOVQCS CX, in3; CMOVQCS DX, in4;                              \

// input is a_ptr b_ptr
// result r4 r5 r0 r1
#define p256MulInline() \
	XORQ r2, r2; XORQ r3, r3; XORQ r4, r4; XORQ r5, r5;      \
    MOVQ (8*0)(b_ptr), DX; MULXQ a,r0, r1; \
	MULXQ b,AX,r2; ADDQ AX, r1; \
	MULXQ c,AX,r3; ADCQ AX, r2; \
	MULXQ d,AX,r4; ADCQ AX, r3; ADCQ $0, r4; \ // a * b[0]
	REDC(r0, r1, r2, r3, r4, r5)                             \
	single(1, r1, r2, r3, r4, r5, r0)                        \ // x * y[1]
	REDC(r1, r2, r3, r4, r5, r0)                             \
	single(2, r2, r3, r4, r5, r0, r1)                        \ // x * y[2]
	REDC(r2, r3, r4, r5, r0, r1)                             \
	single(3, r3, r4, r5, r0, r1, r2)                        \ // x * y[3]
	REDC(r3, r4, r5, r0, r1, r2)                             \ // now result in r4 r5 r0 r1 r2
	maySubP(r4, r5, r0, r1, r2)

// func p256Mul(a, b *[4]uint64)
TEXT ·p256Mul(SB), NOSPLIT, $64-16
	MOVQ ina+8(FP), a_ptr
	MOVQ inb+16(FP), b_ptr
	p256MulInline()
	MOVQ res+0(FP), a_ptr
	MOVQ r4, (8*0)(a_ptr)
	MOVQ r5, (8*1)(a_ptr)
	MOVQ r0, (8*2)(a_ptr)
	MOVQ r1, (8*3)(a_ptr)
	RET

// ---------------------------------V

// REDC(~) : return a0 /e64 mod p, result in (a0, a1, a2, a3)
// (a0, a1, a2, a3) <= a0 * RInv mod p
#define REDCForSqr(a0, a1, a2, a3) \
	MOVQ a0, H; MOVQ a0, L; SHRQ $32, H; SHLQ $32, L;   \
	ADDQ a0, a1; ADCQ $0, a2; ADCQ $0, a3; ADCQ $0, a0; \
	SUBQ L, a1; SBBQ H, a2; SBBQ L, a3; SBBQ H, a0

// input a_ptr
// output r0 r1 r2 r3
#define p256SqrInline() \
	MOVQ a, DX; MULXQ b, r1, r2;                                       \ // y[1:] * y[0] => r0 ~ r4
	MULXQ c, AX, r3; ADDQ AX, r2;                          \
	MULXQ d, AX, r4; ADCQ AX, r3; ADCQ $0, r4;                          \
	MOVQ b, DX; MULXQ c,AX, L; ADDQ AX, r3;                           \ // y[2:] * y[1] => r0 ~ r5
	ADCQ L, r4; MULXQ d, AX, r5; ADCQ $0, r5; ADDQ AX, r4; \
	MOVQ c, DX; MULXQ d, AX, r6; ADCQ AX, r5; ADCQ $0, r6;                          \ // y[3] * y[2]  => r0 ~ r6
	XORQ r7, r7; ADDQ r1, r1; ADCQ r2, r2; ADCQ r3, r3;                                 \
	ADCQ r4, r4; ADCQ r5, r5; ADCQ r6, r6; ADCQ $0, r7;                                 \ // *2
	MOVQ a, DX; MULXQ DX, r0, H;                                       \ // Missing products
	ADDQ H, r1; MOVQ b, DX; MULXQ DX, AX, H; ADCQ AX, r2;              \
	ADCQ H, r3; MOVQ c, DX; MULXQ DX, AX, H; ADCQ AX, r4;               \
	MOVQ d, DX; MULXQ DX, AX, DX; ADCQ H, r5; ADCQ AX, r6; ADCQ DX, r7;                          \
	REDCForSqr(r0, r1, r2, r3)                                                          \
	REDCForSqr(r1, r2, r3, r0)                                                          \
	REDCForSqr(r2, r3, r0, r1)                                                          \
	REDCForSqr(r3, r0, r1, r2)                                                          \
	XORQ H, H; ADDQ r4, r0; ADCQ r5, r1; ADCQ r6, r2; ADCQ r7, r3; ADCQ $0, H;          \
	maySubP(r0, r1, r2, r3, H)

// func p256Sqr(res, a *[4]uint64, n int)
TEXT ·p256Sqr(SB), NOSPLIT, $0
	MOVQ in+8(FP), a_ptr
sqrLoop:
	p256SqrInline()
	MOVQ res+0(FP), BX
	MOVQ r0, (8*0)(BX)
	MOVQ r1, (8*1)(BX)
	MOVQ r2, (8*2)(BX)
	MOVQ r3, (8*3)(BX)
	MOVQ BX, a_ptr

	DECQ in+16(FP)
	JNE  sqrLoop
	RET

// --------------------------------A

TEXT ·redc2222(SB), NOSPLIT, $0
	MOVQ in+0(FP), a_ptr
	MOVQ 0(a_ptr), r0
	MOVQ 8(a_ptr), r1
	MOVQ 16(a_ptr), r2
	MOVQ 24(a_ptr), r3
	REDCForSqr(r0,r1,r2,r3)
	MOVQ r1, 0(a_ptr)
	MOVQ r2, 8(a_ptr)
	MOVQ r3, 16(a_ptr)
	MOVQ r0, 24(a_ptr)
	RET


TEXT ·p256Add(SB), NOSPLIT, $16-0
	MOVQ ina+8(FP), a_ptr
	MOVQ inb+16(FP), b_ptr

	MOVQ 0(a_ptr), r0; MOVQ 8(a_ptr), r1; MOVQ 16(a_ptr), r2; MOVQ 24(a_ptr), r3
	XORQ r4, r4

	ADDQ 0(b_ptr), r0
	ADCQ 8(b_ptr), r1
	ADCQ 16(b_ptr), r2
	ADCQ 24(b_ptr), r3
	ADCQ $0, r4

    maySubP(r0, r1, r2, r3, r4)

	MOVQ res+0(FP), a_ptr
	MOVQ r0, 0(a_ptr)
	MOVQ r1, 8(a_ptr)
	MOVQ r2, 16(a_ptr)
	MOVQ r3, 24(a_ptr)

	RET

TEXT ·p256Sub(SB), NOSPLIT, $16-0
	MOVQ ina+8(FP), a_ptr
	MOVQ inb+16(FP), b_ptr

	MOVQ 0(a_ptr), AX; MOVQ 8(a_ptr), BX; MOVQ 16(a_ptr), CX; MOVQ 24(a_ptr), DX
	XORQ R13, R13
	SUBQ 0(b_ptr), AX
	SBBQ 8(b_ptr), BX
	SBBQ 16(b_ptr), CX
	SBBQ 24(b_ptr), DX
	SBBQ $0, R13

	MOVQ AX, r0; MOVQ BX, r1; MOVQ CX, r2; MOVQ DX, r3

	ADDQ $-1, r0
	ADCQ ·P<>+0x00(SB), r1
	ADCQ $-1, r2
	ADCQ ·P<>+0x08(SB), r3
	ANDQ $1, R13

	CMOVQEQ AX, r0
	CMOVQEQ BX, r1
	CMOVQEQ CX, r2
	CMOVQEQ DX, r3

	MOVQ res+0(FP), a_ptr
	MOVQ r0, 0(a_ptr)
	MOVQ r1, 8(a_ptr)
	MOVQ r2, 16(a_ptr)
	MOVQ r3, 24(a_ptr)

	RET

// func mRInv(in *Fp, n uint64)   demo
TEXT ·mRInv(SB), NOSPLIT, $0-16
	MOVQ in1+8(FP), CX
	MOVQ in2+0(FP), R8

	JCXZQ CXZero // if a == 0

	MOVQ CX, H
	MOVQ CX, L
	SHRQ $32, H // e64 - (a >> 32)
	SHLQ $32, L // e64 - (a << 32)
	NOTQ H
	NOTQ L

	MOVQ CX, 0(R8)
	ADDQ L, 0(R8)
	INCQ 0(R8)

	MOVQ H, 8(R8)
	ADCQ $0, 8(R8)

	MOVQ L, 16(R8)

	MOVQ CX, 24(R8)
	ADDQ H, 24(R8)
	RET

CXZero:
	MOVQ $0, 0(R8)
	MOVQ $0, 8(R8)
	MOVQ $0, 16(R8)
	MOVQ $0, 24(R8)
	RET

// func REDC64(in *Fp)   demo
TEXT ·REDC64(SB), NOSPLIT, $0-16
	MOVQ in+0(FP), a_ptr
	MOVQ 0(a_ptr), r0
	MOVQ 8(a_ptr), r1
	MOVQ 16(a_ptr), r2
	MOVQ 24(a_ptr), r3
	XORQ r4, r4
	XORQ r5, r5
	REDC(r0, r1, r2, r3, r4, r5)// (r1, r2, r3, r4, r5) <= r0 * RInv + (r1, r2, r3, r4)
	MOVQ r1, 0(a_ptr)
	MOVQ r2, 8(a_ptr)
	MOVQ r3, 16(a_ptr)
	MOVQ r4, 24(a_ptr)
	RET
//   AX, BX, CX, DX
// + r0, r1, r2, r3
//------------------
//   r0, r1, r2, r3
#define AddInternal() \
     XORQ R13, R13; \
    ADDQ r0, AX \
 	ADCQ r1, BX \
 	ADCQ r2, CX \
 	ADCQ r3, DX \
 	ADCQ $0, R13 \
 	MOVQ AX, r0; MOVQ BX, r1; MOVQ CX, r2; MOVQ DX, r3 \
 	SUBQ $-1, r0 \
 	SBBQ ·P<>+0x00(SB), r1 \
 	SBBQ $-1, r2 \
 	SBBQ ·P<>+0x08(SB), r3 \
 	SBBQ $0, R13 \
 	CMOVQCS AX, r0 \
 	CMOVQCS BX, r1 \
 	CMOVQCS CX, r2 \
 	CMOVQCS DX, r3
//   AX, BX, CX, DX
// - r0, r1, r2, r3
//------------------
//   r0, r1, r2, r3
#define SubInternal() \
	XORQ R13, R13 \
	SUBQ r0, AX \
	SBBQ r1, BX \
	SBBQ r2, CX \
	SBBQ r3, DX \
	SBBQ $0, R13 \
	MOVQ AX, r0; MOVQ BX, r1; MOVQ CX, r2; MOVQ DX, r3 \
	ADDQ $-1, r0 \
	ADCQ ·P<>+0x00(SB), r1 \
	ADCQ $-1, r2 \
	ADCQ ·P<>+0x08(SB), r3 \
	ANDQ $1, R13 \
	CMOVQEQ AX, r0 \
	CMOVQEQ BX, r1 \
	CMOVQEQ CX, r2 \
	CMOVQEQ DX, r3
TEXT ·sm2PointDouble2Asm(SB), NOSPLIT, $96-32

    MOVQ in+8(FP), a_ptr
    ADDQ $64, a_ptr
    p256SqrInline()
    MOVQ r0, d0-32(SP)
    MOVQ r1, d0-24(SP)
    MOVQ r2, d0-16(SP)
    MOVQ r3, d3-8(SP) // d = z1^2

    MOVQ in+8(FP), a_ptr
    ADDQ $32, a_ptr // y
    MOVQ 0(a_ptr), AX;
    MOVQ 8(a_ptr), BX;
    MOVQ 16(a_ptr), CX;
    MOVQ 24(a_ptr), DX;
    MOVQ 0(a_ptr), r0;
    MOVQ 8(a_ptr), r1;
    MOVQ 16(a_ptr), r2;
    MOVQ 24(a_ptr), r3;
    AddInternal()  // 2* y
    //结果在 r0, r1, r2, r3
    MOVQ r0, b0-64(SP)
    MOVQ r1, b1-56(SP)
    MOVQ r2, b2-48(SP)
    MOVQ r3, b3-40(SP) // b = 2*y
    MOVQ a_ptr, b_ptr;
    ADDQ $32, b_ptr; // z
    LEAQ b0-64(SP), a_ptr;
    p256MulInline()// z = 2 * y1 * z1
    MOVQ res+0(FP), a_ptr // res
    ADDQ $64, a_ptr
    MOVQ r4, 0(a_ptr)
    MOVQ r5, 8(a_ptr)
    MOVQ r0, 16(a_ptr)
    MOVQ r1, 24(a_ptr)

    MOVQ in+8(FP), a_ptr
    p256SqrInline() // x1^2
    MOVQ res+0(FP), b_ptr
    MOVQ r0, a0-96(SP);
    MOVQ r1, a1-88(SP);
    MOVQ r2, a2-80(SP);
    MOVQ r3, a3-72(SP); // a -> x1 ^2

    LEAQ d0-32(SP), a_ptr;
    p256SqrInline() // d^2 -> r0, r1, r2, r3
    MOVQ a0-96(SP), AX;
    MOVQ a1-88(SP), BX;
    MOVQ a2-80(SP), CX;
    MOVQ a3-72(SP), DX;
    SubInternal() // x1 ^2 - d^2
    MOVQ r0, a0-96(SP);
    MOVQ r1, a1-88(SP);
    MOVQ r2, a2-80(SP);
    MOVQ r3, a3-72(SP); // a -> x1 ^2 - d^2
    MOVQ r0, AX;
    MOVQ r1, BX;
    MOVQ r2, CX;
    MOVQ r3, DX;
    AddInternal() // 2 * (x1 ^2 - d^2 )
    MOVQ a0-96(SP), AX;
    MOVQ a1-88(SP), BX;
    MOVQ a2-80(SP), CX;
    MOVQ a3-72(SP), DX;
    AddInternal() // 3 * (x1 ^2 - d^2 )
    MOVQ r0, a0-96(SP);
    MOVQ r1, a1-88(SP);
    MOVQ r2, a2-80(SP);
    MOVQ r3, a3-72(SP); // a-> 3 *( x1 ^2 - d^2 )

    LEAQ b0-64(SP), a_ptr;
    p256SqrInline() // b^2
    MOVQ r0, d0-32(SP)
    MOVQ r1, d1-24(SP)
    MOVQ r2, d2-16(SP)
    MOVQ r3, d3-8(SP) // d = b^2 = 4*y1^2

    LEAQ d0-32(SP), a_ptr
    MOVQ in+8(FP), b_ptr
    p256MulInline() // b^2 * x1
    MOVQ r4, b0-64(SP)
    MOVQ r5, b1-56(SP)
    MOVQ r0, b2-48(SP)
    MOVQ r1, b3-40(SP) // b -> b^2 * x1

    LEAQ a0-96(SP), a_ptr;
    p256SqrInline() // a^2
    MOVQ r0, AX;
    MOVQ r1, BX;
    MOVQ r2, CX;
    MOVQ r3, DX;

    MOVQ b0-64(SP), r0;
    MOVQ b1-56(SP), r1;
    MOVQ b2-48(SP), r2;
    MOVQ b3-40(SP), r3;

    SubInternal() // a^2 -b
    MOVQ r0, AX;
    MOVQ r1, BX;
    MOVQ r2, CX;
    MOVQ r3, DX;
    MOVQ b0-64(SP), r0;
    MOVQ b1-56(SP), r1;
    MOVQ b2-48(SP), r2;
    MOVQ b3-40(SP), r3;
    SubInternal() // x3 ->a^2 - 2 * b

    //x
    MOVQ res+0(FP), a_ptr
    MOVQ r0, 0(a_ptr)
    MOVQ r1, 8(a_ptr)
    MOVQ r2, 16(a_ptr)
    MOVQ r3, 24(a_ptr)

    MOVQ b0-64(SP), AX;
    MOVQ b1-56(SP), BX;
    MOVQ b2-48(SP), CX;
    MOVQ b3-40(SP), DX;
    SubInternal() // b^2 *x1 - x3

    MOVQ r0, b0-64(SP)
    MOVQ r1, b1-56(SP)
    MOVQ r2, b2-48(SP)
    MOVQ r3, b3-40(SP)

    LEAQ a0-96(SP), a_ptr
    LEAQ b0-64(SP), b_ptr
    p256MulInline() // a (b^2 * x1 - x3)
    MOVQ r4, a0-96(SP)
    MOVQ r5, a1-88(SP)
    MOVQ r0, a2-80(SP)
    MOVQ r1, a3-72(SP) // a -> a (b^2 * x1 - x3)

    LEAQ d0-32(SP), a_ptr
    p256SqrInline() // d^2 = b^4 = 16*y1^4
    XORQ R13, R13
    MOVQ r0, AX
    MOVQ r1, BX
    MOVQ r2, CX
    MOVQ r3, DX

    ADDQ $-1, r0
    ADCQ ·P<>+0x00(SB), r1
    ADCQ $-1, r2
    ADCQ ·P<>+0x08(SB), r3
    ADCQ $0, R13
    TESTQ $1, AX

    CMOVQEQ AX, r0
    CMOVQEQ BX, r1
    CMOVQEQ CX, r2
    CMOVQEQ DX, r3
    ANDQ AX, R13

    SHRQ $1, r0:r1
    SHRQ $1, r1:r2
    SHRQ $1, r2:r3
    SHRQ $1, r3:R13

    MOVQ a0-96(SP), AX;
    MOVQ a1-88(SP), BX;
    MOVQ a2-80(SP), CX;
    MOVQ a3-72(SP), DX;
    SubInternal() //  a (b^2 * x1 - x3) - 8*y1 ^4
    MOVQ res+0(FP), a_ptr
    ADDQ $32, a_ptr
    MOVQ r0, 0(a_ptr)
    MOVQ r1, 8(a_ptr)
    MOVQ r2, 16(a_ptr)
    MOVQ r3, 24(a_ptr)
    RET

//	var  1 * RRP mod P = [4]uint64{0x01, 0xffffffff, 0, 0x100000000}
DATA ·RR<>+0x10(SB) /8, $0x01
DATA ·RR<>+0x18(SB) /8, $0xffffffff
DATA ·RR<>+0x20(SB) /8, $0x0
DATA ·RR<>+0x28(SB) /8, $0x100000000
GLOBL ·RR<>(SB), RODATA, $48

TEXT ·sm2PointDouble1Asm(SB), NOSPLIT, $96-32
    MOVQ in+8(FP), a_ptr
    ADDQ $32, a_ptr // y
    MOVQ 0(a_ptr), AX;
    MOVQ 8(a_ptr), BX;
    MOVQ 16(a_ptr), CX;
    MOVQ 24(a_ptr), DX;
    MOVQ 0(a_ptr), r0;
    MOVQ 8(a_ptr), r1;
    MOVQ 16(a_ptr), r2;
    MOVQ 24(a_ptr), r3;
    AddInternal()  // 2* y
    //结果在 r0, r1, r2, r3
    MOVQ r0, b0-32(SP)
    MOVQ r1, b1-24(SP)
    MOVQ r2, b2-16(SP)
    MOVQ r3, b3-8(SP) // b = 2*y

    // z = 2 * y1
    MOVQ res+0(FP), a_ptr // res
    ADDQ $64, a_ptr
    MOVQ r0, 0(a_ptr)
    MOVQ r1, 8(a_ptr)
    MOVQ r2, 16(a_ptr)
    MOVQ r3, 24(a_ptr)


    MOVQ in+8(FP), a_ptr
    p256SqrInline() // x1^2

    MOVQ r0, AX;
    MOVQ r1, BX;
    MOVQ r2, CX;
    MOVQ r3, DX;

    ///////////// d^2 = RR -> r0, r1, r2, r3
    MOVQ ·RR<>+0x10(SB), r0
    MOVQ ·RR<>+0x18(SB), r1
    MOVQ ·RR<>+0x20(SB), r2
    MOVQ ·RR<>+0x28(SB), r3

    SubInternal() // x1 ^2 - d^2
    MOVQ r0, a0-96(SP);
    MOVQ r1, a1-88(SP);
    MOVQ r2, a2-80(SP);
    MOVQ r3, a3-72(SP); // a -> x1 ^2 - d^2
//-------------
    MOVQ r0, AX;
    MOVQ r1, BX;
    MOVQ r2, CX;
    MOVQ r3, DX;
    AddInternal() // 2 * (x1 ^2 - d^2 )
    MOVQ a0-96(SP), AX;
    MOVQ a1-88(SP), BX;
    MOVQ a2-80(SP), CX;
    MOVQ a3-72(SP), DX;
    AddInternal() // 3 * (x1 ^2 - d^2 )

    MOVQ r0, a0-96(SP);
    MOVQ r1, a1-88(SP);
    MOVQ r2, a2-80(SP);
    MOVQ r3, a3-72(SP); // a-> 3 *( x1 ^2 - d^2 )


    LEAQ b0-32(SP), a_ptr;
    p256SqrInline() // b^2
    MOVQ res+0(FP), a_ptr
    ADDQ $32, a_ptr // y3
    MOVQ r0, 0(a_ptr)
    MOVQ r1, 8(a_ptr)
    MOVQ r2, 16(a_ptr)
    MOVQ r3, 24(a_ptr) // y3 = b^2 = 4*y1^2

    MOVQ in+8(FP), b_ptr;
    p256MulInline() // b^2 * x1
    MOVQ r4, b0-32(SP)
    MOVQ r5, b1-24(SP)
    MOVQ r0, b2-16(SP)
    MOVQ r1, b3-8(SP) // b -> b^2 * x1

    LEAQ a0-96(SP), a_ptr;
    p256SqrInline() // a^2
    MOVQ r0, AX;
    MOVQ r1, BX;
    MOVQ r2, CX;
    MOVQ r3, DX;

    MOVQ b0-32(SP), r0;
    MOVQ b1-24(SP), r1;
    MOVQ b2-16(SP), r2;
    MOVQ b3-8(SP), r3;

    SubInternal() // a^2 -b
    MOVQ r0, AX;
    MOVQ r1, BX;
    MOVQ r2, CX;
    MOVQ r3, DX;
    MOVQ b0-32(SP), r0;
    MOVQ b1-24(SP), r1;
    MOVQ b2-16(SP), r2;
    MOVQ b3-8(SP), r3;
    SubInternal() // x3 ->a^2 - 2 * b

    //x
    MOVQ res+0(FP), a_ptr
    MOVQ r0, 0(a_ptr)
    MOVQ r1, 8(a_ptr)
    MOVQ r2, 16(a_ptr)
    MOVQ r3, 24(a_ptr)

    MOVQ b0-32(SP), AX;
    MOVQ b1-24(SP), BX;
    MOVQ b2-16(SP), CX;
    MOVQ b3-8(SP), DX;
    SubInternal() // b^2 *x1 - x3

    MOVQ r0, b0-32(SP)
    MOVQ r1, b1-24(SP)
    MOVQ r2, b2-16(SP)
    MOVQ r3, b3-8(SP)

    LEAQ a0-96(SP), a_ptr
    LEAQ b0-32(SP), b_ptr
    p256MulInline() // a (b^2 * x1 - x3)
    MOVQ r4, b0-32(SP)
    MOVQ r5, b1-24(SP)
    MOVQ r0, b2-16(SP)
    MOVQ r1, b3-8(SP) // b -> a (b^2 * x1 - x3)

    MOVQ res+0(FP), a_ptr
    ADDQ $32, a_ptr
    p256SqrInline() // y3 = 16*y1 ^4
    XORQ R13, R13
    MOVQ r0, AX
    MOVQ r1, BX
    MOVQ r2, CX
    MOVQ r3, DX

    ADDQ $-1, r0
    ADCQ ·P<>+0x00(SB), r1
    ADCQ $-1, r2
    ADCQ ·P<>+0x08(SB), r3
    ADCQ $0, R13
    TESTQ $1, AX

    CMOVQEQ AX, r0
    CMOVQEQ BX, r1
    CMOVQEQ CX, r2
    CMOVQEQ DX, r3
    ANDQ AX, R13

    SHRQ $1, r0:r1
    SHRQ $1, r1:r2
    SHRQ $1, r2:r3
    SHRQ $1, r3:R13

    MOVQ b0-32(SP), AX;
    MOVQ b1-24(SP), BX;
    MOVQ b2-16(SP), CX;
    MOVQ b3-8(SP), DX;
    SubInternal() //  a (b^2 * x1 - x3) - 8*y1 ^4
    MOVQ res+0(FP), a_ptr
    ADDQ $32, a_ptr
    MOVQ r0, 0(a_ptr)
    MOVQ r1, 8(a_ptr)
    MOVQ r2, 16(a_ptr)
    MOVQ r3, 24(a_ptr)
    RET

TEXT ·p256SelectBase(SB),NOSPLIT,$0
	MOVQ index+8(FP), AX
	MOVQ $2048, DI
	MULQ DI
	LEAQ ·precomputed<>(SB) ,DI
	ADDQ AX, DI
	MOVQ point+0(FP),DX
	MOVQ idx+16(FP),AX

	PXOR X15, X15	// X15 = 0
	PCMPEQL X14, X14 // X14 = -1
	PSUBL X14, X15   // X15 = 1
	MOVL AX, X14
	PSHUFD $0, X14, X14

	PXOR X0, X0
	PXOR X1, X1
	PXOR X2, X2
	PXOR X3, X3
	MOVQ $16, AX

	MOVOU X15, X13

loop_select_base:

		MOVOU X13, X12
		PADDL X15, X13
		PCMPEQL X14, X12

		MOVOU (16*0)(DI), X4
		MOVOU (16*1)(DI), X5
		MOVOU (16*2)(DI), X6
		MOVOU (16*3)(DI), X7

		MOVOU (16*4)(DI), X8
		MOVOU (16*5)(DI), X9
		MOVOU (16*6)(DI), X10
		MOVOU (16*7)(DI), X11

		ADDQ $(16*8), DI

		PAND X12, X4
		PAND X12, X5
		PAND X12, X6
		PAND X12, X7

		MOVOU X13, X12
		PADDL X15, X13
		PCMPEQL X14, X12

		PAND X12, X8
		PAND X12, X9
		PAND X12, X10
		PAND X12, X11

		PXOR X4, X0
		PXOR X5, X1
		PXOR X6, X2
		PXOR X7, X3

		PXOR X8, X0
		PXOR X9, X1
		PXOR X10, X2
		PXOR X11, X3

		DECQ AX
		JNE loop_select_base

	MOVOU X0, (16*0)(DX)
	MOVOU X1, (16*1)(DX)
	MOVOU X2, (16*2)(DX)
	MOVOU X3, (16*3)(DX)

	RET

/* ---------------------------------------*/
// func p256NegCond(val []uint64, cond int)
TEXT ·p256NegCond(SB),NOSPLIT,$64
    MOVQ val+0(FP), a_ptr
    MOVQ cond+8(FP), b_ptr
    // acc = poly
    MOVQ $-1, r0
    MOVQ ·P<>+0x00(SB), r1
    MOVQ $-1, r2
    MOVQ ·P<>+0x08(SB), r3
    // Load the original value
    MOVQ (8*0)(a_ptr), r4
    MOVQ (8*1)(a_ptr), r5
    MOVQ (8*2)(a_ptr), r6
    MOVQ (8*3)(a_ptr), r7
    // Speculatively subtract
    SUBQ r4, r0
    SBBQ r5, r1
    SBBQ r6, r2
    SBBQ r7, r3

    // Add in case the operand was > p256, from p256PointAddAffineAsm
    // If condition is 0, keep original value
    TESTQ b_ptr, b_ptr
    CMOVQEQ r4, r0
    CMOVQEQ r5, r1
    CMOVQEQ r6, r2
    CMOVQEQ r7, r3
    // Store result
    MOVQ r0, (8*0)(a_ptr)
    MOVQ r1, (8*1)(a_ptr)
    MOVQ r2, (8*2)(a_ptr)
    MOVQ r3, (8*3)(a_ptr)

    RET

// Constant time point access to arbitrary point table.
// Indexed from 1 to 15, with -1 offset
// (index 0 is implicitly point at infinity)
// func p256Select(point, table []uint64, idx int)
TEXT ·p256Select(SB),NOSPLIT,$0
	MOVQ idx+16(FP),AX
	MOVQ table+8(FP),DI
	MOVQ point+0(FP),DX

	PXOR X15, X15	// X15 = 0
	PCMPEQL X14, X14 // X14 = -1
	PSUBL X14, X15   // X15 = 1
	MOVL AX, X14
	PSHUFD $0, X14, X14

	PXOR X0, X0
	PXOR X1, X1
	PXOR X2, X2
	PXOR X3, X3
	PXOR X4, X4
	PXOR X5, X5
	MOVQ $16, AX

	MOVOU X15, X13

loop_select:

		MOVOU X13, X12
		PADDL X15, X13
		PCMPEQL X14, X12

		MOVOU (16*0)(DI), X6
		MOVOU (16*1)(DI), X7
		MOVOU (16*2)(DI), X8
		MOVOU (16*3)(DI), X9
		MOVOU (16*4)(DI), X10
		MOVOU (16*5)(DI), X11
		ADDQ $(16*6), DI

		PAND X12, X6
		PAND X12, X7
		PAND X12, X8
		PAND X12, X9
		PAND X12, X10
		PAND X12, X11

		PXOR X6, X0
		PXOR X7, X1
		PXOR X8, X2
		PXOR X9, X3
		PXOR X10, X4
		PXOR X11, X5

		DECQ AX
		JNE loop_select

	MOVOU X0, (16*0)(DX)
	MOVOU X1, (16*1)(DX)
	MOVOU X2, (16*2)(DX)
	MOVOU X3, (16*3)(DX)
	MOVOU X4, (16*4)(DX)
	MOVOU X5, (16*5)(DX)

	RET

// func p256MovCond(res, a, b []uint64, cond int)
// If cond == 0 res=b, else res=a
TEXT ·p256MovCond(SB),NOSPLIT,$0
	MOVQ in1+8(FP), a_ptr
	MOVQ in2+16(FP), b_ptr
	MOVQ cond+24(FP), X12

	PXOR X13, X13
	PSHUFD $0, X12, X12
	PCMPEQL X13, X12

	MOVOU X12, X0
	MOVOU (16*0)(a_ptr), X6
	PANDN X6, X0
	MOVOU X12, X1
	MOVOU (16*1)(a_ptr), X7
	PANDN X7, X1
	MOVOU X12, X2
	MOVOU (16*2)(a_ptr), X8
	PANDN X8, X2
	MOVOU X12, X3
	MOVOU (16*3)(a_ptr), X9
	PANDN X9, X3
	MOVOU X12, X4
	MOVOU (16*4)(a_ptr), X10
	PANDN X10, X4
	MOVOU X12, X5
	MOVOU (16*5)(a_ptr), X11
	PANDN X11, X5

	MOVOU (16*0)(b_ptr), X6
	MOVOU (16*1)(b_ptr), X7
	MOVOU (16*2)(b_ptr), X8
	MOVOU (16*3)(b_ptr), X9
	MOVOU (16*4)(b_ptr), X10
	MOVOU (16*5)(b_ptr), X11

	PAND X12, X6
	PAND X12, X7
	PAND X12, X8
	PAND X12, X9
	PAND X12, X10
	PAND X12, X11

	PXOR X6, X0
	PXOR X7, X1
	PXOR X8, X2
	PXOR X9, X3
	PXOR X10, X4
	PXOR X11, X5
	
	MOVQ res+0(FP), a_ptr

	MOVOU X0, (16*0)(a_ptr)
	MOVOU X1, (16*1)(a_ptr)
	MOVOU X2, (16*2)(a_ptr)
	MOVOU X3, (16*3)(a_ptr)
	MOVOU X4, (16*4)(a_ptr)
	MOVOU X5, (16*5)(a_ptr)

	RET
// p256IsZero returns 1 in AX if [r0..r3] represents zero and zero
// otherwise. It writes to [r0..r3], r4 and r5.
#define IsZeroInline() \
	XORQ AX, AX \
	MOVQ $1, r5 \
	MOVQ r0, r4 \
	ORQ r1, r4 \
	ORQ r2, r4 \
	ORQ r3, r4 \
	CMOVQEQ r5, AX \
	XORQ $-1, r0 \
	XORQ ·P<>+0x00(SB), r1 \
	XORQ $-1, r2 \
	XORQ ·P<>+0x08(SB), r3 \
	ORQ r1, r0 \
	ORQ r2, r0 \
	ORQ r3, r0 \
	CMOVQEQ r5, AX

TEXT ·sm2PointAdd2Asm(SB),NOSPLIT, $0
    MOVQ in2+16(FP), a_ptr
    ADDQ $64, a_ptr
    p256SqrInline()
    MOVQ r0, u10-32(SP)
    MOVQ r1, u11-24(SP)
    MOVQ r2, u12-16(SP)
    MOVQ r3, u13-8(SP) // u1 = z2 ^2

    LEAQ u10-32(SP),b_ptr
    p256MulInline()
    MOVQ r4, s10-64(SP)
    MOVQ r5, s11-56(SP)
    MOVQ r0, s12-48(SP)
    MOVQ r1, s13-40(SP) // s1 = u1 * z2 = z2^3

    MOVQ in1+8(FP), a_ptr
    ADDQ $64, a_ptr
    p256SqrInline()
    MOVQ r0, u20-96(SP)
    MOVQ r1, u21-88(SP)
    MOVQ r2, u22-80(SP)
    MOVQ r3, u23-72(SP) // u2 = z1 ^2

    LEAQ u20-96(SP),b_ptr
    p256MulInline()
    MOVQ r4, s20-128(SP)
    MOVQ r5, s21-120(SP)
    MOVQ r0, s22-112(SP)
    MOVQ r1, s23-104(SP) // s2 = u2 * z1 = z1^3

    LEAQ u10-32(SP), a_ptr
    MOVQ in1+8(FP), b_ptr
    p256MulInline()
    MOVQ r4, u10-32(SP)
    MOVQ r5, u11-24(SP)
    MOVQ r0, u12-16(SP)
    MOVQ r1, u13-8(SP) // u1 = u1 * x1

    LEAQ u20-96(SP), a_ptr
    MOVQ in2+16(FP), b_ptr
    p256MulInline()
    MOVQ r4, AX
    MOVQ r5, BX
    MOVQ r0, CX
    MOVQ r1, DX // u2 = u2 * x2

    MOVQ u10-32(SP), r0
    MOVQ u11-24(SP), r1
    MOVQ u12-16(SP), r2
    MOVQ u13-8(SP), r3 // u2 - u1
    SubInternal()
    MOVQ r0, h0-160(SP)
    MOVQ r1, h1-152(SP)
    MOVQ r2, h2-144(SP)
    MOVQ r3, h3-136(SP) // h = u2 - u1

    IsZeroInline()
    MOVQ AX, eq-200(SP)

    MOVQ in1+8(FP), a_ptr
    ADDQ $64, a_ptr
    MOVQ in2+16(FP), b_ptr
    ADDQ $64, b_ptr
    p256MulInline()
    MOVQ res+0(FP), a_ptr
    ADDQ $64, a_ptr
    MOVQ r4, 0(a_ptr)
    MOVQ r5, 8(a_ptr)
    MOVQ r0, 16(a_ptr)
    MOVQ r1, 24(a_ptr) // z3 = z1 * z2

    LEAQ h0-160(SP), b_ptr
    p256MulInline()
    // z
    MOVQ res+0(FP), a_ptr
    ADDQ $64, a_ptr
    MOVQ r4, 0(a_ptr)
    MOVQ r5, 8(a_ptr)
    MOVQ r0, 16(a_ptr)
    MOVQ r1, 24(a_ptr) // z3 = z1 * z2 * h

    LEAQ s10-64(SP), a_ptr
    MOVQ in1+8(FP), b_ptr
    ADDQ $32, b_ptr
    p256MulInline()
    MOVQ r4, s10-64(SP)
    MOVQ r5, s11-56(SP)
    MOVQ r0, s12-48(SP)
    MOVQ r1, s13-40(SP) // s1 = s1 * y1

    LEAQ s20-128(SP), a_ptr
    MOVQ in2+16(FP), b_ptr
    ADDQ $32, b_ptr
    p256MulInline()
    MOVQ r4, AX
    MOVQ r5, BX
    MOVQ r0, CX
    MOVQ r1, DX // s2 * y2

    MOVQ s10-64(SP), r0
    MOVQ s11-56(SP), r1
    MOVQ s12-48(SP), r2
    MOVQ s13-40(SP), r3
    SubInternal()
    MOVQ r0, m0-192(SP)
    MOVQ r1, m1-184(SP)
    MOVQ r2, m2-176(SP)
    MOVQ r3, m3-168(SP) // m = s2* y2 - s1 * y1

    IsZeroInline()
    ANDQ eq-200(SP),AX
    MOVQ AX, eq-200(SP)

    LEAQ h0-160(SP), a_ptr
    p256SqrInline()
    MOVQ r0, u20-96(SP)
    MOVQ r1, u21-88(SP)
    MOVQ r2, u22-80(SP)
    MOVQ r3, u23-72(SP) // u2 = h^2

    LEAQ u20-96(SP), a_ptr
    LEAQ u10-32(SP), b_ptr
    p256MulInline()
    MOVQ r4, u10-32(SP)
    MOVQ r5, u11-24(SP)
    MOVQ r0, u12-16(SP)
    MOVQ r1, u13-8(SP) // u1 = u2 * u1 = u1 * h^2

    LEAQ h0-160(SP), a_ptr
    LEAQ u20-96(SP), b_ptr
    p256MulInline()
    MOVQ r4, h0-160(SP)
    MOVQ r5, h1-152(SP)
    MOVQ r0, h2-144(SP)
    MOVQ r1, h3-136(SP) // h = u2 * h = h^3

    LEAQ m0-192(SP), a_ptr
    p256SqrInline()
    MOVQ r0, AX
    MOVQ r1, BX
    MOVQ r2, CX
    MOVQ r3, DX // m^2

    MOVQ h0-160(SP), r0
    MOVQ h1-152(SP), r1
    MOVQ h2-144(SP), r2
    MOVQ h3-136(SP), r3
    SubInternal() // m^2 - h
    MOVQ r0, AX
    MOVQ r1, BX
    MOVQ r2, CX
    MOVQ r3, DX
    MOVQ u10-32(SP), r0
    MOVQ u11-24(SP), r1
    MOVQ u12-16(SP), r2
    MOVQ u13-8(SP), r3
    SubInternal() // m^2 -h - u1
    MOVQ r0, AX
    MOVQ r1, BX
    MOVQ r2, CX
    MOVQ r3, DX
    MOVQ u10-32(SP), r0
    MOVQ u11-24(SP), r1
    MOVQ u12-16(SP), r2
    MOVQ u13-8(SP), r3
    SubInternal() // m^2 -h - u1 - u1
    // x
    MOVQ res+0(FP), a_ptr
    MOVQ r0, 0(a_ptr)
    MOVQ r1, 8(a_ptr)
    MOVQ r2, 16(a_ptr)
    MOVQ r3, 24(a_ptr)

    MOVQ u10-32(SP), AX
    MOVQ u11-24(SP), BX
    MOVQ u12-16(SP), CX
    MOVQ u13-8(SP), DX
    SubInternal()
    MOVQ r0, u10-32(SP)
    MOVQ r1, u11-24(SP)
    MOVQ r2, u12-16(SP)
    MOVQ r3, u13-8(SP) // u1 = u1 - x3

    LEAQ s10-64(SP), a_ptr
    LEAQ h0-160(SP), b_ptr
    p256MulInline()
    MOVQ r4, s10-64(SP)
    MOVQ r5, s11-56(SP)
    MOVQ r0, s12-48(SP)
    MOVQ r1, s13-40(SP) // s1 = s1 * h

    LEAQ m0-192(SP), a_ptr
    LEAQ u10-32(SP), b_ptr
    p256MulInline()
    MOVQ r4, AX
    MOVQ r5, BX
    MOVQ r0, CX
    MOVQ r1, DX // m0 * u1

    MOVQ s10-64(SP), r0
    MOVQ s11-56(SP), r1
    MOVQ s12-48(SP), r2
    MOVQ s13-40(SP), r3
    SubInternal() //m0 * u1 - s1

// y
    MOVQ res+0(FP), a_ptr
    ADDQ $32, a_ptr
    MOVQ r0, 0(a_ptr)
    MOVQ r1, 8(a_ptr)
    MOVQ r2, 16(a_ptr)
    MOVQ r3, 24(a_ptr)

    MOVQ eq-200(SP), AX
    MOVQ AX ,ret+24(FP)
    RET
    

	
TEXT ·sm2PointAdd1Asm(SB),NOSPLIT, $0
    MOVQ in1+8(FP), a_ptr
    ADDQ $64, a_ptr
    p256SqrInline()
    MOVQ r0, u20-32(SP)
    MOVQ r1, u21-24(SP)
    MOVQ r2, u22-16(SP)
    MOVQ r3, u23-8(SP) // u2 = z1 ^2

    LEAQ u20-32(SP),b_ptr
    p256MulInline()
    MOVQ r4, s20-64(SP)
    MOVQ r5, s21-56(SP)
    MOVQ r0, s22-48(SP)
    MOVQ r1, s23-40(SP) // s2 = u2 * z1 = z1^3

    LEAQ u20-32(SP), a_ptr
    MOVQ in2+16(FP), b_ptr
    p256MulInline()
    MOVQ r4, AX
    MOVQ r5, BX
    MOVQ r0, CX
    MOVQ r1, DX // u2 * x2
    MOVQ in1+8(FP), a_ptr
    MOVQ 0(a_ptr), r0
    MOVQ 8(a_ptr), r1
    MOVQ 16(a_ptr), r2
    MOVQ 24(a_ptr), r3 // u2 - x1
    SubInternal()
    MOVQ r0, h0-96(SP)
    MOVQ r1, h1-88(SP)
    MOVQ r2, h2-80(SP)
    MOVQ r3, h3-72(SP) // h = u2 - x1


    MOVQ in1+8(FP), a_ptr
    ADDQ $64, a_ptr
    LEAQ h0-96(SP), b_ptr
    p256MulInline()
    MOVQ res+0(FP), a_ptr
    ADDQ $64, a_ptr
    MOVQ r4, 0(a_ptr)
    MOVQ r5, 8(a_ptr)
    MOVQ r0, 16(a_ptr)
    MOVQ r1, 24(a_ptr) // z3 = z1 * h

    LEAQ s20-64(SP), a_ptr
    MOVQ in2+16(FP), b_ptr
    ADDQ $32, b_ptr
    p256MulInline()
    MOVQ r4, AX
    MOVQ r5, BX
    MOVQ r0, CX
    MOVQ r1, DX // s2 * y2

    MOVQ in1+8(FP), a_ptr
    ADDQ $32, a_ptr
    MOVQ 0(a_ptr), r0
    MOVQ 8(a_ptr), r1
    MOVQ 16(a_ptr), r2
    MOVQ 24(a_ptr), r3
    SubInternal()
    MOVQ r0, m0-128(SP)
    MOVQ r1, m1-120(SP)
    MOVQ r2, m2-112(SP)
    MOVQ r3, m3-104(SP) // m = s2* y2 - y1

    LEAQ h0-96(SP), a_ptr
    p256SqrInline()
    MOVQ r0, u20-32(SP)
    MOVQ r1, u21-24(SP)
    MOVQ r2, u22-16(SP)
    MOVQ r3, u23-8(SP) // u2 = h^2

    LEAQ u20-32(SP), a_ptr
    MOVQ in1+8(FP), b_ptr
    p256MulInline()
    MOVQ r4, u10-160(SP)
    MOVQ r5, u11-152(SP)
    MOVQ r0, u12-144(SP)
    MOVQ r1, u13-136(SP) // u1 = u2 * x1 = x1 * h^2

    LEAQ h0-96(SP), a_ptr
    LEAQ u20-32(SP), b_ptr
    p256MulInline()
    MOVQ r4, h0-96(SP)
    MOVQ r5, h1-88(SP)
    MOVQ r0, h2-80(SP)
    MOVQ r1, h3-72(SP) // h = u2 * h = h^3

    LEAQ m0-128(SP), a_ptr
    p256SqrInline()
    MOVQ r0, AX
    MOVQ r1, BX
    MOVQ r2, CX
    MOVQ r3, DX // m^2

    MOVQ h0-96(SP), r0
    MOVQ h1-88(SP), r1
    MOVQ h2-80(SP), r2
    MOVQ h3-72(SP), r3
    SubInternal() // m^2 - h
    MOVQ r0, AX
    MOVQ r1, BX
    MOVQ r2, CX
    MOVQ r3, DX
    MOVQ u10-160(SP), r0
    MOVQ u11-152(SP), r1
    MOVQ u12-144(SP), r2
    MOVQ u13-136(SP), r3
    SubInternal() // m^2 -h - u1
    MOVQ r0, AX
    MOVQ r1, BX
    MOVQ r2, CX
    MOVQ r3, DX
    MOVQ u10-160(SP), r0
    MOVQ u11-152(SP), r1
    MOVQ u12-144(SP), r2
    MOVQ u13-136(SP), r3
    SubInternal() // m^2 -h - u1 - u1
    // x
    MOVQ res+0(FP), a_ptr
    MOVQ r0, 0(a_ptr)
    MOVQ r1, 8(a_ptr)
    MOVQ r2, 16(a_ptr)
    MOVQ r3, 24(a_ptr)

    MOVQ u10-160(SP), AX
    MOVQ u11-152(SP), BX
    MOVQ u12-144(SP), CX
    MOVQ u13-136(SP), DX
    SubInternal()
    MOVQ r0, u10-160(SP)
    MOVQ r1, u11-152(SP)
    MOVQ r2, u12-144(SP)
    MOVQ r3, u13-136(SP) // u1 = u1 - x3

    MOVQ in1+8(FP), a_ptr
    ADDQ $32, a_ptr
    LEAQ h0-96(SP), b_ptr
    p256MulInline()
    MOVQ r4, h0-96(SP)
    MOVQ r5, h1-88(SP)
    MOVQ r0, h2-80(SP)
    MOVQ r1, h3-72(SP) // h = y1 * h

    LEAQ m0-128(SP), a_ptr
    LEAQ u10-160(SP), b_ptr
    p256MulInline()
    MOVQ r4, AX
    MOVQ r5, BX
    MOVQ r0, CX
    MOVQ r1, DX // m0 * u1

    MOVQ h0-96(SP), r0
    MOVQ h1-88(SP), r1
    MOVQ h2-80(SP), r2
    MOVQ h3-72(SP), r3
    SubInternal() //m0 * u1 - h

// y
    MOVQ res+0(FP), a_ptr
    ADDQ $32, a_ptr
    MOVQ r0, 0(a_ptr)
    MOVQ r1, 8(a_ptr)
    MOVQ r2, 16(a_ptr)
    MOVQ r3, 24(a_ptr)

    RET


//func maybeReduceModPASM(in *[4]uint64) *[4]uint64
TEXT ·maybeReduceModPASM(SB), NOSPLIT, $8-0
    MOVQ in+0(FP), b_ptr
	MOVQ 0(b_ptr), AX; MOVQ 8(b_ptr), BX; MOVQ 16(b_ptr), CX; MOVQ 24(b_ptr), DX
	MOVQ 0(b_ptr), R8; MOVQ 8(b_ptr), R9; MOVQ 16(b_ptr), R10; MOVQ 24(b_ptr), R11
	SUBQ $-1, AX
    SBBQ ·P<>+0x00(SB), BX
    SBBQ $-1, CX
    SBBQ ·P<>+0x08(SB), DX
    CMOVQCS R8, AX
    CMOVQCS R9, BX
    CMOVQCS R10, CX
    CMOVQCS R11, DX
    MOVQ AX, 0(b_ptr)
    MOVQ BX, 8(b_ptr)
    MOVQ CX, 16(b_ptr)
    MOVQ DX, 24(b_ptr)
    RET
// MULXQ src1, dst_low, dst_hi  : src2 is DX
TEXT ·mul(SB), NOSPLIT, $0
    MOVQ ina+8(FP), DX
    MOVQ inb+16(FP), AX
    MULXQ AX, BX, DX
    MOVQ res+0(FP), AX
    MOVQ BX, 0(AX)
    MOVQ DX, 8(AX)
    RET


DATA N_<>+0x00(SB)/8,$0x327f9e8872350975   //R * RInv - N * N_ = 1
DATA N<>+0x00(SB)/8, $0x53bbf40939d54123
DATA N<>+0x08(SB)/8, $0x7203df6b21c6052b
DATA N<>+0x10(SB)/8, $0xffffffffffffffff   //e64 - 1
DATA N<>+0x18(SB)/8, $0xfffffffeffffffff
GLOBL N_<>(SB), 8, $8
GLOBL N<>(SB), 8, $32

//result is in x1 x2 x3 x0
#define orderREDCForSqr(x0, x1, x2, x3)  \
    MOVQ x0, DX; MULXQ N_<>(SB), DX, AX;\ //t0 = m = (x0, x1, x2, x3) * N_ mod e64
	MULXQ N<>+0x00(SB), AX, H; ADDQ AX,x0;\  //now x0 is zero
	ADCQ H, x1; MULXQ N<>+0x08(SB), AX, H; ADCQ $0, H; ADDQ AX, x1; \
    ADCQ H, x2; MULXQ N<>+0x10(SB), AX, H; ADCQ $0, H; ADDQ AX, x2; \
    ADCQ H, x3; MULXQ N<>+0x18(SB), AX, DX; ADCQ $0, DX; ADDQ AX, x3; ADCQ DX, x0;


// input a_ptr
// output r0 r1 r2 r3
#define orderSqrInline() \
	MOVQ a, DX; MULXQ b, r1, r2;                                       \ // y[1:] * y[0] => r0 ~ r4
	MULXQ c, AX, r3; ADDQ AX, r2;                          \
	MULXQ d, AX, r4; ADCQ AX, r3; ADCQ $0, r4;                          \
	MOVQ b, DX; MULXQ c,AX, L; ADDQ AX, r3;                           \ // y[2:] * y[1] => r0 ~ r5
	ADCQ L, r4; MULXQ d, AX, r5; ADCQ $0, r5; ADDQ AX, r4; \
	MOVQ c, DX; MULXQ d, AX, r6; ADCQ AX, r5; ADCQ $0, r6;                          \ // y[3] * y[2]  => r0 ~ r6
	XORQ r7, r7; ADDQ r1, r1; ADCQ r2, r2; ADCQ r3, r3;                                 \
	ADCQ r4, r4; ADCQ r5, r5; ADCQ r6, r6; ADCQ $0, r7;                                 \ // *2
	MOVQ a, DX; MULXQ DX, r0, H;                                       \ // Missing products
	ADDQ H, r1; MOVQ b, DX; MULXQ DX, AX, H; ADCQ AX, r2;              \
	ADCQ H, r3; MOVQ c, DX; MULXQ DX, AX, H; ADCQ AX, r4;               \
	MOVQ d, DX; MULXQ DX, AX, DX; ADCQ H, r5; ADCQ AX, r6; ADCQ DX, r7;                          \
	orderREDCForSqr(r0, r1, r2, r3)                                                          \
	orderREDCForSqr(r1, r2, r3, r0)                                                          \
	orderREDCForSqr(r2, r3, r0, r1)                                                          \
	orderREDCForSqr(r3, r0, r1, r2)                                                          \
	XORQ H, H; ADDQ r4, r0; ADCQ r5, r1; ADCQ r6, r2; ADCQ r7, r3; ADCQ $0, H;          \
	maySubN(r0, r1, r2, r3, H)


#define maySubN(in1, in2, in3, in4, in5) \
	MOVQ    in1, AX; MOVQ in2, BX; MOVQ in3, CX; MOVQ in4, DX;                                       \
	SUBQ    N<>+0x00(SB), in1; SBBQ N<>+0x08(SB), in2; SBBQ N<>+0x10(SB), in3; SBBQ N<>+0x18(SB), in4; SBBQ $0, in5; \
	CMOVQCS AX, in1; CMOVQCS BX, in2; CMOVQCS CX, in3; CMOVQCS DX, in4;


// func p256Sqr(res, a *[4]uint64, n int)
TEXT ·orderSqr(SB), NOSPLIT, $0
	MOVQ in+8(FP), a_ptr
sqrLoop:
	orderSqrInline()
	MOVQ res+0(FP), BX
	MOVQ r0, (8*0)(BX)
	MOVQ r1, (8*1)(BX)
	MOVQ r2, (8*2)(BX)
	MOVQ r3, (8*3)(BX)
	MOVQ BX, a_ptr

	DECQ in+16(FP)
	JNE  sqrLoop
	RET


TEXT ·redc1111(SB),NOSPLIT,$0
    MOVQ in+0(FP), a_ptr
    MOVQ 0(a_ptr), r0
    MOVQ 8(a_ptr), r1
    MOVQ 16(a_ptr), r2
    MOVQ 24(a_ptr), r3
    orderREDCForSqr(r0,r1,r2,r3)
    MOVQ r1, 0(a_ptr)
    MOVQ r2, 8(a_ptr)
    MOVQ r3, 16(a_ptr)
    MOVQ r0, 24(a_ptr)
    RET

//func biggerThan(a, b *[4]uint64) bool
TEXT ·biggerThan(SB), NOSPLIT, $16-0
    MOVQ ina+0(FP), a_ptr
	MOVQ inb+8(FP), b_ptr
	MOVQ $1, R8
    XORQ R9, R9
	MOVQ 0(b_ptr), AX; MOVQ 8(b_ptr), BX; MOVQ 16(b_ptr), CX; MOVQ 24(b_ptr), DX
	SUBQ 0(a_ptr), AX
    SBBQ 8(a_ptr), BX
    SBBQ 16(a_ptr), CX
    SBBQ 24(a_ptr), DX
    CMOVQCS R8, R9
    MOVQ R9, res+16(FP)
    RET

//result is in x1 x2 x3 x0
#define orderREDC(x0, x1, x2, x3, x4, x5)  \
    MOVQ x0, DX; MULXQ N_<>(SB), DX, AX;\ //t0 = m = (x0, x1, x2, x3) * N_ mod e64
	MULXQ N<>+0x00(SB), AX, H; ADDQ AX,x0; ADCQ H, x1; \  //now x0 is zero
	MULXQ N<>+0x08(SB), AX, H; ADCQ $0, H; ADDQ AX, x1;ADCQ H, x2; \
    MULXQ N<>+0x10(SB), AX, H; ADCQ $0, H; ADDQ AX, x2; ADCQ H, x3;\
    MULXQ N<>+0x18(SB), AX, H; ADCQ $0, H; ADDQ AX, x3; ADCQ H, x4; ADCQ $0, x5;

// input is a_ptr b_ptr
// result r4 r5 r0 r1
#define orderMulInline() \
	XORQ r2, r2; XORQ r3, r3; XORQ r4, r4; XORQ r5, r5;      \
    MOVQ (8*0)(b_ptr), DX; MULXQ a,r0, r1; \
	MULXQ b,AX,r2; ADDQ AX, r1; \
	MULXQ c,AX,r3; ADCQ AX, r2; \
	MULXQ d,AX,r4; ADCQ AX, r3; ADCQ $0, r4; \ // a * b[0]
	orderREDC(r0, r1, r2, r3, r4, r5)                             \
	single(1, r1, r2, r3, r4, r5, r0)                        \ // x * y[1]
	orderREDC(r1, r2, r3, r4, r5, r0)                             \
	single(2, r2, r3, r4, r5, r0, r1)                        \ // x * y[2]
	orderREDC(r2, r3, r4, r5, r0, r1)                             \
	single(3, r3, r4, r5, r0, r1, r2)                        \ // x * y[3]
	orderREDC(r3, r4, r5, r0, r1, r2)                             \ // now result in r4 r5 r0 r1 r2
	maySubN(r4, r5, r0, r1, r2)

#define orderMulInlineSmall() \
	XORQ r2, r2; XORQ r3, r3; XORQ r4, r4; XORQ r5, r5;      \
    MOVQ (8*0)(b_ptr), DX; MULXQ a,r0, r1; \
	MULXQ b,AX,r2; ADDQ AX, r1; \
	MULXQ c,AX,r3; ADCQ AX, r2; \
	MULXQ d,AX,r4; ADCQ AX, r3; ADCQ $0, r4; \ // a * b[0]
    orderREDC(r0, r1, r2, r3, r4, r5)                             \
	orderREDC(r1, r2, r3, r4, r5, r0)                             \
	orderREDC(r2, r3, r4, r5, r0, r1)                             \
	orderREDC(r3, r4, r5, r0, r1, r2)                             \ // now result in r4 r5 r0 r1 r2
	maySubN(r4, r5, r0, r1, r2)

// func p256Mul(a, b *[4]uint64)
TEXT ·orderMul(SB), NOSPLIT, $64-16
	MOVQ ina+8(FP), a_ptr
	MOVQ inb+16(FP), b_ptr
	orderMulInline()
	MOVQ res+0(FP), a_ptr
	MOVQ r4, (8*0)(a_ptr)
	MOVQ r5, (8*1)(a_ptr)
	MOVQ r0, (8*2)(a_ptr)
	MOVQ r1, (8*3)(a_ptr)
	RET

TEXT ·smallOrderMul(SB), NOSPLIT, $64-16
	MOVQ ina+8(FP), a_ptr
	MOVQ inb+16(FP), b_ptr
	orderMulInlineSmall()
	MOVQ res+0(FP), a_ptr
	MOVQ r4, (8*0)(a_ptr)
	MOVQ r5, (8*1)(a_ptr)
	MOVQ r0, (8*2)(a_ptr)
	MOVQ r1, (8*3)(a_ptr)
	RET

//func orderAdd(out, a, b *[4]uint64)
TEXT ·orderAdd(SB), NOSPLIT, $16-0
	MOVQ ina+8(FP), a_ptr
	MOVQ inb+16(FP), b_ptr

	MOVQ 0(a_ptr), r0; MOVQ 8(a_ptr), r1; MOVQ 16(a_ptr), r2; MOVQ 24(a_ptr), r3
	XORQ r4, r4

	ADDQ 0(b_ptr), r0
	ADCQ 8(b_ptr), r1
	ADCQ 16(b_ptr), r2
	ADCQ 24(b_ptr), r3
	ADCQ $0, r4

	maySubN(r0, r1, r2, r3, r4)

	MOVQ res+0(FP), a_ptr
	MOVQ r0, 0(a_ptr)
	MOVQ r1, 8(a_ptr)
	MOVQ r2, 16(a_ptr)
	MOVQ r3, 24(a_ptr)

	RET

//func orderAdd(out, a, b *[4]uint64)
TEXT ·orderSub(SB), NOSPLIT, $16-0
	MOVQ ina+8(FP), a_ptr
	MOVQ inb+16(FP), b_ptr

	MOVQ 0(a_ptr), AX; MOVQ 8(a_ptr), BX; MOVQ 16(a_ptr), CX; MOVQ 24(a_ptr), DX
	XORQ R13, R13

	SUBQ 0(b_ptr), AX
	SBBQ 8(b_ptr), BX
	SBBQ 16(b_ptr), CX
	SBBQ 24(b_ptr), DX
	SBBQ $0, R13

	MOVQ AX, r0; MOVQ BX, r1; MOVQ CX, r2; MOVQ DX, r3

	ADDQ N<>+0x00(SB), r0
	ADCQ N<>+0x08(SB), r1
	ADCQ N<>+0x10(SB), r2
	ADCQ N<>+0x18(SB), r3
	ANDQ $1, R13

	CMOVQEQ AX, r0
	CMOVQEQ BX, r1
	CMOVQEQ CX, r2
	CMOVQEQ DX, r3

	MOVQ res+0(FP), a_ptr
	MOVQ r0, 0(a_ptr)
	MOVQ r1, 8(a_ptr)
	MOVQ r2, 16(a_ptr)
	MOVQ r3, 24(a_ptr)

	RET


