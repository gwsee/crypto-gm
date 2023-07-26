// func rand_64bit(out []byte) (n int)
TEXT ·rand_64bit(SB),$0
  MOVQ len+8(FP), R8
  MOVQ R8, n+24(FP)
  ADDQ $0, R8 // 输入slice长度为0，直接返回
  JE  re

  MOVQ res+0(FP), BX
  SUBQ $8, R8
  JS t // 输入slice小于8字节，进一步判断
q:
  BYTE $0x48; BYTE $0x0f; BYTE $0xc7; BYTE $0xf0 // RdRand RAX, 生成64比特随机数，每次填充8个字节
  MOVQ AX, (BX)
  ADDQ $8, BX
  SUBQ $8, R8
  JNS  q
t:
  ADDQ $8, R8
  DECQ R8 // 判断余数是否大于0
  JS  re
r:
  BYTE $0x0f; BYTE $0xc7; BYTE $0xf0 // RdRand RAX, 剩余不足8字节时，生成16比特的随机数再一个字节一个字节的填充
  MOVB AX, (BX)
  INCQ BX
  DECQ R8
  JNS  r
re:
  RET

// func randUint64_64bit() uint64
TEXT ·randUint64_64bit(SB),$0
  BYTE $0x48; BYTE $0x0f; BYTE $0xc7; BYTE $0xf0 // RdRand RAX
  MOVQ AX, ret+0(FP)
  RET


