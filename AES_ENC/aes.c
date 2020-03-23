#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "aes.h"

#define MUL2(a) (a << 1)^(a&0x80 ? 0x1b : 0x00)
#define MUL3(a) (MUL2(a))^a
#define MUL4(a) MUL2((MUL2(a)))
#define MUL8(a) MUL2((MUL2((MUL2(a)))))
#define MUL9(a) (MUL8(a))^(a)
#define MULB(a) (MUL8(a))^(MUL2(a))^(a)
#define MULD(a) (MUL8(a))^(MUL4(a))^(a)
#define MULE(a) (MUL8(a))^(MUL4(a))^(MUL2(a))

inline u8 MUL(u8 a, u8 b) {
	u8 r = 0, tmp = b;
	u32 i;

	for (i = 0; i < 8; i++) {
		if (a & 1) r ^= tmp;
		tmp = MUL2(tmp);
		a >>= 1;
	}
	return r;
}

inline u8 inv(u8 a) {
	u8 r = a;

	r = MUL(r, r);
	r = MUL(r, a);
	r = MUL(r, r);
	r = MUL(r, a);
	r = MUL(r, r);
	r = MUL(r, a);
	r = MUL(r, r);
	r = MUL(r, a);
	r = MUL(r, r);
	r = MUL(r, a);
	r = MUL(r, r);
	r = MUL(r, a);
	r = MUL(r, r); // a254

	return r;
}

u8 GenSbox(u8 a) {
	u8 r = 0;
	u8 tmp;

	tmp = inv(a);
	if (tmp & 1) r ^= 0x1f;
	if (tmp & 2) r ^= 0x3e;
	if (tmp & 4) r ^= 0x7c;
	if (tmp & 8) r ^= 0xf8;
	if (tmp & 16) r ^= 0xf1;
	if (tmp & 32) r ^= 0xe3;
	if (tmp & 64) r ^= 0xc7;
	if (tmp & 128) r ^= 0x8f;

	return r ^ 0x63;
}

int main(int argc, char *argv[]) {
	u8 a, b, c;
	int i;

	a = 0xab;
	b = 0x38;
	c = MUL(a, b);

	//printf("%02x * %02x = %02x\n", a, b, c);
	//printf("Sbox(%02x) = %02x\n", a, GenSbox(a));
	printf("Sbox(%02x) = %02x, %02x\n", a, GenSbox(a), Sbox[a]);
	/*printf("Sbox[256] = {");
	for (i = 0; i < 256; i++) {
		printf("0x%02x, ", GenSbox(i));
		if (i % 16 == 15) printf("\n");
	}
	printf("}");*/

	return 0;
}