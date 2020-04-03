//아니 왜 암호화 결과가 예상이랑 다르지 버그 찾아야 하는데

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

void AddRoundKey(u8 S[16], u8 RK[16]) {
	S[0] ^= RK[0]; S[1] ^= RK[1]; S[2] ^= RK[2]; S[3] ^= RK[3];
	S[4] ^= RK[4]; S[5] ^= RK[5]; S[6] ^= RK[6]; S[7] ^= RK[7];
	S[8] ^= RK[8]; S[9] ^= RK[9]; S[10] ^= RK[10]; S[11] ^= RK[11];
	S[12] ^= RK[12]; S[13] ^= RK[13]; S[14] ^= RK[14]; S[15] ^= RK[15];
}

void SubBytes(u8 S[16]) {
	S[0] = Sbox[S[0]]; S[1] = Sbox[S[1]]; S[2] = Sbox[S[2]]; S[3] = Sbox[S[3]];
	S[4] = Sbox[S[4]]; S[5] = Sbox[S[5]]; S[6] = Sbox[S[6]]; S[7] = Sbox[S[7]];
	S[8] = Sbox[S[8]]; S[9] = Sbox[S[9]]; S[10] = Sbox[S[10]]; S[11] = Sbox[S[11]];
	S[12] = Sbox[S[12]]; S[13] = Sbox[S[13]]; S[14] = Sbox[S[14]]; S[15] = Sbox[S[15]];
}

void ShiftRows(u8 S[16]) {
	u8 temp;

	temp = S[1]; S[1] = S[5]; S[5] = S[9]; S[9] = S[13]; S[13] = temp;
	temp = S[2]; S[2] = S[10]; S[10] = temp; temp = S[6]; S[6] = S[14]; S[14] = temp;
	temp = S[15]; S[15] = S[11]; S[11] = S[7]; S[7] = S[3]; S[3] = S[15];
}

void MixColumns(u8 S[16]) {
	u8 temp[16];
	int i;

	for (i = 0; i < 16; i += 4) {
		temp[i] = MUL2(S[i]) ^ MUL3(S[i + 1]) ^ S[i + 2] ^ S[i + 3];
		temp[i + 1] = S[i] ^ MUL2(S[i + 1]) ^ MUL3(S[i + 2]) ^ S[i + 3];
		temp[i + 2] = S[i] ^ S[i + 1] ^ MUL2(S[i + 2]) ^ MUL3(S[i + 3]);
		temp[i + 3] = MUL3(S[i]) ^ S[i + 1] ^ S[i + 2] ^ MUL2(S[i + 3]);
	}

	S[0] = temp[0]; S[1] = temp[1]; S[2] = temp[2]; S[3] = temp[3];
	S[4] = temp[4]; S[5] = temp[5]; S[6] = temp[6]; S[7] = temp[7];
	S[8] = temp[8]; S[9] = temp[9]; S[10] = temp[10]; S[11] = temp[11];
	S[12] = temp[12]; S[13] = temp[13]; S[14] = temp[14]; S[15] = temp[15];
}

void AES_ENC(u8 PT[16], u8 RK[], u8 CT[16], int keysize) {
	int Nr = keysize / 32 + 6;
	int i;
	u8 temp[16];

	// PlainText 복사
	temp[0] = PT[0]; temp[1] = PT[1]; temp[2] = PT[2]; temp[3] = PT[3];
	temp[4] = PT[4]; temp[5] = PT[5]; temp[6] = PT[6]; temp[7] = PT[7];
	temp[8] = PT[8]; temp[9] = PT[9]; temp[10] = PT[10]; temp[11] = PT[11];
	temp[12] = PT[12]; temp[13] = PT[13]; temp[14] = PT[14]; temp[15] = PT[15];

	AddRoundKey(temp, RK); // temp의 16 byte와 RK 첫 16 byte xor하여 temp에 결과를 담는 함수

	for (i = 0; i < Nr - 1; i++) {
		SubBytes(temp);
		ShiftRows(temp);
		MixColumns(temp);
		AddRoundKey(temp, RK + 16 * (i + 1));
	}

	SubBytes(temp);
	ShiftRows(temp);
	AddRoundKey(temp, RK + 16 * (i + 1));

	CT[0] = temp[0]; CT[1] = temp[1]; CT[2] = temp[2]; CT[3] = temp[3];
	CT[4] = temp[4]; CT[5] = temp[5]; CT[6] = temp[6]; CT[7] = temp[7];
	CT[8] = temp[8]; CT[9] = temp[9]; CT[10] = temp[10]; CT[11] = temp[11];
	CT[12] = temp[12]; CT[13] = temp[13]; CT[14] = temp[14]; CT[15] = temp[15];
}

u32 u4byte_in(u8 x[]) {
	return (x[0] << 24) | (x[1] << 16) | (x[2] << 8) | x[3]; // x[0]|x[1]|x[2]|x[3]
}

void u4byte_out(u8 x[], u32 y) {
	x[0] = (y >> 24) & 0xff;
	x[1] = (y >> 16) & 0xff;
	x[2] = (y >> 8) & 0xff;
	x[3] = y & 0xff;
}

void AES_KeyWordToByte(u32 W[], u8 RK[]) {
	int i;
	
	for (i = 0; i < 44; i++) {
		u4byte_out(RK + 4 * i, W[i]); // RK[4i]||RK[4i+1]||RK[4i+2]||RK[4i+3] <-- W[i]
	}
}

u32 Rcons[10] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000 , 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000 };

#define RotWord(x) ((x << 8) | (x >> 24));

u32 SubWord(u32 x) {
	u8 a, b, c, d;

	a = Sbox[(u8)(x >> 24)];
	b = Sbox[(u8)(x >> 16)&0xff];
	c = Sbox[(u8)(x >> 8)&0xff];
	d = Sbox[(u8)(x & 0xff)];

	return (((u32)Sbox[(u8)(a << 24)] >> 24) | ((u32)Sbox[(u8)(b << 16)] >> 16) | ((u32)Sbox[(u8)(c << 8)] >> 8) | (u32)Sbox[(u8)d]);
}	

void RoundKeyGeneration128(u8 MK[], u8 RK[]) {
	u32 W[44];
	int i;
	u32 T;

	W[0] = u4byte_in(MK); // W[0] = MK[0] || MK[1] || MK[2] || MK[3]
	W[1] = u4byte_in(MK + 4);
	W[2] = u4byte_in(MK + 8);
	W[3] = u4byte_in(MK + 12);

	for (i = 0; i < 10; i++) {
		//T = G_func(W[4 * i + 3]);
		T = W[4 * i + 3];
		T = RotWord(T);
		T = SubWord(T);
		T ^= Rcons[i];

		W[4 * i + 4] = W[4 * i] ^ T;
		W[4 * i + 5] = W[4 * i + 1] ^ W[4 * i + 4];
		W[4 * i + 6] = W[4 * i + 2] ^ W[4 * i + 5];
		W[4 * i + 7] = W[4 * i + 3] ^ W[4 * i + 6];
	}
	AES_KeyWordToByte(W, RK);
}

void AES_KeySchedule(u8 MK[], u8 RK[], int keysize) {
	if (keysize == 128) RoundKeyGeneration128(MK, RK);
	//if (keysize == 192) RoundKeyGeneration192(MK, RK);
	//if (keysize == 256) RoundKeyGeneration256(MK, RK);
}

int main(int argc, char *argv[]) {
	int i;
	u8 PT[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	u8 MK[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	u8 CT[16] = { 0x00, };
	u8 RK[240] = { 0x00, };
	int keysize = 128;

	AES_KeySchedule(MK, RK, keysize); // 1 round: RK 0~15, 2 round: 16~31
	AES_ENC(PT, RK, CT, keysize);

	for (i = 0; i < 16; i++) printf("%02x ", CT[i]);
	printf("\n");

	/*a = 0xab;
	b = 0x38;
	c = MUL(a, b);
	*/

	//printf("%02x * %02x = %02x\n", a, b, c);
	//printf("Sbox(%02x) = %02x\n", a, GenSbox(a));
	//printf("Sbox(%02x) = %02x, %02x\n", a, GenSbox(a), Sbox[a]);
	/*printf("Sbox[256] = {");
	for (i = 0; i < 256; i++) {
		printf("0x%02x, ", GenSbox(i));
		if (i % 16 == 15) printf("\n");
	}
	printf("}");*/

	return 0;
}