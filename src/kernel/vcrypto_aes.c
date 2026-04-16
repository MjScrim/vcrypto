#include <linux/string.h>
#include "vcrypto_aes.h"

/*
 * =========================================================================
 * vCrypto AES-128 Mathematical Engine
 * =========================================================================
 * * This file implements the core mathematics of the Advanced Encryption
 * Standard (AES). It acts as a pure computation engine, completely isolated
 * from the Virtual File System (VFS), ioctl routing, and hardware locks.
 *
 * AES State Matrix Architecture:
 * ------------------------------
 * AES does not process data sequentially byte-by-byte. Instead, it maps a
 * 16-byte linear input block (b0 to b15) into a 4x4 column-major matrix
 * known as the "State Matrix". All algebraic transformations (SubBytes,
 * ShiftRows, MixColumns) operate on this 2D grid.
 *
 * Linear Input:  [ b0, b1, b2, b3, b4, b5 ... b15 ]
 *
 * Mapped State Matrix (Column-Major Order):
 * [Col 0] [Col 1] [Col 2] [Col 3]
 * +------+------+------+------+
 * Row 0 |  b0  |  b4  |  b8  | b12  |
 * Row 1 |  b1  |  b5  |  b9  | b13  |
 * Row 2 |  b2  |  b6  | b10  | b14  |
 * Row 3 |  b3  |  b7  | b11  | b15  |
 * +------+------+------+------+
 */


/*
 * Substitution Box (S-Box)
 * ------------------------
 * A pre-calculated lookup table used for the non-linear substitution step
 * (SubBytes). It is mathematically constructed by finding the multiplicative
 * inverse of a byte in the Galois Field GF(2^8), followed by an affine
 * transformation.
 *
 * Design note: 'static const' forces the GCC compiler to place this 256-byte
 * array into the '.rodata' (Read-Only) section of the kernel module. This
 * prevents buffer overflow exploits from altering the cryptographic math and
 * heavily optimizes CPU cache hits.
 */
static const uint8_t sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/*
 * Round Constant (Rcon)
 * --------------------
 * Used exclusively during the Key Expansion (Key Schedule) phase. It dictates
 * the multiplication constants to ensure that each round key is mathematically 
 * unique, preventing structural symmetries in the encryption loop.
 */
static const uint8_t rcon[11] = {
	0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

size_t aes_apply_padding(uint8_t *buffer, size_t current_len, size_t max_len)
{
	uint8_t padding_val = AES_BLOCK_SIZE - (current_len & AES_BLOCK_SIZE);
	size_t new_len = current_len + padding_val;
	size_t i;

	if (new_len > max_len)
		return 0;

	for (i = 0; i < padding_val; i++) {
		buffer[current_len + i] = padding_val;
	}

	return new_len;
}

void aes_expand_key(const uint8_t *key, uint8_t *expanded_key)
{
	uint32_t i;
	uint8_t temp[4];
	uint8_t k;

	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		expanded_key[i] = key[i];
	}

	for (i = 16; i < 176; i += 4) {
		temp[0] = expanded_key[i - 4];
		temp[1] = expanded_key[i - 3];
		temp[2] = expanded_key[i - 2];
		temp[3] = expanded_key[i - 1];

		if (i % AES_BLOCK_SIZE == 0) {
			k = temp[0];
			temp[0] = sbox[temp[1]] ^ rcon[ i / AES_BLOCK_SIZE];
			temp[1] = sbox[temp[2]];
			temp[2] = sbox[temp[3]];
			temp[3] = sbox[k];
		}

		expanded_key[i] = expanded_key[i - AES_BLOCK_SIZE] ^ temp[0];
		expanded_key[i + 1] = expanded_key[i - (AES_BLOCK_SIZE - 1)] ^ temp[1];
		expanded_key[i + 2] = expanded_key[i - (AES_BLOCK_SIZE - 2)] ^ temp[2];
		expanded_key[i + 3] = expanded_key[i - (AES_BLOCK_SIZE - 3)] ^ temp[3];
	}
}

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
	uint8_t p = 0;
	int counter;
	uint8_t hi_bit_set;

	for (counter = 0; counter < 8; counter++) {
		if ((b & 1) != 0) {
			p ^= a;
		}
		hi_bit_set = (a & 0x80);
		a <<= 1;
		if (hi_bit_set != 0) {
			a ^= 0x18;
		}
		b >>= 1;
	}

	return p;
}

static void add_round_key(uint8_t *state, const uint8_t *round_key)
{
	int i;
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		state[i] ^= round_key[i];
	}
}

static void sub_bytes(uint8_t *state)
{
	int i;
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		state[i] = sbox[state[i]];
	}
}

static void shift_rows(uint8_t *state)
{
	uint8_t temp;

	temp = state[1];
	state[1] = state[5];
	state[5] = state[9];
	state[9] = state[13];
	state[13] = temp;

	temp = state[2];
	state[2] = state[10];
	state[10] = temp;
	temp = state[6];
	state[6] = state[14];
	state[14] = temp;

	temp = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7] = state[3];
	state[3] = temp;

}

static void mix_columns(uint8_t *state)
{
	uint8_t temp[16];
	int i;

	for (i = 0; i < 4; i++) {
		uint8_t *col = &state[i * 4];
		temp[i * 4 + 0] = gf_mul(0x02, col[0]) ^ gf_mul(0x03, col[1]) ^ col[2] ^ col[3];
		temp[i * 4 + 1] = col[0] ^ gf_mul(0x02, col[1]) ^ gf_mul(0x03, col[2]) ^ col[3];
		temp[i * 4 + 2] = col[0] ^ col[1] ^ gf_mul(0x02, col[2]) ^ gf_mul(0x03, col[3]);
		temp[i * 4 + 3] = gf_mul(0x03, col[0]) ^ col[1] ^ col[2] ^ gf_mul(0x02, col[3]);
	}

	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		state[i] = temp[i];
	}
}

void aes_encrypt_block(uint8_t *state, const uint8_t *expanded_key)
{
	int round;

	add_round_key(state, expanded_key);

	for (round = 1; round < 10; round++) {
		sub_bytes(state);
		shift_rows(state);
		mix_columns(state);
		add_round_key(state, expanded_key + (round + AES_BLOCK_SIZE));
	}

	sub_bytes(state);
	shift_rows(state);
	add_round_key(state, expanded_key + 160);
}
