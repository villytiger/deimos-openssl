/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

module deimos.openssl.aes;

import deimos.openssl._d_util;

public import deimos.openssl.opensslconf;

import core.stdc.config;

enum AES_ENCRYPT = 1;
enum AES_DECRYPT = 0;

/*
 * Because array size can't be a const in C, the following two are macros.
 * Both sizes are in bytes.
 */
enum AES_MAXNR = 14;
enum AES_BLOCK_SIZE = 16;

extern (C):
nothrow:

/* This should be a hidden type, but EVP requires that the size be known */
struct aes_key_st {
version (AES_LONG) {
    c_ulong[4* (AES_MAXNR + 1)] rd_key;
} else {
    uint[4* (AES_MAXNR + 1)] rd_key;
}
    int rounds;
};
alias aes_key_st AES_KEY;

const(char)* AES_options();

int AES_set_encrypt_key(const(ubyte)* userKey, const int bits,
	AES_KEY* key);
int AES_set_decrypt_key(const(ubyte)* userKey, const int bits,
	AES_KEY* key);

void AES_encrypt(const(ubyte)* in_, ubyte* out_,
	const(AES_KEY)* key);
void AES_decrypt(const(ubyte)* in_, ubyte* out_,
	const(AES_KEY)* key);

void AES_ecb_encrypt(const(ubyte)* in_, ubyte* out_,
	const(AES_KEY)* key, const int enc);
void AES_cbc_encrypt(const(ubyte)* in_, ubyte* out_,
	size_t length, const(AES_KEY)* key,
	ubyte* ivec, const int enc);
void AES_cfb128_encrypt(const(ubyte)* in_, ubyte* out_,
	size_t length, const(AES_KEY)* key,
	ubyte* ivec, int* num, const int enc);
void AES_cfb1_encrypt(const(ubyte)* in_, ubyte* out_,
	size_t length, const(AES_KEY)* key,
	ubyte* ivec, int* num, const int enc);
void AES_cfb8_encrypt(const(ubyte)* in_, ubyte* out_,
	size_t length, const(AES_KEY)* key,
	ubyte* ivec, int* num, const int enc);
void AES_ofb128_encrypt(const(ubyte)* in_, ubyte* out_,
	size_t length, const(AES_KEY)* key,
	ubyte* ivec, int* num);
/* NB: the IV is _two_ blocks long */
void AES_ige_encrypt(const(ubyte)* in_, ubyte* out_,
		     size_t length, const(AES_KEY)* key,
		     ubyte* ivec, const int enc);
/* NB: the IV is _four_ blocks long */
void AES_bi_ige_encrypt(const(ubyte)* in_, ubyte* out_,
			size_t length, const(AES_KEY)* key,
			const(AES_KEY)* key2, const(ubyte)* ivec,
			const int enc);

int AES_wrap_key(AES_KEY* key, const(ubyte)* iv,
		ubyte* out_,
		const(ubyte)* in_, uint inlen);
int AES_unwrap_key(AES_KEY* key, const(ubyte)* iv,
		ubyte* out_,
		const(ubyte)* in_, uint inlen);
