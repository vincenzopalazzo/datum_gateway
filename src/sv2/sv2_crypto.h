/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of OCEAN's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://ocean.xyz
 *
 * ---
 *
 * Copyright (c) 2026 Bitcoin Ocean, LLC & Vincenzo Palazzo
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef _SV2_CRYPTO_H_
#define _SV2_CRYPTO_H_

#include "sv2_types.h"

// Symmetric primitives the Noise handshake and transport need.  The
// handshake pattern is Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256, so
// this is SHA-256, HMAC-SHA-256 and ChaCha20-Poly1305 (RFC 8439, 12-byte
// nonce), plus a CSPRNG.  Curve operations go through libsecp256k1
// directly and are not abstracted here.
//
// One backend is compiled in:
//   sv2_crypto_sodium.c   libsodium, used by DATUM Gateway on Linux/BSD
//   sv2_crypto_mbedtls.c  mbedTLS, for ESP-IDF (not yet written)

#define SV2_AEAD_KEY_SIZE 32
#define SV2_AEAD_MAC_SIZE 16
#define SV2_HASH_SIZE 32

// Must be called once per process before any other function here.
int sv2_crypto_init(void);

void sv2_crypto_sha256(const unsigned char *in, size_t len, unsigned char out[SV2_HASH_SIZE]);

// SHA-256 of the concatenation a || b, without copying
void sv2_crypto_sha256_2(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen, unsigned char out[SV2_HASH_SIZE]);

void sv2_crypto_hmac_sha256(const unsigned char key[SV2_HASH_SIZE], const unsigned char *data, size_t len, unsigned char out[SV2_HASH_SIZE]);

// ct must have room for pt_len + SV2_AEAD_MAC_SIZE bytes.  nonce is the
// Noise counter, encoded as 4 zero bytes followed by the little endian u64.
int sv2_crypto_aead_encrypt(const unsigned char key[SV2_AEAD_KEY_SIZE], uint64_t nonce, const unsigned char *ad, size_t ad_len, const unsigned char *pt, size_t pt_len, unsigned char *ct);

// pt must have room for ct_len - SV2_AEAD_MAC_SIZE bytes.  Returns
// SV2_ERR_CRYPTO when the tag does not verify.
int sv2_crypto_aead_decrypt(const unsigned char key[SV2_AEAD_KEY_SIZE], uint64_t nonce, const unsigned char *ad, size_t ad_len, const unsigned char *ct, size_t ct_len, unsigned char *pt);

void sv2_crypto_random(unsigned char *buf, size_t len);

// Zero memory in a way the compiler will not optimise away
void sv2_crypto_memzero(void *p, size_t len);

// Constant time comparison, returns true when equal
bool sv2_crypto_equal(const unsigned char *a, const unsigned char *b, size_t len);

#endif
