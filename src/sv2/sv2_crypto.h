/*
 *
 * sv2.cc
 * Stratum V2 in C for DATUM Gateway and the Bitaxe
 *
 * ---
 *
 * Copyright (c) 2026 Vincenzo Palazzo and contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
