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

#include <sodium.h>
#include <string.h>

#include "sv2_crypto.h"

int sv2_crypto_init(void) {
	if (sodium_init() < 0) return SV2_ERR_CRYPTO;
	return SV2_OK;
}

void sv2_crypto_sha256(const unsigned char *in, size_t len, unsigned char out[SV2_HASH_SIZE]) {
	crypto_hash_sha256(out, in, len);
}

void sv2_crypto_sha256_2(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen, unsigned char out[SV2_HASH_SIZE]) {
	crypto_hash_sha256_state st;
	crypto_hash_sha256_init(&st);
	if (alen) crypto_hash_sha256_update(&st, a, alen);
	if (blen) crypto_hash_sha256_update(&st, b, blen);
	crypto_hash_sha256_final(&st, out);
}

void sv2_crypto_hmac_sha256(const unsigned char key[SV2_HASH_SIZE], const unsigned char *data, size_t len, unsigned char out[SV2_HASH_SIZE]) {
	// crypto_auth_hmacsha256 takes exactly a 32 byte key, which is the only
	// key size Noise ever uses (chaining key or temp key).
	crypto_auth_hmacsha256(out, data, len, key);
}

static void nonce_bytes(uint64_t nonce, unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES]) {
	int i;
	npub[0] = npub[1] = npub[2] = npub[3] = 0;
	for (i = 0; i < 8; i++) {
		npub[4 + i] = (unsigned char)((nonce >> (i * 8)) & 0xFF);
	}
}

int sv2_crypto_aead_encrypt(const unsigned char key[SV2_AEAD_KEY_SIZE], uint64_t nonce, const unsigned char *ad, size_t ad_len, const unsigned char *pt, size_t pt_len, unsigned char *ct) {
	unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
	unsigned long long clen = 0;
	nonce_bytes(nonce, npub);
	if (crypto_aead_chacha20poly1305_ietf_encrypt(ct, &clen, pt, pt_len, ad, ad_len, NULL, npub, key) != 0) {
		return SV2_ERR_CRYPTO;
	}
	if (clen != pt_len + SV2_AEAD_MAC_SIZE) return SV2_ERR_CRYPTO;
	return SV2_OK;
}

int sv2_crypto_aead_decrypt(const unsigned char key[SV2_AEAD_KEY_SIZE], uint64_t nonce, const unsigned char *ad, size_t ad_len, const unsigned char *ct, size_t ct_len, unsigned char *pt) {
	unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
	unsigned long long mlen = 0;
	if (ct_len < SV2_AEAD_MAC_SIZE) return SV2_ERR_INVALID;
	nonce_bytes(nonce, npub);
	if (crypto_aead_chacha20poly1305_ietf_decrypt(pt, &mlen, NULL, ct, ct_len, ad, ad_len, npub, key) != 0) {
		return SV2_ERR_CRYPTO;
	}
	if (mlen != ct_len - SV2_AEAD_MAC_SIZE) return SV2_ERR_CRYPTO;
	return SV2_OK;
}

void sv2_crypto_random(unsigned char *buf, size_t len) {
	randombytes_buf(buf, len);
}

void sv2_crypto_memzero(void *p, size_t len) {
	sodium_memzero(p, len);
}

bool sv2_crypto_equal(const unsigned char *a, const unsigned char *b, size_t len) {
	return sodium_memcmp(a, b, len) == 0;
}
