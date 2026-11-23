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

#include <string.h>

#include <secp256k1_ellswift.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include "sv2_noise.h"

// SHA-256 of SV2_NOISE_PROTOCOL_NAME.  The name is longer than 32 bytes, so
// per the Noise spec the hash is used as the initial h and ck.  Checked
// against a live SHA-256 at init so a broken hash backend fails loudly.
static const unsigned char noise_protocol_name_hash[SV2_HASH_SIZE] = {
	46, 180, 120, 129, 32, 142, 158, 238, 31, 102, 159, 103, 198, 110, 231, 14,
	169, 234, 136, 9, 13, 80, 63, 232, 48, 220, 75, 200, 62, 41, 191, 16
};

/////////////////////////////////
// Symmetric state (Noise spec 5.2)
/////////////////////////////////

static void mix_hash(T_SV2_NOISE *n, const unsigned char *data, size_t len) {
	unsigned char out[SV2_HASH_SIZE];
	sv2_crypto_sha256_2(n->h, SV2_HASH_SIZE, data, len, out);
	memcpy(n->h, out, SV2_HASH_SIZE);
}

static void hkdf2(const unsigned char ck[SV2_HASH_SIZE], const unsigned char *ikm, size_t ikm_len, unsigned char out1[SV2_HASH_SIZE], unsigned char out2[SV2_HASH_SIZE]) {
	unsigned char temp[SV2_HASH_SIZE];
	unsigned char in2[SV2_HASH_SIZE + 1];
	const unsigned char one = 0x01;
	
	sv2_crypto_hmac_sha256(ck, ikm, ikm_len, temp);
	sv2_crypto_hmac_sha256(temp, &one, 1, out1);
	memcpy(in2, out1, SV2_HASH_SIZE);
	in2[SV2_HASH_SIZE] = 0x02;
	sv2_crypto_hmac_sha256(temp, in2, sizeof(in2), out2);
	
	sv2_crypto_memzero(temp, sizeof(temp));
	sv2_crypto_memzero(in2, sizeof(in2));
}

static void mix_key(T_SV2_NOISE *n, const unsigned char ikm[32]) {
	unsigned char ck[SV2_HASH_SIZE];
	unsigned char k[SV2_HASH_SIZE];
	hkdf2(n->ck, ikm, 32, ck, k);
	memcpy(n->ck, ck, SV2_HASH_SIZE);
	memcpy(n->hs.k, k, SV2_AEAD_KEY_SIZE);
	n->hs.n = 0;
	n->hs.has_k = true;
	sv2_crypto_memzero(ck, sizeof(ck));
	sv2_crypto_memzero(k, sizeof(k));
}

// EncryptAndHash: with a key, ciphertext is pt_len + MAC; without, the
// plaintext is passed through.  Either way the bytes on the wire are mixed
// into h.
static int encrypt_and_hash(T_SV2_NOISE *n, const unsigned char *pt, size_t pt_len, unsigned char *out, size_t out_cap, size_t *out_len) {
	if (n->hs.has_k) {
		if (pt_len + SV2_AEAD_MAC_SIZE > out_cap) return SV2_ERR_OVERFLOW;
		if (n->hs.n == UINT64_MAX) return SV2_ERR_NONCE;
		if (sv2_crypto_aead_encrypt(n->hs.k, n->hs.n, n->h, SV2_HASH_SIZE, pt, pt_len, out) != SV2_OK) return SV2_ERR_CRYPTO;
		n->hs.n++;
		*out_len = pt_len + SV2_AEAD_MAC_SIZE;
	} else {
		if (pt_len > out_cap) return SV2_ERR_OVERFLOW;
		if (pt_len) memcpy(out, pt, pt_len);
		*out_len = pt_len;
	}
	mix_hash(n, out, *out_len);
	return SV2_OK;
}

static int decrypt_and_hash(T_SV2_NOISE *n, const unsigned char *ct, size_t ct_len, unsigned char *out, size_t out_cap, size_t *out_len) {
	if (n->hs.has_k) {
		if (ct_len < SV2_AEAD_MAC_SIZE) return SV2_ERR_INVALID;
		if (ct_len - SV2_AEAD_MAC_SIZE > out_cap) return SV2_ERR_OVERFLOW;
		if (n->hs.n == UINT64_MAX) return SV2_ERR_NONCE;
		if (sv2_crypto_aead_decrypt(n->hs.k, n->hs.n, n->h, SV2_HASH_SIZE, ct, ct_len, out) != SV2_OK) return SV2_ERR_CRYPTO;
		n->hs.n++;
		*out_len = ct_len - SV2_AEAD_MAC_SIZE;
	} else {
		if (ct_len > out_cap) return SV2_ERR_OVERFLOW;
		if (ct_len) memcpy(out, ct, ct_len);
		*out_len = ct_len;
	}
	mix_hash(n, ct, ct_len);
	return SV2_OK;
}

static int initialize_symmetric(T_SV2_NOISE *n) {
	unsigned char check[SV2_HASH_SIZE];
	
	sv2_crypto_sha256((const unsigned char *)SV2_NOISE_PROTOCOL_NAME, strlen(SV2_NOISE_PROTOCOL_NAME), check);
	if (memcmp(check, noise_protocol_name_hash, SV2_HASH_SIZE) != 0) return SV2_ERR_CRYPTO;
	
	memcpy(n->ck, noise_protocol_name_hash, SV2_HASH_SIZE);
	memcpy(n->h, noise_protocol_name_hash, SV2_HASH_SIZE);
	
	// MixHash(prologue) with the empty prologue SV2 uses
	mix_hash(n, NULL, 0);
	
	n->hs.has_k = false;
	n->hs.n = 0;
	return SV2_OK;
}

/////////////////////////////////
// Keys
/////////////////////////////////

static int generate_secret_key(secp256k1_context *secp, unsigned char sk[32]) {
	int tries;
	// A random 32 byte string is a valid secret key with overwhelming
	// probability; the loop only exists so the failure path is not silent.
	for (tries = 0; tries < 16; tries++) {
		sv2_crypto_random(sk, 32);
		if (secp256k1_ec_seckey_verify(secp, sk)) return SV2_OK;
	}
	return SV2_ERR_CRYPTO;
}

static int ellswift_from_secret(secp256k1_context *secp, const unsigned char sk[32], unsigned char ell[SV2_NOISE_ELLSWIFT_SIZE]) {
	unsigned char aux[32];
	int ok;
	sv2_crypto_random(aux, sizeof(aux));
	ok = secp256k1_ellswift_create(secp, ell, sk, aux);
	sv2_crypto_memzero(aux, sizeof(aux));
	return ok ? SV2_OK : SV2_ERR_CRYPTO;
}

static int xonly_from_secret(secp256k1_context *secp, const unsigned char sk[32], unsigned char xonly[32]) {
	secp256k1_keypair kp;
	secp256k1_xonly_pubkey xpk;
	int ok = secp256k1_keypair_create(secp, &kp, sk);
	if (ok) ok = secp256k1_keypair_xonly_pub(secp, &xpk, NULL, &kp);
	if (ok) ok = secp256k1_xonly_pubkey_serialize(secp, xonly, &xpk);
	sv2_crypto_memzero(&kp, sizeof(kp));
	return ok ? SV2_OK : SV2_ERR_CRYPTO;
}

// party: 0 when sk belongs to ell_a (the initiator side), 1 for ell_b
static int ecdh(secp256k1_context *secp, const unsigned char ell_a[64], const unsigned char ell_b[64], const unsigned char sk[32], int party, unsigned char out[32]) {
	if (!secp256k1_ellswift_xdh(secp, out, ell_a, ell_b, sk, party, secp256k1_ellswift_xdh_hash_function_bip324, NULL)) {
		return SV2_ERR_CRYPTO;
	}
	return SV2_OK;
}

static void cert_digest(const unsigned char cert_head[10], const unsigned char static_xonly[32], unsigned char out[32]) {
	sv2_crypto_sha256_2(cert_head, 10, static_xonly, 32, out);
}

static int sign_certificate(T_SV2_NOISE_RESPONDER_KEYS *keys, secp256k1_context *secp, uint32_t now) {
	secp256k1_keypair kp;
	unsigned char digest[32];
	unsigned char aux[32];
	int ok;
	
	keys->cert_valid_from = now;
	keys->cert_not_valid_after = (now > UINT32_MAX - keys->cert_validity_seconds) ? UINT32_MAX : now + keys->cert_validity_seconds;
	
	sv2_put_u16(keys->cert, SV2_NOISE_CERTIFICATE_VERSION);
	sv2_put_u32(keys->cert + 2, keys->cert_valid_from);
	sv2_put_u32(keys->cert + 6, keys->cert_not_valid_after);
	
	cert_digest(keys->cert, keys->static_xonly, digest);
	sv2_crypto_random(aux, sizeof(aux));
	
	ok = secp256k1_keypair_create(secp, &kp, keys->authority_sk);
	if (ok) ok = secp256k1_schnorrsig_sign32(secp, keys->cert + 10, digest, &kp, aux);
	
	sv2_crypto_memzero(&kp, sizeof(kp));
	sv2_crypto_memzero(aux, sizeof(aux));
	return ok ? SV2_OK : SV2_ERR_CRYPTO;
}

int sv2_noise_responder_keys_init(T_SV2_NOISE_RESPONDER_KEYS *keys, secp256k1_context *secp, const unsigned char *authority_sk, uint32_t cert_validity_seconds, uint32_t now) {
	int r;
	
	memset(keys, 0, sizeof(*keys));
	if (!cert_validity_seconds) return SV2_ERR_INVALID;
	keys->cert_validity_seconds = cert_validity_seconds;
	
	if (authority_sk) {
		memcpy(keys->authority_sk, authority_sk, 32);
		if (!secp256k1_ec_seckey_verify(secp, keys->authority_sk)) return SV2_ERR_INVALID;
	} else {
		r = generate_secret_key(secp, keys->authority_sk);
		if (r != SV2_OK) return r;
	}
	r = xonly_from_secret(secp, keys->authority_sk, keys->authority_pk);
	if (r != SV2_OK) return r;
	
	r = generate_secret_key(secp, keys->static_sk);
	if (r != SV2_OK) return r;
	r = ellswift_from_secret(secp, keys->static_sk, keys->static_ellswift);
	if (r != SV2_OK) return r;
	r = xonly_from_secret(secp, keys->static_sk, keys->static_xonly);
	if (r != SV2_OK) return r;
	
	return sign_certificate(keys, secp, now);
}

int sv2_noise_responder_keys_refresh(T_SV2_NOISE_RESPONDER_KEYS *keys, secp256k1_context *secp, uint32_t now, bool *renewed) {
	uint32_t half = keys->cert_validity_seconds / 2;
	*renewed = false;
	if (now < keys->cert_valid_from + half && now >= keys->cert_valid_from) return SV2_OK;
	*renewed = true;
	return sign_certificate(keys, secp, now);
}

/////////////////////////////////
// Base58check for the authority public key
/////////////////////////////////

// Payload layout: u16 version (little endian, currently 1) || 32 byte
// x-only key || 4 byte checksum (first bytes of SHA256d over the 34 bytes
// before it).  38 bytes total, which base58 encodes to at most 53 chars.

#define AUTHORITY_KEY_VERSION 1
#define AUTHORITY_KEY_RAW_SIZE 38

static const char b58_alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static int base58_encode(const unsigned char *in, size_t in_len, char *out, size_t out_sz) {
	unsigned char digits[64];
	size_t digits_len = 1;
	size_t i, j, zeros = 0, pos = 0;
	
	if (in_len > 40) return SV2_ERR_INVALID;
	while (zeros < in_len && in[zeros] == 0) zeros++;
	
	digits[0] = 0;
	for (i = zeros; i < in_len; i++) {
		unsigned int carry = in[i];
		for (j = 0; j < digits_len; j++) {
			carry += (unsigned int)digits[j] << 8;
			digits[j] = (unsigned char)(carry % 58);
			carry /= 58;
		}
		while (carry) {
			if (digits_len >= sizeof(digits)) return SV2_ERR_OVERFLOW;
			digits[digits_len++] = (unsigned char)(carry % 58);
			carry /= 58;
		}
	}
	
	if (zeros + digits_len + 1 > out_sz) return SV2_ERR_OVERFLOW;
	for (i = 0; i < zeros; i++) out[pos++] = '1';
	for (i = 0; i < digits_len; i++) out[pos++] = b58_alphabet[digits[digits_len - 1 - i]];
	out[pos] = 0;
	return (int)pos;
}

static int base58_decode(const char *in, unsigned char *out, size_t out_sz, size_t *out_len) {
	unsigned char bytes[64];
	size_t bytes_len = 1;
	size_t i, j, zeros = 0, n;
	
	bytes[0] = 0;
	while (in[zeros] == '1') zeros++;
	
	for (i = zeros; in[i]; i++) {
		const char *p = strchr(b58_alphabet, in[i]);
		unsigned int carry;
		if (!p || !in[i]) return SV2_ERR_INVALID;
		carry = (unsigned int)(p - b58_alphabet);
		for (j = 0; j < bytes_len; j++) {
			carry += (unsigned int)bytes[j] * 58;
			bytes[j] = (unsigned char)(carry & 0xFF);
			carry >>= 8;
		}
		while (carry) {
			if (bytes_len >= sizeof(bytes)) return SV2_ERR_OVERFLOW;
			bytes[bytes_len++] = (unsigned char)(carry & 0xFF);
			carry >>= 8;
		}
	}
	
	// strip the leading zero produced by the empty accumulator
	while (bytes_len > 1 && bytes[bytes_len - 1] == 0) bytes_len--;
	if (bytes_len == 1 && bytes[0] == 0) bytes_len = 0;
	
	n = zeros + bytes_len;
	if (n > out_sz) return SV2_ERR_OVERFLOW;
	for (i = 0; i < zeros; i++) out[i] = 0;
	for (i = 0; i < bytes_len; i++) out[zeros + i] = bytes[bytes_len - 1 - i];
	*out_len = n;
	return SV2_OK;
}

static void sha256d(const unsigned char *in, size_t len, unsigned char out[32]) {
	unsigned char tmp[32];
	sv2_crypto_sha256(in, len, tmp);
	sv2_crypto_sha256(tmp, 32, out);
}

int sv2_noise_authority_pk_to_base58(const unsigned char pk[32], char *out, size_t out_sz) {
	unsigned char raw[AUTHORITY_KEY_RAW_SIZE];
	unsigned char check[32];
	sv2_put_u16(raw, AUTHORITY_KEY_VERSION);
	memcpy(raw + 2, pk, 32);
	sha256d(raw, 34, check);
	memcpy(raw + 34, check, 4);
	return base58_encode(raw, sizeof(raw), out, out_sz);
}

int sv2_noise_authority_pk_from_base58(const char *in, unsigned char pk[32]) {
	unsigned char raw[64];
	unsigned char check[32];
	size_t raw_len = 0;
	int r = base58_decode(in, raw, sizeof(raw), &raw_len);
	if (r != SV2_OK) return r;
	if (raw_len != AUTHORITY_KEY_RAW_SIZE) return SV2_ERR_INVALID;
	if (sv2_get_u16(raw) != AUTHORITY_KEY_VERSION) return SV2_ERR_INVALID;
	sha256d(raw, 34, check);
	if (memcmp(check, raw + 34, 4) != 0) return SV2_ERR_INVALID;
	memcpy(pk, raw + 2, 32);
	return SV2_OK;
}

/////////////////////////////////
// Handshake
/////////////////////////////////

void sv2_noise_clear(T_SV2_NOISE *n) {
	secp256k1_context *secp = n->secp;
	sv2_crypto_memzero(n, sizeof(*n));
	n->secp = secp;
	n->state = SV2_NOISE_STATE_DEAD;
}

int sv2_noise_init_responder(T_SV2_NOISE *n, secp256k1_context *secp, const T_SV2_NOISE_RESPONDER_KEYS *keys) {
	int r;
	memset(n, 0, sizeof(*n));
	n->secp = secp;
	n->is_initiator = false;
	n->keys = keys;
	r = initialize_symmetric(n);
	if (r != SV2_OK) {
		n->state = SV2_NOISE_STATE_DEAD;
		return r;
	}
	n->state = SV2_NOISE_STATE_INIT;
	return SV2_OK;
}

int sv2_noise_init_initiator(T_SV2_NOISE *n, secp256k1_context *secp, const unsigned char *authority_pk) {
	int r;
	memset(n, 0, sizeof(*n));
	n->secp = secp;
	n->is_initiator = true;
	if (authority_pk) {
		n->has_authority_pk = true;
		memcpy(n->authority_pk, authority_pk, 32);
	}
	r = initialize_symmetric(n);
	if (r != SV2_OK) {
		n->state = SV2_NOISE_STATE_DEAD;
		return r;
	}
	n->state = SV2_NOISE_STATE_INIT;
	return SV2_OK;
}

static void split(T_SV2_NOISE *n) {
	unsigned char k1[SV2_HASH_SIZE];
	unsigned char k2[SV2_HASH_SIZE];
	hkdf2(n->ck, NULL, 0, k1, k2);
	// The initiator sends with the first key, the responder with the second
	memcpy(n->send.k, n->is_initiator ? k1 : k2, SV2_AEAD_KEY_SIZE);
	memcpy(n->recv.k, n->is_initiator ? k2 : k1, SV2_AEAD_KEY_SIZE);
	n->send.n = 0;
	n->recv.n = 0;
	n->send.has_k = true;
	n->recv.has_k = true;
	sv2_crypto_memzero(k1, sizeof(k1));
	sv2_crypto_memzero(k2, sizeof(k2));
	
	// handshake material is no longer needed
	sv2_crypto_memzero(n->h, sizeof(n->h));
	sv2_crypto_memzero(n->ck, sizeof(n->ck));
	sv2_crypto_memzero(&n->hs, sizeof(n->hs));
	sv2_crypto_memzero(n->e_sk, sizeof(n->e_sk));
	n->rx_have_header = false;
	n->state = SV2_NOISE_STATE_TRANSPORT;
}

int sv2_noise_initiator_act1(T_SV2_NOISE *n, unsigned char out[SV2_NOISE_ACT1_SIZE]) {
	int r;
	size_t empty_len = 0;
	
	if (!n->is_initiator || n->state != SV2_NOISE_STATE_INIT) return SV2_ERR_STATE;
	
	r = generate_secret_key(n->secp, n->e_sk);
	if (r != SV2_OK) goto fail;
	r = ellswift_from_secret(n->secp, n->e_sk, n->e_ellswift);
	if (r != SV2_OK) goto fail;
	
	// -> e
	memcpy(out, n->e_ellswift, SV2_NOISE_ELLSWIFT_SIZE);
	mix_hash(n, n->e_ellswift, SV2_NOISE_ELLSWIFT_SIZE);
	
	// The pattern's first message carries an empty payload, which is still
	// run through EncryptAndHash (a bare MixHash while there is no key).
	r = encrypt_and_hash(n, NULL, 0, out + SV2_NOISE_ELLSWIFT_SIZE, SV2_NOISE_ACT1_SIZE - SV2_NOISE_ELLSWIFT_SIZE, &empty_len);
	if (r != SV2_OK || empty_len != 0) goto fail;
	
	n->state = SV2_NOISE_STATE_ACT1_SENT;
	return SV2_OK;
	
fail:
	sv2_noise_clear(n);
	return r;
}

int sv2_noise_responder_act2(T_SV2_NOISE *n, const unsigned char in[SV2_NOISE_ACT1_SIZE], unsigned char out[SV2_NOISE_ACT2_SIZE], uint32_t now) {
	unsigned char shared[32];
	unsigned char empty[SV2_AEAD_MAC_SIZE];
	size_t written = 0;
	int r;
	
	if (n->is_initiator || n->state != SV2_NOISE_STATE_INIT || !n->keys) return SV2_ERR_STATE;
	
	// The caller decides when the certificate is renewed; refuse to hand
	// out one that is already expired rather than let every miner fail
	// verification.
	if (now > n->keys->cert_not_valid_after) return SV2_ERR_CERT;
	
	// <- e (theirs), then the empty payload
	mix_hash(n, in, SV2_NOISE_ELLSWIFT_SIZE);
	r = decrypt_and_hash(n, NULL, 0, empty, sizeof(empty), &written);
	if (r != SV2_OK) goto fail;
	
	// -> e (ours)
	r = generate_secret_key(n->secp, n->e_sk);
	if (r != SV2_OK) goto fail;
	r = ellswift_from_secret(n->secp, n->e_sk, n->e_ellswift);
	if (r != SV2_OK) goto fail;
	memcpy(out, n->e_ellswift, SV2_NOISE_ELLSWIFT_SIZE);
	mix_hash(n, n->e_ellswift, SV2_NOISE_ELLSWIFT_SIZE);
	
	// ee
	r = ecdh(n->secp, in, n->e_ellswift, n->e_sk, 1, shared);
	if (r != SV2_OK) goto fail;
	mix_key(n, shared);
	
	// s (encrypted)
	r = encrypt_and_hash(n, n->keys->static_ellswift, SV2_NOISE_ELLSWIFT_SIZE, out + SV2_NOISE_ELLSWIFT_SIZE, SV2_NOISE_ACT2_SIZE - SV2_NOISE_ELLSWIFT_SIZE, &written);
	if (r != SV2_OK) goto fail;
	
	// es
	r = ecdh(n->secp, in, n->keys->static_ellswift, n->keys->static_sk, 1, shared);
	if (r != SV2_OK) goto fail;
	mix_key(n, shared);
	
	// SIGNATURE_NOISE_MESSAGE (encrypted)
	r = encrypt_and_hash(n, n->keys->cert, SV2_NOISE_CERT_SIZE, out + SV2_NOISE_ELLSWIFT_SIZE + SV2_NOISE_ELLSWIFT_SIZE + SV2_AEAD_MAC_SIZE, SV2_NOISE_ACT2_SIZE - (SV2_NOISE_ELLSWIFT_SIZE + SV2_NOISE_ELLSWIFT_SIZE + SV2_AEAD_MAC_SIZE), &written);
	if (r != SV2_OK) goto fail;
	
	sv2_crypto_memzero(shared, sizeof(shared));
	split(n);
	return SV2_OK;
	
fail:
	sv2_crypto_memzero(shared, sizeof(shared));
	sv2_noise_clear(n);
	return r;
}

static bool verify_certificate(T_SV2_NOISE *n, const unsigned char cert[SV2_NOISE_CERT_SIZE], const unsigned char rs_ellswift[64], uint32_t now) {
	secp256k1_pubkey rs_pub;
	secp256k1_xonly_pubkey rs_xonly, auth;
	unsigned char digest[32];
	uint32_t lo, hi;
	
	n->cert.version = sv2_get_u16(cert);
	n->cert.valid_from = sv2_get_u32(cert + 2);
	n->cert.not_valid_after = sv2_get_u32(cert + 6);
	n->cert.authenticated = false;
	
	if (!secp256k1_ellswift_decode(n->secp, &rs_pub, rs_ellswift)) return false;
	if (!secp256k1_xonly_pubkey_from_pubkey(n->secp, &rs_xonly, NULL, &rs_pub)) return false;
	secp256k1_xonly_pubkey_serialize(n->secp, n->cert.responder_static_xonly, &rs_xonly);
	
	if (n->cert.version != SV2_NOISE_CERTIFICATE_VERSION) return false;
	if (!n->has_authority_pk) return true;
	
	lo = (n->cert.valid_from > SV2_NOISE_CERT_TIME_LEEWAY) ? n->cert.valid_from - SV2_NOISE_CERT_TIME_LEEWAY : 0;
	hi = (n->cert.not_valid_after > UINT32_MAX - SV2_NOISE_CERT_TIME_LEEWAY) ? UINT32_MAX : n->cert.not_valid_after + SV2_NOISE_CERT_TIME_LEEWAY;
	if (now < lo || now > hi) return false;
	
	cert_digest(cert, n->cert.responder_static_xonly, digest);
	if (!secp256k1_xonly_pubkey_parse(n->secp, &auth, n->authority_pk)) return false;
	if (!secp256k1_schnorrsig_verify(n->secp, cert + 10, digest, 32, &auth)) return false;
	
	n->cert.authenticated = true;
	return true;
}

int sv2_noise_initiator_act2(T_SV2_NOISE *n, const unsigned char in[SV2_NOISE_ACT2_SIZE], uint32_t now) {
	unsigned char shared[32];
	unsigned char rs[SV2_NOISE_ELLSWIFT_SIZE];
	unsigned char cert[SV2_NOISE_CERT_SIZE];
	size_t written = 0;
	const unsigned char *re = in;
	const unsigned char *enc_s = in + SV2_NOISE_ELLSWIFT_SIZE;
	const unsigned char *enc_cert = enc_s + SV2_NOISE_ELLSWIFT_SIZE + SV2_AEAD_MAC_SIZE;
	int r;
	
	if (!n->is_initiator || n->state != SV2_NOISE_STATE_ACT1_SENT) return SV2_ERR_STATE;
	
	// <- e
	mix_hash(n, re, SV2_NOISE_ELLSWIFT_SIZE);
	
	// ee
	r = ecdh(n->secp, n->e_ellswift, re, n->e_sk, 0, shared);
	if (r != SV2_OK) goto fail;
	mix_key(n, shared);
	
	// s
	r = decrypt_and_hash(n, enc_s, SV2_NOISE_ELLSWIFT_SIZE + SV2_AEAD_MAC_SIZE, rs, sizeof(rs), &written);
	if (r != SV2_OK) goto fail;
	
	// es
	r = ecdh(n->secp, n->e_ellswift, rs, n->e_sk, 0, shared);
	if (r != SV2_OK) goto fail;
	mix_key(n, shared);
	
	// SIGNATURE_NOISE_MESSAGE
	r = decrypt_and_hash(n, enc_cert, SV2_NOISE_CERT_SIZE + SV2_AEAD_MAC_SIZE, cert, sizeof(cert), &written);
	if (r != SV2_OK) goto fail;
	
	if (!verify_certificate(n, cert, rs, now)) {
		r = SV2_ERR_CERT;
		goto fail;
	}
	
	sv2_crypto_memzero(shared, sizeof(shared));
	split(n);
	return SV2_OK;
	
fail:
	sv2_crypto_memzero(shared, sizeof(shared));
	sv2_noise_clear(n);
	return r;
}

/////////////////////////////////
// Transport
/////////////////////////////////

uint32_t sv2_noise_encrypted_payload_size(uint32_t payload_len) {
	uint32_t chunks = (payload_len + SV2_NOISE_MAX_PLAINTEXT_CHUNK - 1) / SV2_NOISE_MAX_PLAINTEXT_CHUNK;
	return payload_len + chunks * SV2_AEAD_MAC_SIZE;
}

uint32_t sv2_noise_encrypted_frame_size(uint32_t frame_len) {
	if (frame_len < SV2_FRAME_HEADER_SIZE) return 0;
	return SV2_NOISE_ENC_HEADER_SIZE + sv2_noise_encrypted_payload_size(frame_len - SV2_FRAME_HEADER_SIZE);
}

static int transport_encrypt(T_SV2_CIPHER_STATE *cs, const unsigned char *pt, size_t pt_len, unsigned char *ct) {
	if (!cs->has_k) return SV2_ERR_STATE;
	if (cs->n == UINT64_MAX) return SV2_ERR_NONCE;
	if (sv2_crypto_aead_encrypt(cs->k, cs->n, NULL, 0, pt, pt_len, ct) != SV2_OK) return SV2_ERR_CRYPTO;
	cs->n++;
	return SV2_OK;
}

static int transport_decrypt(T_SV2_CIPHER_STATE *cs, const unsigned char *ct, size_t ct_len, unsigned char *pt) {
	if (!cs->has_k) return SV2_ERR_STATE;
	if (cs->n == UINT64_MAX) return SV2_ERR_NONCE;
	if (sv2_crypto_aead_decrypt(cs->k, cs->n, NULL, 0, ct, ct_len, pt) != SV2_OK) return SV2_ERR_CRYPTO;
	cs->n++;
	return SV2_OK;
}

int sv2_noise_encrypt_frame(T_SV2_NOISE *n, const unsigned char *frame, uint32_t frame_len, unsigned char *out, uint32_t out_cap) {
	T_SV2_FRAME_HEADER h;
	uint32_t total, pos_in, pos_out, chunk;
	int r;
	
	if (n->state != SV2_NOISE_STATE_TRANSPORT) return SV2_ERR_STATE;
	if (frame_len < SV2_FRAME_HEADER_SIZE) return SV2_ERR_INVALID;
	
	r = sv2_frame_header_parse(frame, frame_len, &h);
	if (r != SV2_OK) return r;
	if (h.msg_length != frame_len - SV2_FRAME_HEADER_SIZE) return SV2_ERR_INVALID;
	
	total = sv2_noise_encrypted_frame_size(frame_len);
	if (total > out_cap) return SV2_ERR_OVERFLOW;
	
	r = transport_encrypt(&n->send, frame, SV2_FRAME_HEADER_SIZE, out);
	if (r != SV2_OK) goto fail;
	
	pos_in = SV2_FRAME_HEADER_SIZE;
	pos_out = SV2_NOISE_ENC_HEADER_SIZE;
	while (pos_in < frame_len) {
		chunk = frame_len - pos_in;
		if (chunk > SV2_NOISE_MAX_PLAINTEXT_CHUNK) chunk = SV2_NOISE_MAX_PLAINTEXT_CHUNK;
		r = transport_encrypt(&n->send, frame + pos_in, chunk, out + pos_out);
		if (r != SV2_OK) goto fail;
		pos_in += chunk;
		pos_out += chunk + SV2_AEAD_MAC_SIZE;
	}
	
	return (int)total;
	
fail:
	// A failed encryption leaves the nonce sequence unusable; the caller
	// has to drop the connection.
	n->state = SV2_NOISE_STATE_DEAD;
	return r;
}

int sv2_noise_read_frame(T_SV2_NOISE *n, const unsigned char *in, uint32_t in_len, unsigned char *out, uint32_t out_cap, uint32_t *out_len, uint32_t *consumed) {
	uint32_t enc_payload, pos_in, pos_out, chunk, remaining;
	int r;
	
	*out_len = 0;
	*consumed = 0;
	
	if (n->state != SV2_NOISE_STATE_TRANSPORT) return SV2_ERR_STATE;
	
	if (!n->rx_have_header) {
		if (in_len < SV2_NOISE_ENC_HEADER_SIZE) return SV2_NEED_MORE;
		r = transport_decrypt(&n->recv, in, SV2_NOISE_ENC_HEADER_SIZE, n->rx_header_bytes);
		if (r != SV2_OK) goto fail;
		r = sv2_frame_header_parse(n->rx_header_bytes, SV2_FRAME_HEADER_SIZE, &n->rx_header);
		if (r != SV2_OK) goto fail;
		n->rx_have_header = true;
		*consumed = SV2_NOISE_ENC_HEADER_SIZE;
		in += SV2_NOISE_ENC_HEADER_SIZE;
		in_len -= SV2_NOISE_ENC_HEADER_SIZE;
	}
	
	// Bound the frame before waiting for it so an attacker cannot make us
	// buffer 16 MB per connection.
	if (n->rx_header.msg_length > out_cap || SV2_FRAME_HEADER_SIZE + n->rx_header.msg_length > out_cap) {
		r = SV2_ERR_OVERFLOW;
		goto fail;
	}
	
	enc_payload = sv2_noise_encrypted_payload_size(n->rx_header.msg_length);
	if (in_len < enc_payload) return SV2_NEED_MORE;
	
	memcpy(out, n->rx_header_bytes, SV2_FRAME_HEADER_SIZE);
	pos_in = 0;
	pos_out = SV2_FRAME_HEADER_SIZE;
	remaining = n->rx_header.msg_length;
	while (remaining) {
		chunk = remaining > SV2_NOISE_MAX_PLAINTEXT_CHUNK ? SV2_NOISE_MAX_PLAINTEXT_CHUNK : remaining;
		r = transport_decrypt(&n->recv, in + pos_in, chunk + SV2_AEAD_MAC_SIZE, out + pos_out);
		if (r != SV2_OK) goto fail;
		pos_in += chunk + SV2_AEAD_MAC_SIZE;
		pos_out += chunk;
		remaining -= chunk;
	}
	
	n->rx_have_header = false;
	*consumed += enc_payload;
	*out_len = pos_out;
	return SV2_OK;
	
fail:
	n->state = SV2_NOISE_STATE_DEAD;
	return r;
}
