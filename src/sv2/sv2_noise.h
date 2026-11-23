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

#ifndef _SV2_NOISE_H_
#define _SV2_NOISE_H_

#include <secp256k1.h>

#include "sv2_crypto.h"
#include "sv2_frame.h"

// Stratum V2 protocol security, spec section 4.
//
// Handshake: Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256
//
//   -> e                        64 bytes: initiator ephemeral, ElligatorSwift
//   <- e, ee, s, es, SIGNATURE  64 + (64+16) + (74+16) = 234 bytes
//
// The responder proves who it is with a SIGNATURE_NOISE_MESSAGE: a
// certificate over its static key, signed (BIP-340 Schnorr) by a long-term
// authority key the initiator is expected to know out of band.
//
// Transport: every SV2 frame becomes
//
//   AEAD(header, 6 bytes) -> 22 bytes
//   AEAD(payload chunk)   -> up to 65535 bytes each, chunks of 65519 plaintext
//
// with one AEAD nonce per encryption and no additional data.  The header is
// decrypted first and its msg_length tells the receiver how much ciphertext
// follows.  There is no other length prefix on the wire.
//
// Nothing in here allocates.  A T_SV2_NOISE is a fixed-size struct the
// caller owns, one per connection; the responder's long-term material lives
// in a T_SV2_NOISE_RESPONDER_KEYS that many connections can share read-only.

#define SV2_NOISE_ELLSWIFT_SIZE 64
#define SV2_NOISE_ACT1_SIZE SV2_NOISE_ELLSWIFT_SIZE
#define SV2_NOISE_CERT_SIZE 74
#define SV2_NOISE_ACT2_SIZE (SV2_NOISE_ELLSWIFT_SIZE + (SV2_NOISE_ELLSWIFT_SIZE + SV2_AEAD_MAC_SIZE) + (SV2_NOISE_CERT_SIZE + SV2_AEAD_MAC_SIZE))

#define SV2_NOISE_CERTIFICATE_VERSION 0
#define SV2_NOISE_CERT_TIME_LEEWAY 10

// Encrypted frame geometry
#define SV2_NOISE_ENC_HEADER_SIZE (SV2_FRAME_HEADER_SIZE + SV2_AEAD_MAC_SIZE)
#define SV2_NOISE_MAX_CHUNK 65535
#define SV2_NOISE_MAX_PLAINTEXT_CHUNK (SV2_NOISE_MAX_CHUNK - SV2_AEAD_MAC_SIZE)

#define SV2_NOISE_PROTOCOL_NAME "Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256"

typedef struct {
	unsigned char k[SV2_AEAD_KEY_SIZE];
	uint64_t n;
	bool has_k;
} T_SV2_CIPHER_STATE;

// Long-term responder material.  Fill with sv2_noise_responder_keys_init()
// and refresh the certificate with sv2_noise_responder_keys_refresh() before
// it expires.  Read-only during handshakes, so a copy per thread needs no
// locking.
typedef struct {
	unsigned char authority_sk[32];
	unsigned char authority_pk[32]; // x-only, what miners configure
	
	unsigned char static_sk[32];
	unsigned char static_ellswift[SV2_NOISE_ELLSWIFT_SIZE];
	unsigned char static_xonly[32];
	
	uint32_t cert_validity_seconds;
	uint32_t cert_valid_from;
	uint32_t cert_not_valid_after;
	unsigned char cert[SV2_NOISE_CERT_SIZE];
} T_SV2_NOISE_RESPONDER_KEYS;

// Certificate details the initiator learned during the handshake
typedef struct {
	uint16_t version;
	uint32_t valid_from;
	uint32_t not_valid_after;
	unsigned char responder_static_xonly[32];
	bool authenticated; // signature verified against a pinned authority key
} T_SV2_NOISE_CERT_INFO;

#define SV2_NOISE_STATE_INIT 0
#define SV2_NOISE_STATE_ACT1_SENT 1 // initiator: waiting for act 2
#define SV2_NOISE_STATE_TRANSPORT 2
#define SV2_NOISE_STATE_DEAD 3

typedef struct {
	secp256k1_context *secp; // caller owned, must outlive this struct
	bool is_initiator;
	int state;
	
	// symmetric state during the handshake
	unsigned char h[SV2_HASH_SIZE];
	unsigned char ck[SV2_HASH_SIZE];
	T_SV2_CIPHER_STATE hs;
	
	unsigned char e_sk[32];
	unsigned char e_ellswift[SV2_NOISE_ELLSWIFT_SIZE];
	
	// responder only
	const T_SV2_NOISE_RESPONDER_KEYS *keys;
	
	// initiator only
	bool has_authority_pk;
	unsigned char authority_pk[32];
	T_SV2_NOISE_CERT_INFO cert;
	
	// transport
	T_SV2_CIPHER_STATE send;
	T_SV2_CIPHER_STATE recv;
	
	// receive side reassembly: the header is decrypted as soon as its 22
	// bytes arrive, then we wait for the whole encrypted payload
	bool rx_have_header;
	T_SV2_FRAME_HEADER rx_header;
	unsigned char rx_header_bytes[SV2_FRAME_HEADER_SIZE];
} T_SV2_NOISE;

/////////////////////////////////
// Responder keys and certificate
/////////////////////////////////

// Derive everything from a 32 byte authority secret key, generating a fresh
// static key and signing a certificate valid from now.  Pass a NULL
// authority_sk to generate a new authority key as well (its secret is left
// in keys->authority_sk for the caller to persist).
int sv2_noise_responder_keys_init(T_SV2_NOISE_RESPONDER_KEYS *keys, secp256k1_context *secp, const unsigned char *authority_sk, uint32_t cert_validity_seconds, uint32_t now);

// Re-sign the certificate when it is past half of its validity.  Returns
// SV2_OK and sets *renewed accordingly.
int sv2_noise_responder_keys_refresh(T_SV2_NOISE_RESPONDER_KEYS *keys, secp256k1_context *secp, uint32_t now, bool *renewed);

// Text form of the authority public key in the format SRI tools and the
// Bitaxe UI expect: base58check of (version 0x0001 LE || x-only key) with a
// 4 byte double-SHA256 checksum.  Buffer needs at least 64 bytes.
int sv2_noise_authority_pk_to_base58(const unsigned char pk[32], char *out, size_t out_sz);
int sv2_noise_authority_pk_from_base58(const char *in, unsigned char pk[32]);

/////////////////////////////////
// Handshake
/////////////////////////////////

int sv2_noise_init_responder(T_SV2_NOISE *n, secp256k1_context *secp, const T_SV2_NOISE_RESPONDER_KEYS *keys);

// authority_pk may be NULL to accept any responder (unauthenticated, only
// acceptable on a trusted local network).
int sv2_noise_init_initiator(T_SV2_NOISE *n, secp256k1_context *secp, const unsigned char *authority_pk);

// Initiator: produce act 1 (64 bytes) to send.
int sv2_noise_initiator_act1(T_SV2_NOISE *n, unsigned char out[SV2_NOISE_ACT1_SIZE]);

// Responder: consume act 1 and produce act 2 (234 bytes) to send.  On
// success the transport keys are ready.
int sv2_noise_responder_act2(T_SV2_NOISE *n, const unsigned char in[SV2_NOISE_ACT1_SIZE], unsigned char out[SV2_NOISE_ACT2_SIZE], uint32_t now);

// Initiator: consume act 2.  On success the transport keys are ready and
// n->cert describes the responder's certificate.  SV2_ERR_CERT means the
// responder could not be authenticated with the pinned authority key.
int sv2_noise_initiator_act2(T_SV2_NOISE *n, const unsigned char in[SV2_NOISE_ACT2_SIZE], uint32_t now);

static inline bool sv2_noise_is_transport(const T_SV2_NOISE *n) {
	return n->state == SV2_NOISE_STATE_TRANSPORT;
}

// Wipe every secret.  Safe to call in any state, including on a struct
// that was never initialised.
void sv2_noise_clear(T_SV2_NOISE *n);

/////////////////////////////////
// Transport
/////////////////////////////////

// Bytes on the wire for a plaintext frame of frame_len bytes (header
// included), or 0 when frame_len is smaller than a header.
uint32_t sv2_noise_encrypted_frame_size(uint32_t frame_len);

// Bytes of ciphertext that follow an encrypted header whose msg_length is
// payload_len.
uint32_t sv2_noise_encrypted_payload_size(uint32_t payload_len);

// Encrypt a complete plaintext frame (as produced by the message encoders)
// into out.  Returns the number of bytes written or a negative error.
int sv2_noise_encrypt_frame(T_SV2_NOISE *n, const unsigned char *frame, uint32_t frame_len, unsigned char *out, uint32_t out_cap);

// Incremental decryption from a byte stream.  Feed whatever has been
// received so far; the function returns:
//
//   SV2_OK          one plaintext frame (header + payload) is in out,
//                   *out_len bytes long, and *consumed input bytes are done
//   SV2_NEED_MORE   more input is required; *consumed bytes are done with
//                   and must be dropped from the caller's buffer (the
//                   decrypted header is kept in n until the payload arrives)
//   < 0             fatal, close the connection
//
// out_cap bounds the plaintext frame; a header announcing a larger payload
// is rejected with SV2_ERR_OVERFLOW before any of it is read, which is how
// a caller enforces its own maximum message size.
int sv2_noise_read_frame(T_SV2_NOISE *n, const unsigned char *in, uint32_t in_len, unsigned char *out, uint32_t out_cap, uint32_t *out_len, uint32_t *consumed);

#endif
