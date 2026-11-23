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

// src/sv2_noise.h for the SRI-backed build.
//
// The functions, constants and type names are those of src/sv2_noise.h, so
// datum_sv2.c and the tools compile against either.  The structs differ:
// the handshake and transport state live in a noise_sv2 session owned by
// libsv2_sri, and T_SV2_NOISE holds a handle to it.  Only what callers
// read is kept in the open.
//
// Lifetime: sv2_noise_init_*() expects a zeroed or cleared struct and
// creates the session; sv2_noise_clear() releases it.  A struct that was
// initialised must be cleared, or the session leaks.
//
// The responder keys are plain data.  noise_sv2 makes a fresh static key
// for every responder and signs a certificate valid from the handshake
// time at every handshake, so there is no static key or certificate to
// keep and sv2_noise_responder_keys_refresh() has nothing to do.  A
// responder built from a static key and a pre-issued certificate, which
// would take the authority secret off the gateway, waits on
// stratum-mining/stratum#2437.

#define SV2_NOISE_ELLSWIFT_SIZE 64
#define SV2_NOISE_ACT1_SIZE SV2_NOISE_ELLSWIFT_SIZE
#define SV2_NOISE_CERT_SIZE 74
#define SV2_NOISE_ACT2_SIZE (SV2_NOISE_ELLSWIFT_SIZE + (SV2_NOISE_ELLSWIFT_SIZE + SV2_AEAD_MAC_SIZE) + (SV2_NOISE_CERT_SIZE + SV2_AEAD_MAC_SIZE))

#define SV2_NOISE_CERTIFICATE_VERSION 0
#define SV2_NOISE_CERT_TIME_LEEWAY 10

#define SV2_NOISE_ENC_HEADER_SIZE (SV2_FRAME_HEADER_SIZE + SV2_AEAD_MAC_SIZE)
#define SV2_NOISE_MAX_CHUNK 65535
#define SV2_NOISE_MAX_PLAINTEXT_CHUNK (SV2_NOISE_MAX_CHUNK - SV2_AEAD_MAC_SIZE)

#define SV2_NOISE_PROTOCOL_NAME "Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256"

typedef struct {
	unsigned char authority_sk[32];
	unsigned char authority_pk[32]; // x-only, what miners configure
	uint32_t cert_validity_seconds;
} T_SV2_NOISE_RESPONDER_KEYS;

// noise_sv2's initiator verifies the certificate but does not hand its
// fields out, so only `authenticated` is filled in.
typedef struct {
	uint16_t version;
	uint32_t valid_from;
	uint32_t not_valid_after;
	unsigned char responder_static_xonly[32];
	bool authenticated;
} T_SV2_NOISE_CERT_INFO;

#define SV2_NOISE_STATE_INIT 0
#define SV2_NOISE_STATE_ACT1_SENT 1
#define SV2_NOISE_STATE_TRANSPORT 2
#define SV2_NOISE_STATE_DEAD 3

struct Sv2SriNoise;

typedef struct {
	struct Sv2SriNoise *sri;
	bool is_initiator;
	int state;
	T_SV2_NOISE_CERT_INFO cert;
} T_SV2_NOISE;

int sv2_noise_responder_keys_init(T_SV2_NOISE_RESPONDER_KEYS *keys, secp256k1_context *secp, const unsigned char *authority_sk, uint32_t cert_validity_seconds, uint32_t now);
int sv2_noise_responder_keys_refresh(T_SV2_NOISE_RESPONDER_KEYS *keys, secp256k1_context *secp, uint32_t now, bool *renewed);

int sv2_noise_authority_pk_to_base58(const unsigned char pk[32], char *out, size_t out_sz);
int sv2_noise_authority_pk_from_base58(const char *in, unsigned char pk[32]);

int sv2_noise_init_responder(T_SV2_NOISE *n, secp256k1_context *secp, const T_SV2_NOISE_RESPONDER_KEYS *keys);
int sv2_noise_init_initiator(T_SV2_NOISE *n, secp256k1_context *secp, const unsigned char *authority_pk);
int sv2_noise_initiator_act1(T_SV2_NOISE *n, unsigned char out[SV2_NOISE_ACT1_SIZE]);
int sv2_noise_responder_act2(T_SV2_NOISE *n, const unsigned char in[SV2_NOISE_ACT1_SIZE], unsigned char out[SV2_NOISE_ACT2_SIZE], uint32_t now);
int sv2_noise_initiator_act2(T_SV2_NOISE *n, const unsigned char in[SV2_NOISE_ACT2_SIZE], uint32_t now);

static inline bool sv2_noise_is_transport(const T_SV2_NOISE *n) {
	return n->state == SV2_NOISE_STATE_TRANSPORT;
}

void sv2_noise_clear(T_SV2_NOISE *n);

uint32_t sv2_noise_encrypted_frame_size(uint32_t frame_len);
uint32_t sv2_noise_encrypted_payload_size(uint32_t payload_len);
int sv2_noise_encrypt_frame(T_SV2_NOISE *n, const unsigned char *frame, uint32_t frame_len, unsigned char *out, uint32_t out_cap);
int sv2_noise_read_frame(T_SV2_NOISE *n, const unsigned char *in, uint32_t in_len, unsigned char *out, uint32_t out_cap, uint32_t *out_len, uint32_t *consumed);

#endif
