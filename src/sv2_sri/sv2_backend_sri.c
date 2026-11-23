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

// sv2.cc's protocol interface on top of libsv2_sri (sri-capi/), so that
// datum_sv2.c and the tools build unchanged against the SRI crates.
//
// This file replaces src/sv2_codec.c, sv2_crypto_sodium.c, sv2_frame.c,
// sv2_msg_common.c, sv2_msg_mining.c and sv2_noise.c, and goes with
// sri-capi/shim/sv2_noise.h in place of src/sv2_noise.h.  Everything the
// protocol does (Noise, framing, binary encoding, which message a frame
// holds) happens in the SRI crates; what is here only hands sv2.cc's
// structs to sv2_sri.h's records, which are laid out the same.
//
// Provided: every sv2_noise_* and sv2_msg_* function, sv2_frame_header_*,
// the little endian and string helpers of sv2_codec.h, and
// sv2_crypto_init/random/sha256/memzero.  Not provided: the T_SV2_READER /
// T_SV2_WRITER field codec and sv2_frame_begin/finish (sv2.cc's own
// encoder internals) and the AEAD/HMAC primitives of sv2_crypto.h, which
// nothing outside src/ calls.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sv2_sri.h>

#include "sv2_msg_common.h"
#include "sv2_msg_mining.h"
#include "sv2_noise.h"

// The error codes are shared by value, so they pass straight through.
_Static_assert(SV2_SRI_OK == SV2_OK, "error codes");
_Static_assert(SV2_SRI_NEED_MORE == SV2_NEED_MORE, "error codes");
_Static_assert(SV2_SRI_ERR_TRUNCATED == SV2_ERR_TRUNCATED, "error codes");
_Static_assert(SV2_SRI_ERR_OVERFLOW == SV2_ERR_OVERFLOW, "error codes");
_Static_assert(SV2_SRI_ERR_INVALID == SV2_ERR_INVALID, "error codes");
_Static_assert(SV2_SRI_ERR_CRYPTO == SV2_ERR_CRYPTO, "error codes");
_Static_assert(SV2_SRI_ERR_STATE == SV2_ERR_STATE, "error codes");
_Static_assert(SV2_SRI_ERR_CERT == SV2_ERR_CERT, "error codes");
_Static_assert(SV2_SRI_ERR_TRAILING == SV2_ERR_TRAILING, "error codes");
_Static_assert(SV2_SRI_ERR_UNSUPPORTED == SV2_ERR_UNSUPPORTED, "error codes");
_Static_assert(SV2_SRI_ACT1_SIZE == SV2_NOISE_ACT1_SIZE, "handshake sizes");
_Static_assert(SV2_SRI_ACT2_SIZE == SV2_NOISE_ACT2_SIZE, "handshake sizes");
_Static_assert(SV2_SRI_ENCRYPTED_HEADER_SIZE == SV2_NOISE_ENC_HEADER_SIZE, "frame sizes");
// So are the message type numbers.
_Static_assert(SV2_SRI_MSG_SETUP_CONNECTION == SV2_MSG_SETUP_CONNECTION, "message types");
_Static_assert(SV2_SRI_MSG_SETUP_CONNECTION_SUCCESS == SV2_MSG_SETUP_CONNECTION_SUCCESS, "message types");
_Static_assert(SV2_SRI_MSG_SETUP_CONNECTION_ERROR == SV2_MSG_SETUP_CONNECTION_ERROR, "message types");
_Static_assert(SV2_SRI_MSG_CHANNEL_ENDPOINT_CHANGED == SV2_MSG_CHANNEL_ENDPOINT_CHANGED, "message types");
_Static_assert(SV2_SRI_MSG_RECONNECT == SV2_MSG_RECONNECT, "message types");
_Static_assert(SV2_SRI_MSG_OPEN_STANDARD_MINING_CHANNEL == SV2_MSG_OPEN_STANDARD_MINING_CHANNEL, "message types");
_Static_assert(SV2_SRI_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS == SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, "message types");
_Static_assert(SV2_SRI_MSG_OPEN_MINING_CHANNEL_ERROR == SV2_MSG_OPEN_MINING_CHANNEL_ERROR, "message types");
_Static_assert(SV2_SRI_MSG_OPEN_EXTENDED_MINING_CHANNEL == SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL, "message types");
_Static_assert(SV2_SRI_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS == SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS, "message types");
_Static_assert(SV2_SRI_MSG_NEW_MINING_JOB == SV2_MSG_NEW_MINING_JOB, "message types");
_Static_assert(SV2_SRI_MSG_UPDATE_CHANNEL == SV2_MSG_UPDATE_CHANNEL, "message types");
_Static_assert(SV2_SRI_MSG_UPDATE_CHANNEL_ERROR == SV2_MSG_UPDATE_CHANNEL_ERROR, "message types");
_Static_assert(SV2_SRI_MSG_CLOSE_CHANNEL == SV2_MSG_CLOSE_CHANNEL, "message types");
_Static_assert(SV2_SRI_MSG_SET_EXTRANONCE_PREFIX == SV2_MSG_SET_EXTRANONCE_PREFIX, "message types");
_Static_assert(SV2_SRI_MSG_SUBMIT_SHARES_STANDARD == SV2_MSG_SUBMIT_SHARES_STANDARD, "message types");
_Static_assert(SV2_SRI_MSG_SUBMIT_SHARES_EXTENDED == SV2_MSG_SUBMIT_SHARES_EXTENDED, "message types");
_Static_assert(SV2_SRI_MSG_SUBMIT_SHARES_SUCCESS == SV2_MSG_SUBMIT_SHARES_SUCCESS, "message types");
_Static_assert(SV2_SRI_MSG_SUBMIT_SHARES_ERROR == SV2_MSG_SUBMIT_SHARES_ERROR, "message types");
_Static_assert(SV2_SRI_MSG_NEW_EXTENDED_MINING_JOB == SV2_MSG_NEW_EXTENDED_MINING_JOB, "message types");
_Static_assert(SV2_SRI_MSG_SET_NEW_PREV_HASH == SV2_MSG_SET_NEW_PREV_HASH, "message types");
_Static_assert(SV2_SRI_MSG_SET_TARGET == SV2_MSG_SET_TARGET, "message types");
_Static_assert(SV2_SRI_MSG_SET_GROUP_CHANNEL == SV2_MSG_SET_GROUP_CHANNEL, "message types");

// binary_sv2 decodes from a mutable slice; sv2.cc's decoders take a const
// payload.  The bytes are left as they were, but not untouched: on a
// SetupConnection with an unknown protocol the C API masks the protocol
// byte for a second attempt and puts it back, so the payload must be
// writable memory (the gateway's receive buffer is).
#define PAYLOAD(p) ((uint8_t *)(uintptr_t)(p))

/////////////////////////////////
// Crypto and codec helpers
/////////////////////////////////

int sv2_crypto_init(void) {
	return SV2_OK;
}

void sv2_crypto_random(unsigned char *buf, size_t len) {
	sv2_sri_random(buf, len);
}

void sv2_crypto_sha256(const unsigned char *in, size_t len, unsigned char out[SV2_HASH_SIZE]) {
	sv2_sri_sha256(in, len, out);
}

void sv2_crypto_memzero(void *p, size_t len) {
	volatile unsigned char *v = p;
	while (len--) *v++ = 0;
}

uint16_t sv2_get_u16(const unsigned char *p) {
	return (uint16_t)(p[0] | (p[1] << 8));
}

uint32_t sv2_get_u24(const unsigned char *p) {
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

uint32_t sv2_get_u32(const unsigned char *p) {
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint64_t sv2_get_u64(const unsigned char *p) {
	return (uint64_t)sv2_get_u32(p) | ((uint64_t)sv2_get_u32(p + 4) << 32);
}

void sv2_put_u16(unsigned char *p, uint16_t v) {
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
}

void sv2_put_u24(unsigned char *p, uint32_t v) {
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
	p[2] = (unsigned char)(v >> 16);
}

void sv2_put_u32(unsigned char *p, uint32_t v) {
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
	p[2] = (unsigned char)(v >> 16);
	p[3] = (unsigned char)(v >> 24);
}

void sv2_put_u64(unsigned char *p, uint64_t v) {
	sv2_put_u32(p, (uint32_t)v);
	sv2_put_u32(p + 4, (uint32_t)(v >> 32));
}

bool sv2_str_copy(char *dst, size_t dst_sz, T_SV2_BYTES src) {
	if (!dst_sz) return false;
	if (src.len >= dst_sz || (src.len && memchr(src.data, 0, src.len))) {
		dst[0] = 0;
		return false;
	}
	if (src.len) memcpy(dst, src.data, src.len);
	dst[src.len] = 0;
	return true;
}

T_SV2_BYTES sv2_str(const char *s) {
	size_t n = s ? strlen(s) : 0;
	if (n > 0xFFFFFFFFu) n = 0xFFFFFFFFu;
	return sv2_bytes(s, (uint32_t)n);
}

/////////////////////////////////
// Framing
/////////////////////////////////

int sv2_frame_header_parse(const unsigned char *buf, uint32_t len, T_SV2_FRAME_HEADER *h) {
	Sv2SriFrameHeader s;
	int r = sv2_sri_frame_header_decode(buf, len, &s);
	if (r != SV2_OK) return r;
	h->extension_type = s.extension_type;
	h->msg_type = s.msg_type;
	h->msg_length = s.msg_length;
	return SV2_OK;
}

int sv2_frame_header_write(unsigned char *buf, uint32_t cap, const T_SV2_FRAME_HEADER *h) {
	Sv2SriFrameHeader s;
	int r;
	s.extension_type = h->extension_type;
	s.msg_type = h->msg_type;
	s.msg_length = h->msg_length;
	r = sv2_sri_frame_header_encode(&s, buf, cap);
	return r < 0 ? r : SV2_OK;
}

bool sv2_msg_has_channel_bit(uint8_t msg_type) {
	return sv2_sri_msg_has_channel_bit(msg_type);
}

/////////////////////////////////
// Noise
/////////////////////////////////

int sv2_noise_responder_keys_init(T_SV2_NOISE_RESPONDER_KEYS *keys, secp256k1_context *secp, const unsigned char *authority_sk, uint32_t cert_validity_seconds, uint32_t now) {
	(void)secp;
	(void)now;
	memset(keys, 0, sizeof(*keys));
	if (!cert_validity_seconds) return SV2_ERR_INVALID;
	keys->cert_validity_seconds = cert_validity_seconds;
	if (!authority_sk) return sv2_sri_authority_keypair_generate(keys->authority_sk, keys->authority_pk);
	memcpy(keys->authority_sk, authority_sk, 32);
	return sv2_sri_authority_pubkey(keys->authority_sk, keys->authority_pk);
}

int sv2_noise_responder_keys_refresh(T_SV2_NOISE_RESPONDER_KEYS *keys, secp256k1_context *secp, uint32_t now, bool *renewed) {
	(void)keys;
	(void)secp;
	(void)now;
	*renewed = false;
	return SV2_OK;
}

int sv2_noise_authority_pk_to_base58(const unsigned char pk[32], char *out, size_t out_sz) {
	return sv2_sri_authority_pubkey_to_base58(pk, out, out_sz);
}

int sv2_noise_authority_pk_from_base58(const char *in, unsigned char pk[32]) {
	return sv2_sri_authority_pubkey_from_base58(in, pk);
}

void sv2_noise_clear(T_SV2_NOISE *n) {
	sv2_sri_noise_free(n->sri);
	memset(n, 0, sizeof(*n));
	n->state = SV2_NOISE_STATE_DEAD;
}

int sv2_noise_init_responder(T_SV2_NOISE *n, secp256k1_context *secp, const T_SV2_NOISE_RESPONDER_KEYS *keys) {
	(void)secp;
	memset(n, 0, sizeof(*n));
	n->sri = sv2_sri_noise_responder_new(keys->authority_pk, keys->authority_sk, keys->cert_validity_seconds);
	n->state = n->sri ? SV2_NOISE_STATE_INIT : SV2_NOISE_STATE_DEAD;
	return n->sri ? SV2_OK : SV2_ERR_INVALID;
}

int sv2_noise_init_initiator(T_SV2_NOISE *n, secp256k1_context *secp, const unsigned char *authority_pk) {
	(void)secp;
	memset(n, 0, sizeof(*n));
	n->is_initiator = true;
	n->sri = sv2_sri_noise_initiator_new(authority_pk);
	n->state = n->sri ? SV2_NOISE_STATE_INIT : SV2_NOISE_STATE_DEAD;
	return n->sri ? SV2_OK : SV2_ERR_INVALID;
}

int sv2_noise_initiator_act1(T_SV2_NOISE *n, unsigned char out[SV2_NOISE_ACT1_SIZE]) {
	int r;
	if (!n->is_initiator || n->state != SV2_NOISE_STATE_INIT) return SV2_ERR_STATE;
	r = sv2_sri_noise_initiator_step0(n->sri, out);
	if (r != SV2_OK) {
		sv2_noise_clear(n);
		return r;
	}
	n->state = SV2_NOISE_STATE_ACT1_SENT;
	return SV2_OK;
}

int sv2_noise_responder_act2(T_SV2_NOISE *n, const unsigned char in[SV2_NOISE_ACT1_SIZE], unsigned char out[SV2_NOISE_ACT2_SIZE], uint32_t now) {
	int r;
	if (n->is_initiator || n->state != SV2_NOISE_STATE_INIT) return SV2_ERR_STATE;
	r = sv2_sri_noise_responder_step1(n->sri, in, now, out);
	if (r != SV2_OK) {
		sv2_noise_clear(n);
		return r;
	}
	n->state = SV2_NOISE_STATE_TRANSPORT;
	return SV2_OK;
}

int sv2_noise_initiator_act2(T_SV2_NOISE *n, const unsigned char in[SV2_NOISE_ACT2_SIZE], uint32_t now) {
	int r;
	if (!n->is_initiator || n->state != SV2_NOISE_STATE_ACT1_SENT) return SV2_ERR_STATE;
	r = sv2_sri_noise_initiator_step2(n->sri, in, now);
	if (r != SV2_OK) {
		sv2_noise_clear(n);
		return r;
	}
	n->cert.authenticated = sv2_sri_noise_is_authenticated(n->sri);
	n->state = SV2_NOISE_STATE_TRANSPORT;
	return SV2_OK;
}

uint32_t sv2_noise_encrypted_payload_size(uint32_t payload_len) {
	return sv2_sri_noise_encrypted_payload_size(payload_len);
}

uint32_t sv2_noise_encrypted_frame_size(uint32_t frame_len) {
	return sv2_sri_noise_encrypted_frame_size(frame_len);
}

int sv2_noise_encrypt_frame(T_SV2_NOISE *n, const unsigned char *frame, uint32_t frame_len, unsigned char *out, uint32_t out_cap) {
	int r;
	if (n->state != SV2_NOISE_STATE_TRANSPORT) return SV2_ERR_STATE;
	r = sv2_sri_noise_encrypt_frame(n->sri, frame, frame_len, out, out_cap);
	if (r < 0 && !sv2_sri_noise_is_transport(n->sri)) n->state = SV2_NOISE_STATE_DEAD;
	return r;
}

int sv2_noise_read_frame(T_SV2_NOISE *n, const unsigned char *in, uint32_t in_len, unsigned char *out, uint32_t out_cap, uint32_t *out_len, uint32_t *consumed) {
	int r;
	*out_len = 0;
	*consumed = 0;
	if (n->state != SV2_NOISE_STATE_TRANSPORT) return SV2_ERR_STATE;
	r = sv2_sri_noise_read_frame(n->sri, in, in_len, out, out_cap, out_len, consumed);
	if (r < 0 && !sv2_sri_noise_is_transport(n->sri)) n->state = SV2_NOISE_STATE_DEAD;
	return r;
}

/////////////////////////////////
// Messages
/////////////////////////////////

// The records of sv2_sri.h are sv2.cc's message structs declared field for
// field in the same order, with Sv2SriBytes for T_SV2_BYTES, so a record is
// copied whole rather than field by field.  The sizes are checked here;
// tests/sri_backend_check.c round-trips every message through both layers,
// which is where a field out of place would show.

#define SAME_LAYOUT(C, S) _Static_assert(sizeof(C) == sizeof(S) && _Alignof(C) == _Alignof(S), #C " and " #S " are laid out differently")
SAME_LAYOUT(T_SV2_BYTES, Sv2SriBytes);
_Static_assert(offsetof(T_SV2_BYTES, data) == offsetof(Sv2SriBytes, data), "byte views differ");
_Static_assert(offsetof(T_SV2_BYTES, len) == offsetof(Sv2SriBytes, len), "byte views differ");
SAME_LAYOUT(T_SV2_MSG_SETUP_CONNECTION, Sv2SriSetupConnection);
SAME_LAYOUT(T_SV2_MSG_SETUP_CONNECTION_SUCCESS, Sv2SriSetupConnectionSuccess);
SAME_LAYOUT(T_SV2_MSG_SETUP_CONNECTION_ERROR, Sv2SriSetupConnectionError);
SAME_LAYOUT(T_SV2_MSG_CHANNEL_ENDPOINT_CHANGED, Sv2SriChannelEndpointChanged);
SAME_LAYOUT(T_SV2_MSG_RECONNECT, Sv2SriReconnect);
SAME_LAYOUT(T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL, Sv2SriOpenStandardMiningChannel);
SAME_LAYOUT(T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, Sv2SriOpenStandardMiningChannelSuccess);
SAME_LAYOUT(T_SV2_MSG_OPEN_MINING_CHANNEL_ERROR, Sv2SriOpenMiningChannelError);
SAME_LAYOUT(T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL, Sv2SriOpenExtendedMiningChannel);
SAME_LAYOUT(T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS, Sv2SriOpenExtendedMiningChannelSuccess);
SAME_LAYOUT(T_SV2_MSG_UPDATE_CHANNEL, Sv2SriUpdateChannel);
SAME_LAYOUT(T_SV2_MSG_UPDATE_CHANNEL_ERROR, Sv2SriUpdateChannelError);
SAME_LAYOUT(T_SV2_MSG_CLOSE_CHANNEL, Sv2SriCloseChannel);
SAME_LAYOUT(T_SV2_MSG_SET_EXTRANONCE_PREFIX, Sv2SriSetExtranoncePrefix);
SAME_LAYOUT(T_SV2_MSG_SET_TARGET, Sv2SriSetTarget);
SAME_LAYOUT(T_SV2_MSG_SET_GROUP_CHANNEL, Sv2SriSetGroupChannel);
SAME_LAYOUT(T_SV2_MSG_NEW_MINING_JOB, Sv2SriNewMiningJob);
SAME_LAYOUT(T_SV2_MSG_NEW_EXTENDED_MINING_JOB, Sv2SriNewExtendedMiningJob);
SAME_LAYOUT(T_SV2_MSG_SET_NEW_PREV_HASH, Sv2SriSetNewPrevHash);
SAME_LAYOUT(T_SV2_MSG_SUBMIT_SHARES_STANDARD, Sv2SriSubmitSharesStandard);
SAME_LAYOUT(T_SV2_MSG_SUBMIT_SHARES_EXTENDED, Sv2SriSubmitSharesExtended);
SAME_LAYOUT(T_SV2_MSG_SUBMIT_SHARES_SUCCESS, Sv2SriSubmitSharesSuccess);
SAME_LAYOUT(T_SV2_MSG_SUBMIT_SHARES_ERROR, Sv2SriSubmitSharesError);
_Static_assert(sizeof(((T_SV2_MESSAGE *)0)->u) == sizeof(Sv2SriMessageUnion), "message unions differ");

// One message of the given type, decoded by SRI, which also says what the
// frame actually held.
static int decode_one(uint8_t msg_type, const unsigned char *payload, uint32_t len, Sv2SriMessage *s) {
	uint16_t ext = sv2_msg_has_channel_bit(msg_type) ? SV2_CHANNEL_MSG_BIT : 0;
	int r = sv2_sri_message_decode(ext, msg_type, PAYLOAD(payload), len, s);
	if (r != SV2_OK) return r;
	return s->msg_type == msg_type ? SV2_OK : SV2_ERR_INVALID;
}

// sv2.cc's per-message functions: the record goes to the crates to frame,
// or SRI is asked for one message and the record copied out.
#define SRI_MESSAGE(fn, T, member, MSG)                                               \
	int sv2_msg_##fn##_encode(unsigned char *buf, uint32_t cap, const T *m) {         \
		Sv2SriMessage s;                                                              \
		s.msg_type = MSG;                                                             \
		memcpy(&s.u.member, m, sizeof(*m));                                           \
		return sv2_sri_message_encode(&s, buf, cap);                                  \
	}                                                                                 \
	int sv2_msg_##fn##_decode(const unsigned char *payload, uint32_t len, T *m) {     \
		Sv2SriMessage s;                                                              \
		int r = decode_one(MSG, payload, len, &s);                                    \
		if (r != SV2_OK) return r;                                                    \
		memcpy(m, &s.u.member, sizeof(*m));                                           \
		return SV2_OK;                                                                \
	}

SRI_MESSAGE(setup_connection, T_SV2_MSG_SETUP_CONNECTION, setup_connection, SV2_MSG_SETUP_CONNECTION)
SRI_MESSAGE(setup_connection_success, T_SV2_MSG_SETUP_CONNECTION_SUCCESS, setup_connection_success, SV2_MSG_SETUP_CONNECTION_SUCCESS)
SRI_MESSAGE(setup_connection_error, T_SV2_MSG_SETUP_CONNECTION_ERROR, setup_connection_error, SV2_MSG_SETUP_CONNECTION_ERROR)
SRI_MESSAGE(channel_endpoint_changed, T_SV2_MSG_CHANNEL_ENDPOINT_CHANGED, channel_endpoint_changed, SV2_MSG_CHANNEL_ENDPOINT_CHANGED)
SRI_MESSAGE(reconnect, T_SV2_MSG_RECONNECT, reconnect, SV2_MSG_RECONNECT)
SRI_MESSAGE(open_standard_mining_channel, T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL, open_standard_mining_channel, SV2_MSG_OPEN_STANDARD_MINING_CHANNEL)
SRI_MESSAGE(open_standard_mining_channel_success, T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, open_standard_mining_channel_success, SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS)
SRI_MESSAGE(open_mining_channel_error, T_SV2_MSG_OPEN_MINING_CHANNEL_ERROR, open_mining_channel_error, SV2_MSG_OPEN_MINING_CHANNEL_ERROR)
SRI_MESSAGE(open_extended_mining_channel, T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL, open_extended_mining_channel, SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL)
SRI_MESSAGE(open_extended_mining_channel_success, T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS, open_extended_mining_channel_success, SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS)
SRI_MESSAGE(update_channel, T_SV2_MSG_UPDATE_CHANNEL, update_channel, SV2_MSG_UPDATE_CHANNEL)
SRI_MESSAGE(update_channel_error, T_SV2_MSG_UPDATE_CHANNEL_ERROR, update_channel_error, SV2_MSG_UPDATE_CHANNEL_ERROR)
SRI_MESSAGE(close_channel, T_SV2_MSG_CLOSE_CHANNEL, close_channel, SV2_MSG_CLOSE_CHANNEL)
SRI_MESSAGE(set_extranonce_prefix, T_SV2_MSG_SET_EXTRANONCE_PREFIX, set_extranonce_prefix, SV2_MSG_SET_EXTRANONCE_PREFIX)
SRI_MESSAGE(set_target, T_SV2_MSG_SET_TARGET, set_target, SV2_MSG_SET_TARGET)
SRI_MESSAGE(set_group_channel, T_SV2_MSG_SET_GROUP_CHANNEL, set_group_channel, SV2_MSG_SET_GROUP_CHANNEL)
SRI_MESSAGE(new_mining_job, T_SV2_MSG_NEW_MINING_JOB, new_mining_job, SV2_MSG_NEW_MINING_JOB)
SRI_MESSAGE(new_extended_mining_job, T_SV2_MSG_NEW_EXTENDED_MINING_JOB, new_extended_mining_job, SV2_MSG_NEW_EXTENDED_MINING_JOB)
SRI_MESSAGE(set_new_prev_hash, T_SV2_MSG_SET_NEW_PREV_HASH, set_new_prev_hash, SV2_MSG_SET_NEW_PREV_HASH)
SRI_MESSAGE(submit_shares_standard, T_SV2_MSG_SUBMIT_SHARES_STANDARD, submit_shares_standard, SV2_MSG_SUBMIT_SHARES_STANDARD)
SRI_MESSAGE(submit_shares_extended, T_SV2_MSG_SUBMIT_SHARES_EXTENDED, submit_shares_extended, SV2_MSG_SUBMIT_SHARES_EXTENDED)
SRI_MESSAGE(submit_shares_success, T_SV2_MSG_SUBMIT_SHARES_SUCCESS, submit_shares_success, SV2_MSG_SUBMIT_SHARES_SUCCESS)
SRI_MESSAGE(submit_shares_error, T_SV2_MSG_SUBMIT_SHARES_ERROR, submit_shares_error, SV2_MSG_SUBMIT_SHARES_ERROR)

// A whole frame: parsers_sv2 says which message it holds, or that it is
// one this layer has no record for.
int sv2_msg_decode_frame(const unsigned char *frame, uint32_t len, T_SV2_MESSAGE *m) {
	T_SV2_FRAME_HEADER h;
	Sv2SriMessage s;
	int r = sv2_frame_header_parse(frame, len, &h);
	if (r != SV2_OK) return r;
	if (len - SV2_FRAME_HEADER_SIZE != h.msg_length) return SV2_ERR_INVALID;
	m->extension_type = h.extension_type;
	m->msg_type = h.msg_type;
	r = sv2_sri_message_decode(h.extension_type, h.msg_type, PAYLOAD(frame + SV2_FRAME_HEADER_SIZE), h.msg_length, &s);
	if (r != SV2_OK) return r;
	memcpy(&m->u, &s.u, sizeof(m->u));
	return SV2_OK;
}
