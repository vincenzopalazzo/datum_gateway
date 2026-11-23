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

#ifndef _SV2_MSG_MINING_H_
#define _SV2_MSG_MINING_H_

#include "sv2_frame.h"
#include "sv2_msg_common.h"

// Mining protocol messages, spec section 5.  Only the messages a pool-side
// role and a mining device exchange over standard and extended channels;
// custom jobs (SetCustomMiningJob) belong to work selection and are not
// implemented.

#define SV2_MSG_OPEN_STANDARD_MINING_CHANNEL 0x10
#define SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS 0x11
#define SV2_MSG_OPEN_MINING_CHANNEL_ERROR 0x12
#define SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL 0x13
#define SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS 0x14
#define SV2_MSG_NEW_MINING_JOB 0x15
#define SV2_MSG_UPDATE_CHANNEL 0x16
#define SV2_MSG_UPDATE_CHANNEL_ERROR 0x17
#define SV2_MSG_CLOSE_CHANNEL 0x18
#define SV2_MSG_SET_EXTRANONCE_PREFIX 0x19
#define SV2_MSG_SUBMIT_SHARES_STANDARD 0x1a
#define SV2_MSG_SUBMIT_SHARES_EXTENDED 0x1b
#define SV2_MSG_SUBMIT_SHARES_SUCCESS 0x1c
#define SV2_MSG_SUBMIT_SHARES_ERROR 0x1d
#define SV2_MSG_NEW_EXTENDED_MINING_JOB 0x1f
#define SV2_MSG_SET_NEW_PREV_HASH 0x20
#define SV2_MSG_SET_TARGET 0x21
#define SV2_MSG_SET_CUSTOM_MINING_JOB 0x22
#define SV2_MSG_SET_CUSTOM_MINING_JOB_SUCCESS 0x23
#define SV2_MSG_SET_CUSTOM_MINING_JOB_ERROR 0x24
#define SV2_MSG_SET_GROUP_CHANNEL 0x25

// Error codes defined by the spec for the messages below
#define SV2_ERROR_UNKNOWN_USER "unknown-user"
#define SV2_ERROR_MAX_TARGET_OUT_OF_RANGE "max-target-out-of-range"
#define SV2_ERROR_INVALID_CHANNEL_ID "invalid-channel-id"
#define SV2_ERROR_STALE_SHARE "stale-share"
#define SV2_ERROR_DIFFICULTY_TOO_LOW "difficulty-too-low"
#define SV2_ERROR_INVALID_JOB_ID "invalid-job-id"

// Longest extranonce (prefix plus rollable part) an extended channel can carry
#define SV2_EXTRANONCE_MAX 32

typedef struct {
	uint32_t request_id;
	T_SV2_BYTES user_identity;
	float nominal_hash_rate;
	unsigned char max_target[32];
} T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL;

typedef struct {
	uint32_t request_id;
	uint32_t channel_id;
	unsigned char target[32];
	T_SV2_BYTES extranonce_prefix;
	uint32_t group_channel_id;
} T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS;

typedef struct {
	uint32_t request_id;
	T_SV2_BYTES error_code;
} T_SV2_MSG_OPEN_MINING_CHANNEL_ERROR;

typedef struct {
	uint32_t request_id;
	T_SV2_BYTES user_identity;
	float nominal_hash_rate;
	unsigned char max_target[32];
	uint16_t min_extranonce_size;
} T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL;

typedef struct {
	uint32_t request_id;
	uint32_t channel_id;
	unsigned char target[32];
	uint16_t extranonce_size;
	T_SV2_BYTES extranonce_prefix;
	uint32_t group_channel_id;
} T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS;

typedef struct {
	uint32_t channel_id;
	uint32_t job_id;
	bool has_min_ntime; // absent = future job, activated by SetNewPrevHash
	uint32_t min_ntime;
	uint32_t version;
	unsigned char merkle_root[32];
} T_SV2_MSG_NEW_MINING_JOB;

typedef struct {
	uint32_t channel_id;
	uint32_t job_id;
	bool has_min_ntime;
	uint32_t min_ntime;
	uint32_t version;
	bool version_rolling_allowed;
	uint8_t merkle_path_count;
	T_SV2_BYTES merkle_path; // merkle_path_count * 32 bytes
	T_SV2_BYTES coinbase_tx_prefix;
	T_SV2_BYTES coinbase_tx_suffix;
} T_SV2_MSG_NEW_EXTENDED_MINING_JOB;

typedef struct {
	uint32_t channel_id;
	uint32_t job_id;
	unsigned char prev_hash[32];
	uint32_t min_ntime;
	uint32_t nbits;
} T_SV2_MSG_SET_NEW_PREV_HASH;

typedef struct {
	uint32_t channel_id;
	unsigned char maximum_target[32];
} T_SV2_MSG_SET_TARGET;

typedef struct {
	uint32_t channel_id;
	float nominal_hash_rate;
	unsigned char maximum_target[32];
} T_SV2_MSG_UPDATE_CHANNEL;

typedef struct {
	uint32_t channel_id;
	T_SV2_BYTES error_code;
} T_SV2_MSG_UPDATE_CHANNEL_ERROR;

typedef struct {
	uint32_t channel_id;
	T_SV2_BYTES reason_code;
} T_SV2_MSG_CLOSE_CHANNEL;

typedef struct {
	uint32_t channel_id;
	T_SV2_BYTES extranonce_prefix;
} T_SV2_MSG_SET_EXTRANONCE_PREFIX;

typedef struct {
	uint32_t channel_id;
	uint32_t sequence_number;
	uint32_t job_id;
	uint32_t nonce;
	uint32_t ntime;
	uint32_t version;
} T_SV2_MSG_SUBMIT_SHARES_STANDARD;

typedef struct {
	uint32_t channel_id;
	uint32_t sequence_number;
	uint32_t job_id;
	uint32_t nonce;
	uint32_t ntime;
	uint32_t version;
	T_SV2_BYTES extranonce;
} T_SV2_MSG_SUBMIT_SHARES_EXTENDED;

typedef struct {
	uint32_t channel_id;
	uint32_t last_sequence_number;
	uint32_t new_submits_accepted_count;
	uint64_t new_shares_sum;
} T_SV2_MSG_SUBMIT_SHARES_SUCCESS;

typedef struct {
	uint32_t channel_id;
	uint32_t sequence_number;
	T_SV2_BYTES error_code;
} T_SV2_MSG_SUBMIT_SHARES_ERROR;

typedef struct {
	uint32_t group_channel_id;
	uint16_t channel_ids_count;
	T_SV2_BYTES channel_ids; // channel_ids_count * 4 bytes, little endian each
} T_SV2_MSG_SET_GROUP_CHANNEL;

// Whether a base-protocol message type is addressed to a channel, i.e. must
// carry the channel_msg bit in its frame header.  Unknown types return false.
bool sv2_msg_has_channel_bit(uint8_t msg_type);

int sv2_msg_open_standard_mining_channel_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL *m);
int sv2_msg_open_standard_mining_channel_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL *m);

int sv2_msg_open_standard_mining_channel_success_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS *m);
int sv2_msg_open_standard_mining_channel_success_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS *m);

int sv2_msg_open_mining_channel_error_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_OPEN_MINING_CHANNEL_ERROR *m);
int sv2_msg_open_mining_channel_error_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_OPEN_MINING_CHANNEL_ERROR *m);

int sv2_msg_open_extended_mining_channel_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL *m);
int sv2_msg_open_extended_mining_channel_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL *m);

int sv2_msg_open_extended_mining_channel_success_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS *m);
int sv2_msg_open_extended_mining_channel_success_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS *m);

int sv2_msg_new_mining_job_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_NEW_MINING_JOB *m);
int sv2_msg_new_mining_job_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_NEW_MINING_JOB *m);

int sv2_msg_new_extended_mining_job_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_NEW_EXTENDED_MINING_JOB *m);
int sv2_msg_new_extended_mining_job_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_NEW_EXTENDED_MINING_JOB *m);

int sv2_msg_set_new_prev_hash_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SET_NEW_PREV_HASH *m);
int sv2_msg_set_new_prev_hash_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SET_NEW_PREV_HASH *m);

int sv2_msg_set_target_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SET_TARGET *m);
int sv2_msg_set_target_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SET_TARGET *m);

int sv2_msg_update_channel_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_UPDATE_CHANNEL *m);
int sv2_msg_update_channel_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_UPDATE_CHANNEL *m);

int sv2_msg_update_channel_error_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_UPDATE_CHANNEL_ERROR *m);
int sv2_msg_update_channel_error_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_UPDATE_CHANNEL_ERROR *m);

int sv2_msg_close_channel_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_CLOSE_CHANNEL *m);
int sv2_msg_close_channel_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_CLOSE_CHANNEL *m);

int sv2_msg_set_extranonce_prefix_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SET_EXTRANONCE_PREFIX *m);
int sv2_msg_set_extranonce_prefix_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SET_EXTRANONCE_PREFIX *m);

int sv2_msg_submit_shares_standard_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SUBMIT_SHARES_STANDARD *m);
int sv2_msg_submit_shares_standard_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SUBMIT_SHARES_STANDARD *m);

int sv2_msg_submit_shares_extended_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SUBMIT_SHARES_EXTENDED *m);
int sv2_msg_submit_shares_extended_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SUBMIT_SHARES_EXTENDED *m);

int sv2_msg_submit_shares_success_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SUBMIT_SHARES_SUCCESS *m);
int sv2_msg_submit_shares_success_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SUBMIT_SHARES_SUCCESS *m);

int sv2_msg_submit_shares_error_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SUBMIT_SHARES_ERROR *m);
int sv2_msg_submit_shares_error_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SUBMIT_SHARES_ERROR *m);

int sv2_msg_set_group_channel_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SET_GROUP_CHANNEL *m);
int sv2_msg_set_group_channel_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SET_GROUP_CHANNEL *m);

// One decoded frame: the header fields and, for the common and mining
// messages above, the message.  Which member of `u` is live follows from
// `msg_type`.
typedef struct {
	uint16_t extension_type; // as in the header, channel_msg bit included
	uint8_t msg_type;
	union {
		T_SV2_MSG_SETUP_CONNECTION setup_connection;
		T_SV2_MSG_SETUP_CONNECTION_SUCCESS setup_connection_success;
		T_SV2_MSG_SETUP_CONNECTION_ERROR setup_connection_error;
		T_SV2_MSG_CHANNEL_ENDPOINT_CHANGED channel_endpoint_changed;
		T_SV2_MSG_RECONNECT reconnect;
		T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL open_standard_mining_channel;
		T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS open_standard_mining_channel_success;
		T_SV2_MSG_OPEN_MINING_CHANNEL_ERROR open_mining_channel_error;
		T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL open_extended_mining_channel;
		T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS open_extended_mining_channel_success;
		T_SV2_MSG_NEW_MINING_JOB new_mining_job;
		T_SV2_MSG_NEW_EXTENDED_MINING_JOB new_extended_mining_job;
		T_SV2_MSG_SET_NEW_PREV_HASH set_new_prev_hash;
		T_SV2_MSG_SET_TARGET set_target;
		T_SV2_MSG_UPDATE_CHANNEL update_channel;
		T_SV2_MSG_UPDATE_CHANNEL_ERROR update_channel_error;
		T_SV2_MSG_CLOSE_CHANNEL close_channel;
		T_SV2_MSG_SET_EXTRANONCE_PREFIX set_extranonce_prefix;
		T_SV2_MSG_SUBMIT_SHARES_STANDARD submit_shares_standard;
		T_SV2_MSG_SUBMIT_SHARES_EXTENDED submit_shares_extended;
		T_SV2_MSG_SUBMIT_SHARES_SUCCESS submit_shares_success;
		T_SV2_MSG_SUBMIT_SHARES_ERROR submit_shares_error;
		T_SV2_MSG_SET_GROUP_CHANNEL set_group_channel;
	} u;
} T_SV2_MESSAGE;

// Decode a whole plaintext frame (header and payload) into m.  Byte fields
// of m point into frame.  SV2_ERR_UNSUPPORTED is a well-formed frame of an
// extension, or of a message type, this layer has no decoder for; the
// header fields of m are set so the caller can log it, and the caller
// decides whether to ignore it (spec section 3.4.1 says to, for extensions
// it has not negotiated).  A channel_msg bit that does not fit the message
// is SV2_ERR_INVALID.
int sv2_msg_decode_frame(const unsigned char *frame, uint32_t len, T_SV2_MESSAGE *m);

#endif
