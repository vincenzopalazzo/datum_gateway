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

#include "sv2_msg_common.h"
#include "sv2_msg_mining.h"

bool sv2_msg_has_channel_bit(uint8_t msg_type) {
	switch (msg_type) {
		case SV2_MSG_CHANNEL_ENDPOINT_CHANGED:
		case SV2_MSG_NEW_MINING_JOB:
		case SV2_MSG_UPDATE_CHANNEL:
		case SV2_MSG_UPDATE_CHANNEL_ERROR:
		case SV2_MSG_CLOSE_CHANNEL:
		case SV2_MSG_SET_EXTRANONCE_PREFIX:
		case SV2_MSG_SUBMIT_SHARES_STANDARD:
		case SV2_MSG_SUBMIT_SHARES_EXTENDED:
		case SV2_MSG_SUBMIT_SHARES_SUCCESS:
		case SV2_MSG_SUBMIT_SHARES_ERROR:
		case SV2_MSG_NEW_EXTENDED_MINING_JOB:
		case SV2_MSG_SET_NEW_PREV_HASH:
		case SV2_MSG_SET_TARGET:
		case SV2_MSG_SET_CUSTOM_MINING_JOB:
		case SV2_MSG_SET_CUSTOM_MINING_JOB_SUCCESS:
		case SV2_MSG_SET_CUSTOM_MINING_JOB_ERROR:
			return true;
		default:
			return false;
	}
}

/////////////////////////////////
// Channel opening
/////////////////////////////////

int sv2_msg_open_standard_mining_channel_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->request_id);
	sv2_write_str0_255(&w, m->user_identity);
	sv2_write_f32(&w, m->nominal_hash_rate);
	sv2_write_u256(&w, m->max_target);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_OPEN_STANDARD_MINING_CHANNEL, false);
}

int sv2_msg_open_standard_mining_channel_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->request_id);
	sv2_read_str0_255(&r, &m->user_identity);
	sv2_read_f32(&r, &m->nominal_hash_rate);
	sv2_read_u256(&r, m->max_target);
	return sv2_reader_finish(&r);
}

int sv2_msg_open_standard_mining_channel_success_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->request_id);
	sv2_write_u32(&w, m->channel_id);
	sv2_write_u256(&w, m->target);
	sv2_write_b0_32(&w, m->extranonce_prefix);
	sv2_write_u32(&w, m->group_channel_id);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, false);
}

int sv2_msg_open_standard_mining_channel_success_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->request_id);
	sv2_read_u32(&r, &m->channel_id);
	sv2_read_u256(&r, m->target);
	sv2_read_b0_32(&r, &m->extranonce_prefix);
	sv2_read_u32(&r, &m->group_channel_id);
	return sv2_reader_finish(&r);
}

int sv2_msg_open_mining_channel_error_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_OPEN_MINING_CHANNEL_ERROR *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->request_id);
	sv2_write_str0_255(&w, m->error_code);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_OPEN_MINING_CHANNEL_ERROR, false);
}

int sv2_msg_open_mining_channel_error_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_OPEN_MINING_CHANNEL_ERROR *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->request_id);
	sv2_read_str0_255(&r, &m->error_code);
	return sv2_reader_finish(&r);
}

int sv2_msg_open_extended_mining_channel_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->request_id);
	sv2_write_str0_255(&w, m->user_identity);
	sv2_write_f32(&w, m->nominal_hash_rate);
	sv2_write_u256(&w, m->max_target);
	sv2_write_u16(&w, m->min_extranonce_size);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL, false);
}

int sv2_msg_open_extended_mining_channel_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->request_id);
	sv2_read_str0_255(&r, &m->user_identity);
	sv2_read_f32(&r, &m->nominal_hash_rate);
	sv2_read_u256(&r, m->max_target);
	sv2_read_u16(&r, &m->min_extranonce_size);
	return sv2_reader_finish(&r);
}

int sv2_msg_open_extended_mining_channel_success_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->request_id);
	sv2_write_u32(&w, m->channel_id);
	sv2_write_u256(&w, m->target);
	sv2_write_u16(&w, m->extranonce_size);
	sv2_write_b0_32(&w, m->extranonce_prefix);
	sv2_write_u32(&w, m->group_channel_id);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS, false);
}

int sv2_msg_open_extended_mining_channel_success_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->request_id);
	sv2_read_u32(&r, &m->channel_id);
	sv2_read_u256(&r, m->target);
	sv2_read_u16(&r, &m->extranonce_size);
	sv2_read_b0_32(&r, &m->extranonce_prefix);
	sv2_read_u32(&r, &m->group_channel_id);
	return sv2_reader_finish(&r);
}

/////////////////////////////////
// Jobs
/////////////////////////////////

int sv2_msg_new_mining_job_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_NEW_MINING_JOB *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->channel_id);
	sv2_write_u32(&w, m->job_id);
	sv2_write_option_u32(&w, m->has_min_ntime, m->min_ntime);
	sv2_write_u32(&w, m->version);
	sv2_write_u256(&w, m->merkle_root);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_NEW_MINING_JOB, true);
}

int sv2_msg_new_mining_job_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_NEW_MINING_JOB *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->channel_id);
	sv2_read_u32(&r, &m->job_id);
	sv2_read_option_u32(&r, &m->has_min_ntime, &m->min_ntime);
	sv2_read_u32(&r, &m->version);
	sv2_read_u256(&r, m->merkle_root);
	return sv2_reader_finish(&r);
}

int sv2_msg_new_extended_mining_job_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_NEW_EXTENDED_MINING_JOB *m) {
	T_SV2_WRITER w;
	if (m->merkle_path.len != (uint32_t)m->merkle_path_count * 32) return SV2_ERR_INVALID;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->channel_id);
	sv2_write_u32(&w, m->job_id);
	sv2_write_option_u32(&w, m->has_min_ntime, m->min_ntime);
	sv2_write_u32(&w, m->version);
	sv2_write_bool(&w, m->version_rolling_allowed);
	sv2_write_seq0_255_u256(&w, m->merkle_path.data, m->merkle_path_count);
	sv2_write_b0_64k(&w, m->coinbase_tx_prefix);
	sv2_write_b0_64k(&w, m->coinbase_tx_suffix);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_NEW_EXTENDED_MINING_JOB, true);
}

int sv2_msg_new_extended_mining_job_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_NEW_EXTENDED_MINING_JOB *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->channel_id);
	sv2_read_u32(&r, &m->job_id);
	sv2_read_option_u32(&r, &m->has_min_ntime, &m->min_ntime);
	sv2_read_u32(&r, &m->version);
	sv2_read_bool(&r, &m->version_rolling_allowed);
	sv2_read_seq0_255_u256(&r, &m->merkle_path, &m->merkle_path_count);
	sv2_read_b0_64k(&r, &m->coinbase_tx_prefix);
	sv2_read_b0_64k(&r, &m->coinbase_tx_suffix);
	return sv2_reader_finish(&r);
}

int sv2_msg_set_new_prev_hash_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SET_NEW_PREV_HASH *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->channel_id);
	sv2_write_u32(&w, m->job_id);
	sv2_write_u256(&w, m->prev_hash);
	sv2_write_u32(&w, m->min_ntime);
	sv2_write_u32(&w, m->nbits);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_SET_NEW_PREV_HASH, true);
}

int sv2_msg_set_new_prev_hash_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SET_NEW_PREV_HASH *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->channel_id);
	sv2_read_u32(&r, &m->job_id);
	sv2_read_u256(&r, m->prev_hash);
	sv2_read_u32(&r, &m->min_ntime);
	sv2_read_u32(&r, &m->nbits);
	return sv2_reader_finish(&r);
}

int sv2_msg_set_target_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SET_TARGET *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->channel_id);
	sv2_write_u256(&w, m->maximum_target);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_SET_TARGET, true);
}

int sv2_msg_set_target_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SET_TARGET *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->channel_id);
	sv2_read_u256(&r, m->maximum_target);
	return sv2_reader_finish(&r);
}

/////////////////////////////////
// Channel maintenance
/////////////////////////////////

int sv2_msg_update_channel_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_UPDATE_CHANNEL *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->channel_id);
	sv2_write_f32(&w, m->nominal_hash_rate);
	sv2_write_u256(&w, m->maximum_target);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_UPDATE_CHANNEL, true);
}

int sv2_msg_update_channel_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_UPDATE_CHANNEL *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->channel_id);
	sv2_read_f32(&r, &m->nominal_hash_rate);
	sv2_read_u256(&r, m->maximum_target);
	return sv2_reader_finish(&r);
}

int sv2_msg_update_channel_error_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_UPDATE_CHANNEL_ERROR *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->channel_id);
	sv2_write_str0_255(&w, m->error_code);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_UPDATE_CHANNEL_ERROR, true);
}

int sv2_msg_update_channel_error_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_UPDATE_CHANNEL_ERROR *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->channel_id);
	sv2_read_str0_255(&r, &m->error_code);
	return sv2_reader_finish(&r);
}

int sv2_msg_close_channel_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_CLOSE_CHANNEL *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->channel_id);
	sv2_write_str0_255(&w, m->reason_code);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_CLOSE_CHANNEL, true);
}

int sv2_msg_close_channel_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_CLOSE_CHANNEL *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->channel_id);
	sv2_read_str0_255(&r, &m->reason_code);
	return sv2_reader_finish(&r);
}

int sv2_msg_set_extranonce_prefix_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SET_EXTRANONCE_PREFIX *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->channel_id);
	sv2_write_b0_32(&w, m->extranonce_prefix);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_SET_EXTRANONCE_PREFIX, true);
}

int sv2_msg_set_extranonce_prefix_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SET_EXTRANONCE_PREFIX *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->channel_id);
	sv2_read_b0_32(&r, &m->extranonce_prefix);
	return sv2_reader_finish(&r);
}

int sv2_msg_set_group_channel_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SET_GROUP_CHANNEL *m) {
	T_SV2_WRITER w;
	uint32_t i;
	if (m->channel_ids.len != (uint32_t)m->channel_ids_count * 4) return SV2_ERR_INVALID;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->group_channel_id);
	sv2_write_u16(&w, m->channel_ids_count);
	for (i = 0; i < m->channel_ids_count; i++) {
		sv2_write_u32(&w, sv2_seq_u32_get(m->channel_ids, i));
	}
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_SET_GROUP_CHANNEL, false);
}

int sv2_msg_set_group_channel_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SET_GROUP_CHANNEL *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->group_channel_id);
	sv2_read_seq0_64k_u32(&r, &m->channel_ids, &m->channel_ids_count);
	return sv2_reader_finish(&r);
}

/////////////////////////////////
// Shares
/////////////////////////////////

int sv2_msg_submit_shares_standard_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SUBMIT_SHARES_STANDARD *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->channel_id);
	sv2_write_u32(&w, m->sequence_number);
	sv2_write_u32(&w, m->job_id);
	sv2_write_u32(&w, m->nonce);
	sv2_write_u32(&w, m->ntime);
	sv2_write_u32(&w, m->version);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_SUBMIT_SHARES_STANDARD, true);
}

int sv2_msg_submit_shares_standard_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SUBMIT_SHARES_STANDARD *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->channel_id);
	sv2_read_u32(&r, &m->sequence_number);
	sv2_read_u32(&r, &m->job_id);
	sv2_read_u32(&r, &m->nonce);
	sv2_read_u32(&r, &m->ntime);
	sv2_read_u32(&r, &m->version);
	return sv2_reader_finish(&r);
}

int sv2_msg_submit_shares_extended_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SUBMIT_SHARES_EXTENDED *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->channel_id);
	sv2_write_u32(&w, m->sequence_number);
	sv2_write_u32(&w, m->job_id);
	sv2_write_u32(&w, m->nonce);
	sv2_write_u32(&w, m->ntime);
	sv2_write_u32(&w, m->version);
	sv2_write_b0_32(&w, m->extranonce);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_SUBMIT_SHARES_EXTENDED, true);
}

int sv2_msg_submit_shares_extended_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SUBMIT_SHARES_EXTENDED *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->channel_id);
	sv2_read_u32(&r, &m->sequence_number);
	sv2_read_u32(&r, &m->job_id);
	sv2_read_u32(&r, &m->nonce);
	sv2_read_u32(&r, &m->ntime);
	sv2_read_u32(&r, &m->version);
	sv2_read_b0_32(&r, &m->extranonce);
	return sv2_reader_finish(&r);
}

int sv2_msg_submit_shares_success_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SUBMIT_SHARES_SUCCESS *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->channel_id);
	sv2_write_u32(&w, m->last_sequence_number);
	sv2_write_u32(&w, m->new_submits_accepted_count);
	sv2_write_u64(&w, m->new_shares_sum);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_SUBMIT_SHARES_SUCCESS, true);
}

int sv2_msg_submit_shares_success_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SUBMIT_SHARES_SUCCESS *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->channel_id);
	sv2_read_u32(&r, &m->last_sequence_number);
	sv2_read_u32(&r, &m->new_submits_accepted_count);
	sv2_read_u64(&r, &m->new_shares_sum);
	return sv2_reader_finish(&r);
}

int sv2_msg_submit_shares_error_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SUBMIT_SHARES_ERROR *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->channel_id);
	sv2_write_u32(&w, m->sequence_number);
	sv2_write_str0_255(&w, m->error_code);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_SUBMIT_SHARES_ERROR, true);
}

int sv2_msg_submit_shares_error_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SUBMIT_SHARES_ERROR *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->channel_id);
	sv2_read_u32(&r, &m->sequence_number);
	sv2_read_str0_255(&r, &m->error_code);
	return sv2_reader_finish(&r);
}

/////////////////////////////////
// Frame to message
/////////////////////////////////

int sv2_msg_decode_frame(const unsigned char *frame, uint32_t len, T_SV2_MESSAGE *m) {
	T_SV2_FRAME_HEADER h;
	const unsigned char *p;
	uint32_t plen;
	int r = sv2_frame_header_parse(frame, len, &h);
	if (r != SV2_OK) return r;
	if (len - SV2_FRAME_HEADER_SIZE != h.msg_length) return SV2_ERR_INVALID;
	m->extension_type = h.extension_type;
	m->msg_type = h.msg_type;
	if (sv2_frame_extension(&h) != SV2_EXTENSION_BASE) return SV2_ERR_UNSUPPORTED;
	// A type this layer does not decode is reported as such below, except
	// with the channel_msg bit set, which no unknown type has here: that
	// is invalid, as it was before the frame decoder existed.
	if (sv2_frame_is_channel_msg(&h) != sv2_msg_has_channel_bit(h.msg_type)) return SV2_ERR_INVALID;
	p = frame + SV2_FRAME_HEADER_SIZE;
	plen = h.msg_length;
	switch (h.msg_type) {
		case SV2_MSG_SETUP_CONNECTION: return sv2_msg_setup_connection_decode(p, plen, &m->u.setup_connection);
		case SV2_MSG_SETUP_CONNECTION_SUCCESS: return sv2_msg_setup_connection_success_decode(p, plen, &m->u.setup_connection_success);
		case SV2_MSG_SETUP_CONNECTION_ERROR: return sv2_msg_setup_connection_error_decode(p, plen, &m->u.setup_connection_error);
		case SV2_MSG_CHANNEL_ENDPOINT_CHANGED: return sv2_msg_channel_endpoint_changed_decode(p, plen, &m->u.channel_endpoint_changed);
		case SV2_MSG_RECONNECT: return sv2_msg_reconnect_decode(p, plen, &m->u.reconnect);
		case SV2_MSG_OPEN_STANDARD_MINING_CHANNEL: return sv2_msg_open_standard_mining_channel_decode(p, plen, &m->u.open_standard_mining_channel);
		case SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS: return sv2_msg_open_standard_mining_channel_success_decode(p, plen, &m->u.open_standard_mining_channel_success);
		case SV2_MSG_OPEN_MINING_CHANNEL_ERROR: return sv2_msg_open_mining_channel_error_decode(p, plen, &m->u.open_mining_channel_error);
		case SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL: return sv2_msg_open_extended_mining_channel_decode(p, plen, &m->u.open_extended_mining_channel);
		case SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS: return sv2_msg_open_extended_mining_channel_success_decode(p, plen, &m->u.open_extended_mining_channel_success);
		case SV2_MSG_NEW_MINING_JOB: return sv2_msg_new_mining_job_decode(p, plen, &m->u.new_mining_job);
		case SV2_MSG_NEW_EXTENDED_MINING_JOB: return sv2_msg_new_extended_mining_job_decode(p, plen, &m->u.new_extended_mining_job);
		case SV2_MSG_SET_NEW_PREV_HASH: return sv2_msg_set_new_prev_hash_decode(p, plen, &m->u.set_new_prev_hash);
		case SV2_MSG_SET_TARGET: return sv2_msg_set_target_decode(p, plen, &m->u.set_target);
		case SV2_MSG_UPDATE_CHANNEL: return sv2_msg_update_channel_decode(p, plen, &m->u.update_channel);
		case SV2_MSG_UPDATE_CHANNEL_ERROR: return sv2_msg_update_channel_error_decode(p, plen, &m->u.update_channel_error);
		case SV2_MSG_CLOSE_CHANNEL: return sv2_msg_close_channel_decode(p, plen, &m->u.close_channel);
		case SV2_MSG_SET_EXTRANONCE_PREFIX: return sv2_msg_set_extranonce_prefix_decode(p, plen, &m->u.set_extranonce_prefix);
		case SV2_MSG_SUBMIT_SHARES_STANDARD: return sv2_msg_submit_shares_standard_decode(p, plen, &m->u.submit_shares_standard);
		case SV2_MSG_SUBMIT_SHARES_EXTENDED: return sv2_msg_submit_shares_extended_decode(p, plen, &m->u.submit_shares_extended);
		case SV2_MSG_SUBMIT_SHARES_SUCCESS: return sv2_msg_submit_shares_success_decode(p, plen, &m->u.submit_shares_success);
		case SV2_MSG_SUBMIT_SHARES_ERROR: return sv2_msg_submit_shares_error_decode(p, plen, &m->u.submit_shares_error);
		case SV2_MSG_SET_GROUP_CHANNEL: return sv2_msg_set_group_channel_decode(p, plen, &m->u.set_group_channel);
		default: return SV2_ERR_UNSUPPORTED;
	}
}
