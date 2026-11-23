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

int sv2_msg_setup_connection_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SETUP_CONNECTION *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u8(&w, m->protocol);
	sv2_write_u16(&w, m->min_version);
	sv2_write_u16(&w, m->max_version);
	sv2_write_u32(&w, m->flags);
	sv2_write_str0_255(&w, m->endpoint_host);
	sv2_write_u16(&w, m->endpoint_port);
	sv2_write_str0_255(&w, m->vendor);
	sv2_write_str0_255(&w, m->hardware_version);
	sv2_write_str0_255(&w, m->firmware);
	sv2_write_str0_255(&w, m->device_id);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_SETUP_CONNECTION, false);
}

int sv2_msg_setup_connection_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SETUP_CONNECTION *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u8(&r, &m->protocol);
	sv2_read_u16(&r, &m->min_version);
	sv2_read_u16(&r, &m->max_version);
	sv2_read_u32(&r, &m->flags);
	sv2_read_str0_255(&r, &m->endpoint_host);
	sv2_read_u16(&r, &m->endpoint_port);
	sv2_read_str0_255(&r, &m->vendor);
	sv2_read_str0_255(&r, &m->hardware_version);
	sv2_read_str0_255(&r, &m->firmware);
	sv2_read_str0_255(&r, &m->device_id);
	return sv2_reader_finish(&r);
}

int sv2_msg_setup_connection_success_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SETUP_CONNECTION_SUCCESS *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u16(&w, m->used_version);
	sv2_write_u32(&w, m->flags);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_SETUP_CONNECTION_SUCCESS, false);
}

int sv2_msg_setup_connection_success_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SETUP_CONNECTION_SUCCESS *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u16(&r, &m->used_version);
	sv2_read_u32(&r, &m->flags);
	return sv2_reader_finish(&r);
}

int sv2_msg_setup_connection_error_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SETUP_CONNECTION_ERROR *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->flags);
	sv2_write_str0_255(&w, m->error_code);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_SETUP_CONNECTION_ERROR, false);
}

int sv2_msg_setup_connection_error_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SETUP_CONNECTION_ERROR *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->flags);
	sv2_read_str0_255(&r, &m->error_code);
	return sv2_reader_finish(&r);
}

int sv2_msg_channel_endpoint_changed_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_CHANNEL_ENDPOINT_CHANGED *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_u32(&w, m->channel_id);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_CHANNEL_ENDPOINT_CHANGED, true);
}

int sv2_msg_channel_endpoint_changed_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_CHANNEL_ENDPOINT_CHANGED *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_u32(&r, &m->channel_id);
	return sv2_reader_finish(&r);
}

int sv2_msg_reconnect_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_RECONNECT *m) {
	T_SV2_WRITER w;
	sv2_frame_begin(&w, buf, cap);
	sv2_write_str0_255(&w, m->new_host);
	sv2_write_u16(&w, m->new_port);
	return sv2_frame_finish(&w, SV2_EXTENSION_BASE, SV2_MSG_RECONNECT, false);
}

int sv2_msg_reconnect_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_RECONNECT *m) {
	T_SV2_READER r;
	sv2_reader_init(&r, payload, len);
	sv2_read_str0_255(&r, &m->new_host);
	sv2_read_u16(&r, &m->new_port);
	return sv2_reader_finish(&r);
}
