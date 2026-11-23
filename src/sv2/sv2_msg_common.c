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
