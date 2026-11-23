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

#include "sv2_frame.h"

int sv2_frame_header_parse(const unsigned char *buf, uint32_t len, T_SV2_FRAME_HEADER *h) {
	if (len < SV2_FRAME_HEADER_SIZE) return SV2_ERR_TRUNCATED;
	h->extension_type = sv2_get_u16(buf);
	h->msg_type = buf[2];
	h->msg_length = sv2_get_u24(buf + 3);
	return SV2_OK;
}

int sv2_frame_header_write(unsigned char *buf, uint32_t cap, const T_SV2_FRAME_HEADER *h) {
	if (cap < SV2_FRAME_HEADER_SIZE) return SV2_ERR_OVERFLOW;
	if (h->msg_length > SV2_FRAME_MAX_PAYLOAD) return SV2_ERR_INVALID;
	sv2_put_u16(buf, h->extension_type);
	buf[2] = h->msg_type;
	sv2_put_u24(buf + 3, h->msg_length);
	return SV2_OK;
}

int sv2_frame_begin(T_SV2_WRITER *w, unsigned char *buf, uint32_t cap) {
	sv2_writer_init(w, buf, cap);
	if (cap < SV2_FRAME_HEADER_SIZE) {
		w->fail = true;
		return SV2_ERR_OVERFLOW;
	}
	w->pos = SV2_FRAME_HEADER_SIZE;
	return SV2_OK;
}

int sv2_frame_finish(T_SV2_WRITER *w, uint16_t extension, uint8_t msg_type, bool channel_msg) {
	T_SV2_FRAME_HEADER h;
	int r;
	
	if (w->fail) return SV2_ERR_OVERFLOW;
	if (w->pos < SV2_FRAME_HEADER_SIZE) return SV2_ERR_STATE;
	
	h.extension_type = (uint16_t)((extension & SV2_EXTENSION_MASK) | (channel_msg ? SV2_CHANNEL_MSG_BIT : 0));
	h.msg_type = msg_type;
	h.msg_length = w->pos - SV2_FRAME_HEADER_SIZE;
	
	r = sv2_frame_header_write(w->buf, w->cap, &h);
	if (r != SV2_OK) return r;
	
	return (int)w->pos;
}
