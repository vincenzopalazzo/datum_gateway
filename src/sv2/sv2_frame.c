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
