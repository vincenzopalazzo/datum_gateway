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

#include <string.h>

#include "sv2_codec.h"

// Byte-wise little endian access.  Works on any host endianness and any
// alignment, which matters on the ESP32 where unaligned loads fault.

uint16_t sv2_get_u16(const unsigned char *p) {
	return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
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
	p[0] = (unsigned char)(v & 0xFF);
	p[1] = (unsigned char)((v >> 8) & 0xFF);
}

void sv2_put_u24(unsigned char *p, uint32_t v) {
	p[0] = (unsigned char)(v & 0xFF);
	p[1] = (unsigned char)((v >> 8) & 0xFF);
	p[2] = (unsigned char)((v >> 16) & 0xFF);
}

void sv2_put_u32(unsigned char *p, uint32_t v) {
	p[0] = (unsigned char)(v & 0xFF);
	p[1] = (unsigned char)((v >> 8) & 0xFF);
	p[2] = (unsigned char)((v >> 16) & 0xFF);
	p[3] = (unsigned char)((v >> 24) & 0xFF);
}

void sv2_put_u64(unsigned char *p, uint64_t v) {
	sv2_put_u32(p, (uint32_t)(v & 0xFFFFFFFFULL));
	sv2_put_u32(p + 4, (uint32_t)(v >> 32));
}

/////////////////////////////////
// Reader
/////////////////////////////////

void sv2_reader_init(T_SV2_READER *r, const unsigned char *buf, uint32_t len) {
	r->buf = buf;
	r->len = len;
	r->pos = 0;
	r->fail = false;
}

uint32_t sv2_reader_remaining(const T_SV2_READER *r) {
	return r->len - r->pos;
}

int sv2_reader_finish(const T_SV2_READER *r) {
	if (r->fail) return SV2_ERR_TRUNCATED;
	if (r->pos != r->len) return SV2_ERR_TRAILING;
	return SV2_OK;
}

static inline const unsigned char *reader_take(T_SV2_READER *r, uint32_t n) {
	const unsigned char *p;
	if (r->fail) return NULL;
	if (n > r->len - r->pos) {
		r->fail = true;
		return NULL;
	}
	p = r->buf + r->pos;
	r->pos += n;
	return p;
}

bool sv2_read_bytes(T_SV2_READER *r, unsigned char *out, uint32_t n) {
	const unsigned char *p = reader_take(r, n);
	if (!p) return false;
	if (n) memcpy(out, p, n);
	return true;
}

bool sv2_read_view(T_SV2_READER *r, T_SV2_BYTES *out, uint32_t n) {
	const unsigned char *p = reader_take(r, n);
	if (!p) return false;
	out->data = p;
	out->len = n;
	return true;
}

bool sv2_read_u8(T_SV2_READER *r, uint8_t *v) {
	const unsigned char *p = reader_take(r, 1);
	if (!p) return false;
	*v = p[0];
	return true;
}

bool sv2_read_u16(T_SV2_READER *r, uint16_t *v) {
	const unsigned char *p = reader_take(r, 2);
	if (!p) return false;
	*v = sv2_get_u16(p);
	return true;
}

bool sv2_read_u24(T_SV2_READER *r, uint32_t *v) {
	const unsigned char *p = reader_take(r, 3);
	if (!p) return false;
	*v = sv2_get_u24(p);
	return true;
}

bool sv2_read_u32(T_SV2_READER *r, uint32_t *v) {
	const unsigned char *p = reader_take(r, 4);
	if (!p) return false;
	*v = sv2_get_u32(p);
	return true;
}

bool sv2_read_u64(T_SV2_READER *r, uint64_t *v) {
	const unsigned char *p = reader_take(r, 8);
	if (!p) return false;
	*v = sv2_get_u64(p);
	return true;
}

bool sv2_read_f32(T_SV2_READER *r, float *v) {
	uint32_t bits;
	if (!sv2_read_u32(r, &bits)) return false;
	memcpy(v, &bits, 4);
	return true;
}

bool sv2_read_bool(T_SV2_READER *r, bool *v) {
	uint8_t b;
	if (!sv2_read_u8(r, &b)) return false;
	// Spec §3.1: BOOL is "an unsigned 1-bit integer, True = 1, False = 0 with
	// 7 additional padding bits in the high positions. Recipients MUST NOT
	// interpret bits outside of the least significant bit." Every byte is
	// valid; only bit 0 carries the value (SRI's binary_sv2 does the same).
	*v = (b & 1) != 0;
	return true;
}

bool sv2_read_u256(T_SV2_READER *r, unsigned char out[32]) {
	return sv2_read_bytes(r, out, 32);
}

static bool read_len_prefixed(T_SV2_READER *r, uint32_t len_width, uint32_t max_len, T_SV2_BYTES *out) {
	uint32_t n = 0;
	uint16_t n16;
	uint8_t n8;
	
	switch (len_width) {
		case 1:
			if (!sv2_read_u8(r, &n8)) return false;
			n = n8;
			break;
		case 2:
			if (!sv2_read_u16(r, &n16)) return false;
			n = n16;
			break;
		case 3:
			if (!sv2_read_u24(r, &n)) return false;
			break;
		default:
			r->fail = true;
			return false;
	}
	if (n > max_len) {
		r->fail = true;
		return false;
	}
	return sv2_read_view(r, out, n);
}

bool sv2_read_str0_255(T_SV2_READER *r, T_SV2_BYTES *out) {
	return read_len_prefixed(r, 1, 255, out);
}

bool sv2_read_b0_32(T_SV2_READER *r, T_SV2_BYTES *out) {
	return read_len_prefixed(r, 1, 32, out);
}

bool sv2_read_b0_255(T_SV2_READER *r, T_SV2_BYTES *out) {
	return read_len_prefixed(r, 1, 255, out);
}

bool sv2_read_b0_64k(T_SV2_READER *r, T_SV2_BYTES *out) {
	return read_len_prefixed(r, 2, 65535, out);
}

bool sv2_read_b0_16m(T_SV2_READER *r, T_SV2_BYTES *out) {
	return read_len_prefixed(r, 3, 16777215, out);
}

bool sv2_read_seq0_255_u256(T_SV2_READER *r, T_SV2_BYTES *out, uint8_t *count) {
	uint8_t n;
	if (!sv2_read_u8(r, &n)) return false;
	if (!sv2_read_view(r, out, (uint32_t)n * 32)) return false;
	*count = n;
	return true;
}

bool sv2_read_seq0_64k_u32(T_SV2_READER *r, T_SV2_BYTES *out, uint16_t *count) {
	uint16_t n;
	if (!sv2_read_u16(r, &n)) return false;
	if (!sv2_read_view(r, out, (uint32_t)n * 4)) return false;
	*count = n;
	return true;
}

bool sv2_read_option_u32(T_SV2_READER *r, bool *present, uint32_t *v) {
	uint8_t n;
	if (!sv2_read_u8(r, &n)) return false;
	switch (n) {
		case 0: {
			*present = false;
			*v = 0;
			return true;
		}
		case 1: {
			*present = true;
			return sv2_read_u32(r, v);
		}
		default: {
			// OPTION is a sequence of at most one element
			r->fail = true;
			return false;
		}
	}
}

/////////////////////////////////
// Writer
/////////////////////////////////

void sv2_writer_init(T_SV2_WRITER *w, unsigned char *buf, uint32_t cap) {
	w->buf = buf;
	w->cap = cap;
	w->pos = 0;
	w->fail = false;
}

static inline unsigned char *writer_take(T_SV2_WRITER *w, uint32_t n) {
	unsigned char *p;
	if (w->fail) return NULL;
	if (n > w->cap - w->pos) {
		w->fail = true;
		return NULL;
	}
	p = w->buf + w->pos;
	w->pos += n;
	return p;
}

bool sv2_write_bytes(T_SV2_WRITER *w, const unsigned char *in, uint32_t n) {
	unsigned char *p = writer_take(w, n);
	if (!p) return false;
	if (n) memcpy(p, in, n);
	return true;
}

bool sv2_write_u8(T_SV2_WRITER *w, uint8_t v) {
	unsigned char *p = writer_take(w, 1);
	if (!p) return false;
	p[0] = v;
	return true;
}

bool sv2_write_u16(T_SV2_WRITER *w, uint16_t v) {
	unsigned char *p = writer_take(w, 2);
	if (!p) return false;
	sv2_put_u16(p, v);
	return true;
}

bool sv2_write_u24(T_SV2_WRITER *w, uint32_t v) {
	unsigned char *p;
	if (v > 0xFFFFFF) {
		w->fail = true;
		return false;
	}
	p = writer_take(w, 3);
	if (!p) return false;
	sv2_put_u24(p, v);
	return true;
}

bool sv2_write_u32(T_SV2_WRITER *w, uint32_t v) {
	unsigned char *p = writer_take(w, 4);
	if (!p) return false;
	sv2_put_u32(p, v);
	return true;
}

bool sv2_write_u64(T_SV2_WRITER *w, uint64_t v) {
	unsigned char *p = writer_take(w, 8);
	if (!p) return false;
	sv2_put_u64(p, v);
	return true;
}

bool sv2_write_f32(T_SV2_WRITER *w, float v) {
	uint32_t bits;
	memcpy(&bits, &v, 4);
	return sv2_write_u32(w, bits);
}

bool sv2_write_bool(T_SV2_WRITER *w, bool v) {
	return sv2_write_u8(w, v ? 1 : 0);
}

bool sv2_write_u256(T_SV2_WRITER *w, const unsigned char in[32]) {
	return sv2_write_bytes(w, in, 32);
}

static bool write_len_prefixed(T_SV2_WRITER *w, uint32_t len_width, uint32_t max_len, T_SV2_BYTES b) {
	if (b.len > max_len) {
		w->fail = true;
		return false;
	}
	switch (len_width) {
		case 1:
			if (!sv2_write_u8(w, (uint8_t)b.len)) return false;
			break;
		case 2:
			if (!sv2_write_u16(w, (uint16_t)b.len)) return false;
			break;
		case 3:
			if (!sv2_write_u24(w, b.len)) return false;
			break;
		default:
			w->fail = true;
			return false;
	}
	return sv2_write_bytes(w, b.data, b.len);
}

bool sv2_write_str0_255(T_SV2_WRITER *w, T_SV2_BYTES s) {
	return write_len_prefixed(w, 1, 255, s);
}

bool sv2_write_b0_32(T_SV2_WRITER *w, T_SV2_BYTES b) {
	return write_len_prefixed(w, 1, 32, b);
}

bool sv2_write_b0_255(T_SV2_WRITER *w, T_SV2_BYTES b) {
	return write_len_prefixed(w, 1, 255, b);
}

bool sv2_write_b0_64k(T_SV2_WRITER *w, T_SV2_BYTES b) {
	return write_len_prefixed(w, 2, 65535, b);
}

bool sv2_write_b0_16m(T_SV2_WRITER *w, T_SV2_BYTES b) {
	return write_len_prefixed(w, 3, 16777215, b);
}

bool sv2_write_seq0_255_u256(T_SV2_WRITER *w, const unsigned char *items, uint8_t count) {
	if (!sv2_write_u8(w, count)) return false;
	return sv2_write_bytes(w, items, (uint32_t)count * 32);
}

bool sv2_write_seq0_64k_u32(T_SV2_WRITER *w, const uint32_t *items, uint16_t count) {
	uint32_t i;
	if (!sv2_write_u16(w, count)) return false;
	for (i = 0; i < count; i++) {
		if (!sv2_write_u32(w, items[i])) return false;
	}
	return true;
}

bool sv2_write_option_u32(T_SV2_WRITER *w, bool present, uint32_t v) {
	if (!sv2_write_u8(w, present ? 1 : 0)) return false;
	if (!present) return true;
	return sv2_write_u32(w, v);
}

/////////////////////////////////
// String helpers
/////////////////////////////////

bool sv2_str_copy(char *dst, size_t dst_sz, T_SV2_BYTES src) {
	uint32_t i;
	if (!dst_sz) return false;
	if (src.len >= dst_sz) {
		dst[0] = 0;
		return false;
	}
	for (i = 0; i < src.len; i++) {
		if (src.data[i] == 0) {
			dst[0] = 0;
			return false;
		}
	}
	if (src.len) memcpy(dst, src.data, src.len);
	dst[src.len] = 0;
	return true;
}

T_SV2_BYTES sv2_str(const char *s) {
	size_t n = s ? strlen(s) : 0;
	// Longer strings are rejected by the STR0_255 writer; clamp the length
	// here only so the u32 conversion is well defined.
	if (n > 0xFFFFFFFFu) n = 0xFFFFFFFFu;
	return sv2_bytes(s, (uint32_t)n);
}
