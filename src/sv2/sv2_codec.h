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

#ifndef _SV2_CODEC_H_
#define _SV2_CODEC_H_

#include "sv2_types.h"

// Primitive data types from the Stratum V2 spec, section 2 (Binary Protocol).
// Every integer is little endian.  Variable length fields carry a little
// endian length prefix whose width gives the type its name:
//   STR0_255 / B0_255 / SEQ0_255  -> u8 length
//   B0_32                         -> u8 length, max 32
//   B0_64K / SEQ0_64K             -> u16 length
//   B0_16M                        -> u24 length
//   OPTION[T]                     -> u8 count (0 or 1) followed by T
//
// The reader never writes and never fails hard: once any read fails the
// reader is poisoned (r->fail) and every later read returns false, so a
// decoder can chain reads and check once at the end.  The writer mirrors
// this with w->fail on overflow.

typedef struct {
	const unsigned char *buf;
	uint32_t len;
	uint32_t pos;
	bool fail;
} T_SV2_READER;

typedef struct {
	unsigned char *buf;
	uint32_t cap;
	uint32_t pos;
	bool fail;
} T_SV2_WRITER;

void sv2_reader_init(T_SV2_READER *r, const unsigned char *buf, uint32_t len);
uint32_t sv2_reader_remaining(const T_SV2_READER *r);

// SV2_OK when every read succeeded and the payload is fully consumed,
// SV2_ERR_TRUNCATED when a read ran out of input, SV2_ERR_TRAILING otherwise.
int sv2_reader_finish(const T_SV2_READER *r);

bool sv2_read_bytes(T_SV2_READER *r, unsigned char *out, uint32_t n);
bool sv2_read_view(T_SV2_READER *r, T_SV2_BYTES *out, uint32_t n);
bool sv2_read_u8(T_SV2_READER *r, uint8_t *v);
bool sv2_read_u16(T_SV2_READER *r, uint16_t *v);
bool sv2_read_u24(T_SV2_READER *r, uint32_t *v);
bool sv2_read_u32(T_SV2_READER *r, uint32_t *v);
bool sv2_read_u64(T_SV2_READER *r, uint64_t *v);
bool sv2_read_f32(T_SV2_READER *r, float *v);
bool sv2_read_bool(T_SV2_READER *r, bool *v);
bool sv2_read_u256(T_SV2_READER *r, unsigned char out[32]);
bool sv2_read_str0_255(T_SV2_READER *r, T_SV2_BYTES *out);
bool sv2_read_b0_32(T_SV2_READER *r, T_SV2_BYTES *out);
bool sv2_read_b0_255(T_SV2_READER *r, T_SV2_BYTES *out);
bool sv2_read_b0_64k(T_SV2_READER *r, T_SV2_BYTES *out);
bool sv2_read_b0_16m(T_SV2_READER *r, T_SV2_BYTES *out);
// out->data points at count*32 contiguous bytes
bool sv2_read_seq0_255_u256(T_SV2_READER *r, T_SV2_BYTES *out, uint8_t *count);
// out->data points at count*4 little endian u32 values; use sv2_seq_u32_get()
bool sv2_read_seq0_64k_u32(T_SV2_READER *r, T_SV2_BYTES *out, uint16_t *count);
bool sv2_read_option_u32(T_SV2_READER *r, bool *present, uint32_t *v);

void sv2_writer_init(T_SV2_WRITER *w, unsigned char *buf, uint32_t cap);
bool sv2_write_bytes(T_SV2_WRITER *w, const unsigned char *in, uint32_t n);
bool sv2_write_u8(T_SV2_WRITER *w, uint8_t v);
bool sv2_write_u16(T_SV2_WRITER *w, uint16_t v);
bool sv2_write_u24(T_SV2_WRITER *w, uint32_t v);
bool sv2_write_u32(T_SV2_WRITER *w, uint32_t v);
bool sv2_write_u64(T_SV2_WRITER *w, uint64_t v);
bool sv2_write_f32(T_SV2_WRITER *w, float v);
bool sv2_write_bool(T_SV2_WRITER *w, bool v);
bool sv2_write_u256(T_SV2_WRITER *w, const unsigned char in[32]);
bool sv2_write_str0_255(T_SV2_WRITER *w, T_SV2_BYTES s);
bool sv2_write_b0_32(T_SV2_WRITER *w, T_SV2_BYTES b);
bool sv2_write_b0_255(T_SV2_WRITER *w, T_SV2_BYTES b);
bool sv2_write_b0_64k(T_SV2_WRITER *w, T_SV2_BYTES b);
bool sv2_write_b0_16m(T_SV2_WRITER *w, T_SV2_BYTES b);
bool sv2_write_seq0_255_u256(T_SV2_WRITER *w, const unsigned char *items, uint8_t count);
bool sv2_write_seq0_64k_u32(T_SV2_WRITER *w, const uint32_t *items, uint16_t count);
bool sv2_write_option_u32(T_SV2_WRITER *w, bool present, uint32_t v);

// Little endian helpers usable outside a reader/writer
uint16_t sv2_get_u16(const unsigned char *p);
uint32_t sv2_get_u24(const unsigned char *p);
uint32_t sv2_get_u32(const unsigned char *p);
uint64_t sv2_get_u64(const unsigned char *p);
void sv2_put_u16(unsigned char *p, uint16_t v);
void sv2_put_u24(unsigned char *p, uint32_t v);
void sv2_put_u32(unsigned char *p, uint32_t v);
void sv2_put_u64(unsigned char *p, uint64_t v);

// i-th element of a SEQ0_64K[u32] view
static inline uint32_t sv2_seq_u32_get(T_SV2_BYTES seq, uint32_t i) {
	return sv2_get_u32(seq.data + (i * 4));
}

// Copy a STR0_255 view into a NUL terminated C string.  Fails when the
// string does not fit or contains a NUL byte.
bool sv2_str_copy(char *dst, size_t dst_sz, T_SV2_BYTES src);

// Build a view from a C string (length capped at 255 by the caller's writer)
T_SV2_BYTES sv2_str(const char *s);

#endif
