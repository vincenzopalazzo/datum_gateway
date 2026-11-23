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

#ifndef _SV2_FRAME_H_
#define _SV2_FRAME_H_

#include "sv2_codec.h"

// Stratum V2 message framing, spec section 3.3.
//
//   extension_type  u16  bit 15 is the channel_msg flag; the remaining 15
//                        bits identify the extension (0 = base protocol)
//   msg_type        u8
//   msg_length      u24  payload length, not counting this header
//
// When channel_msg is set the first four bytes of the payload are the
// channel_id the message is addressed to.

#define SV2_FRAME_HEADER_SIZE 6
#define SV2_FRAME_MAX_PAYLOAD 0xFFFFFFu
#define SV2_CHANNEL_MSG_BIT 0x8000u
#define SV2_EXTENSION_MASK 0x7FFFu

#define SV2_EXTENSION_BASE 0

typedef struct {
	uint16_t extension_type;
	uint8_t msg_type;
	uint32_t msg_length;
} T_SV2_FRAME_HEADER;

static inline bool sv2_frame_is_channel_msg(const T_SV2_FRAME_HEADER *h) {
	return (h->extension_type & SV2_CHANNEL_MSG_BIT) != 0;
}

static inline uint16_t sv2_frame_extension(const T_SV2_FRAME_HEADER *h) {
	return h->extension_type & SV2_EXTENSION_MASK;
}

// Parse the first SV2_FRAME_HEADER_SIZE bytes of buf.
int sv2_frame_header_parse(const unsigned char *buf, uint32_t len, T_SV2_FRAME_HEADER *h);

// Write the header into buf.
int sv2_frame_header_write(unsigned char *buf, uint32_t cap, const T_SV2_FRAME_HEADER *h);

// Message encoders reserve the header, write the payload through a writer
// and call this to fill the header in.  Returns the full frame length or a
// negative error when the writer overflowed.
int sv2_frame_begin(T_SV2_WRITER *w, unsigned char *buf, uint32_t cap);
int sv2_frame_finish(T_SV2_WRITER *w, uint16_t extension, uint8_t msg_type, bool channel_msg);

#endif
