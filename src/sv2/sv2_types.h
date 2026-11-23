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

#ifndef _SV2_TYPES_H_
#define _SV2_TYPES_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Return codes shared by every sv2_* module.
// Functions return SV2_OK (0) or a negative error.  Stream readers may also
// return SV2_NEED_MORE (positive) when the input is incomplete.
#define SV2_OK 0
#define SV2_NEED_MORE 1
#define SV2_ERR_TRUNCATED -1   // input ended before the field did
#define SV2_ERR_OVERFLOW -2    // output buffer too small
#define SV2_ERR_INVALID -3     // malformed or out-of-spec value
#define SV2_ERR_CRYPTO -4      // AEAD/ECDH/signature primitive failed
#define SV2_ERR_STATE -5       // call does not match the state machine
#define SV2_ERR_NONCE -6       // AEAD nonce exhausted, connection must end
#define SV2_ERR_CERT -7        // responder certificate rejected
#define SV2_ERR_TRAILING -8    // bytes left over after the last field
#define SV2_ERR_UNSUPPORTED -9 // a well-formed frame of a message or extension this layer has no decoder for

// Protocol identifiers carried in SetupConnection.protocol
#define SV2_PROTOCOL_MINING 0
#define SV2_PROTOCOL_JOB_DECLARATION 1
#define SV2_PROTOCOL_TEMPLATE_DISTRIBUTION 2

// The only protocol version currently defined
#define SV2_PROTOCOL_VERSION 2

// A borrowed byte range.  Decoders point these into the caller's payload
// buffer so no message is ever copied or allocated; encoders read from them.
typedef struct {
	const unsigned char *data;
	uint32_t len;
} T_SV2_BYTES;

static inline T_SV2_BYTES sv2_bytes(const void *data, uint32_t len) {
	T_SV2_BYTES b;
	b.data = (const unsigned char *)data;
	b.len = len;
	return b;
}

#endif
