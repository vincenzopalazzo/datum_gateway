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
