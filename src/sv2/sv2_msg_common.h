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

#ifndef _SV2_MSG_COMMON_H_
#define _SV2_MSG_COMMON_H_

#include "sv2_frame.h"

// Common messages, spec section 3.  Shared by every subprotocol.

#define SV2_MSG_SETUP_CONNECTION 0x00
#define SV2_MSG_SETUP_CONNECTION_SUCCESS 0x01
#define SV2_MSG_SETUP_CONNECTION_ERROR 0x02
#define SV2_MSG_CHANNEL_ENDPOINT_CHANGED 0x03
#define SV2_MSG_RECONNECT 0x04

// SetupConnection.flags for the mining protocol (spec 5.3.1)
#define SV2_SETUP_FLAG_REQUIRES_STANDARD_JOBS (1u << 0)
#define SV2_SETUP_FLAG_REQUIRES_WORK_SELECTION (1u << 1)
#define SV2_SETUP_FLAG_REQUIRES_VERSION_ROLLING (1u << 2)

// SetupConnection.Success.flags for the mining protocol (spec 5.3.2)
#define SV2_SETUP_SUCCESS_FLAG_REQUIRES_FIXED_VERSION (1u << 0)
#define SV2_SETUP_SUCCESS_FLAG_REQUIRES_EXTENDED_CHANNELS (1u << 1)

// SetupConnection.Error.error_code values
#define SV2_ERROR_UNSUPPORTED_FEATURE_FLAGS "unsupported-feature-flags"
#define SV2_ERROR_UNSUPPORTED_PROTOCOL "unsupported-protocol"
#define SV2_ERROR_PROTOCOL_VERSION_MISMATCH "protocol-version-mismatch"

typedef struct {
	uint8_t protocol;
	uint16_t min_version;
	uint16_t max_version;
	uint32_t flags;
	T_SV2_BYTES endpoint_host;
	uint16_t endpoint_port;
	T_SV2_BYTES vendor;
	T_SV2_BYTES hardware_version;
	T_SV2_BYTES firmware;
	T_SV2_BYTES device_id;
} T_SV2_MSG_SETUP_CONNECTION;

typedef struct {
	uint16_t used_version;
	uint32_t flags;
} T_SV2_MSG_SETUP_CONNECTION_SUCCESS;

typedef struct {
	uint32_t flags;
	T_SV2_BYTES error_code;
} T_SV2_MSG_SETUP_CONNECTION_ERROR;

typedef struct {
	uint32_t channel_id;
} T_SV2_MSG_CHANNEL_ENDPOINT_CHANGED;

typedef struct {
	T_SV2_BYTES new_host;
	uint16_t new_port;
} T_SV2_MSG_RECONNECT;

// Encoders write a complete frame (header included) into buf and return
// its length, or a negative error.  Decoders take the payload that follows
// the header and return SV2_OK or a negative error; views in the output
// struct point into payload and are only valid while it is.

int sv2_msg_setup_connection_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SETUP_CONNECTION *m);
int sv2_msg_setup_connection_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SETUP_CONNECTION *m);

int sv2_msg_setup_connection_success_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SETUP_CONNECTION_SUCCESS *m);
int sv2_msg_setup_connection_success_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SETUP_CONNECTION_SUCCESS *m);

int sv2_msg_setup_connection_error_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_SETUP_CONNECTION_ERROR *m);
int sv2_msg_setup_connection_error_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_SETUP_CONNECTION_ERROR *m);

int sv2_msg_channel_endpoint_changed_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_CHANNEL_ENDPOINT_CHANGED *m);
int sv2_msg_channel_endpoint_changed_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_CHANNEL_ENDPOINT_CHANGED *m);

int sv2_msg_reconnect_encode(unsigned char *buf, uint32_t cap, const T_SV2_MSG_RECONNECT *m);
int sv2_msg_reconnect_decode(const unsigned char *payload, uint32_t len, T_SV2_MSG_RECONNECT *m);

#endif
