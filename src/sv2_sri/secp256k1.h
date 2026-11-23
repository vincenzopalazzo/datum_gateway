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

#ifndef SECP256K1_H
#define SECP256K1_H

// Stand-in for libsecp256k1's header in the SRI-backed build.
//
// sv2.cc's Noise functions take a secp256k1_context that the caller
// creates, and datum_sv2.c (like the simulators) creates one per thread
// with these three calls.  In the SRI build the curve work happens inside
// libsv2_sri, which carries its own copy of libsecp256k1 through the
// rust-secp256k1 crate (with prefixed symbols), so the context is never
// used.  This header lets the callers compile unchanged without linking a
// second libsecp256k1 for nothing.  It must come before the real header
// on the include path, and nothing in an SRI build may need the real one.

#include <stddef.h>

typedef struct secp256k1_context_struct secp256k1_context;

#define SECP256K1_CONTEXT_NONE 1

static inline secp256k1_context *secp256k1_context_create(unsigned int flags) {
	// any non-NULL pointer will do; nobody dereferences it
	static char unused;
	(void)flags;
	return (secp256k1_context *)(void *)&unused;
}

static inline void secp256k1_context_destroy(secp256k1_context *ctx) {
	(void)ctx;
}

static inline int secp256k1_context_randomize(secp256k1_context *ctx, const unsigned char *seed32) {
	(void)ctx;
	(void)seed32;
	return 1;
}

#endif
