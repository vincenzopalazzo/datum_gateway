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
