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

#ifndef _DATUM_SV2_CHANNEL_H_
#define _DATUM_SV2_CHANNEL_H_

// The channel layer of the SV2 server: what the mining protocol keeps per
// channel and decides about it, apart from the DATUM job pipeline that
// feeds it (datum_sv2.c, the same file in both builds).  A channel's
// extranonce prefix, its jobs and their ids, the chain tip they are mined
// under and the checks a share has to pass are the layer's; the coinbase
// per difficulty tier, vardiff, the pool submission and the stats stay
// with the gateway.
//
// Two implementations, installed by datum/build.sh as src/datum_sv2_channel.c:
//
//   datum/datum_sv2_channel.c             the default build.  The session id
//                                         is the extranonce prefix, a job id
//                                         is the gateway's own reference, and
//                                         a share is checked against DATUM's
//                                         job tables.
//   sri-capi/shim/datum_sv2_channel_sri.c the SRI build: channels_sv2's
//                                         server channels through sv2_sri.h.
//                                         The crate allocates the prefix,
//                                         issues the job ids and validates
//                                         the shares.

#include <stdbool.h>
#include <stdint.h>

#include "datum_stratum.h"

// Room for the longest error code of OpenMiningChannel.Error,
// UpdateChannel.Error or SubmitShares.Error, NUL included
#define DATUM_SV2_CHANNEL_ERROR_CODE_MAX 48

typedef struct T_DATUM_SV2_CHANNEL_PROTO T_DATUM_SV2_CHANNEL_PROTO;

// Once at server start, before any thread runs.  max_channels is the most
// the server has open at once (stratum_v2.max_clients): the default build
// allocates its per-channel state here, so that nothing is allocated while
// miners are served.
int datum_sv2_channel_layer_init(int max_threads, int max_channels);

// Once per server thread, from its init.  The SRI build keeps an extranonce
// allocator per thread, so no lock is needed; the thread id keeps the
// threads' prefixes apart.
int datum_sv2_channel_thread_init(int thread_id);

typedef struct {
	bool extended;
	uint32_t channel_id;             // the gateway's id for the channel: its session id
	const char *user_identity;
	float nominal_hash_rate;
	const unsigned char *max_target; // 32 bytes, as on the wire
	uint16_t min_extranonce_size;    // extended channels: the rollable bytes asked for
	const unsigned char *target;     // 32 bytes: the channel's first target
} T_DATUM_SV2_CHANNEL_OPEN;

// Open a channel: the layer picks its extranonce prefix.  m is the
// channel's miner data, in which the default build keeps the job targets.
// NULL with error_code set when the request is refused.
T_DATUM_SV2_CHANNEL_PROTO *datum_sv2_channel_open(int thread_id, T_DATUM_MINER_DATA *m, const T_DATUM_SV2_CHANNEL_OPEN *o, char error_code[DATUM_SV2_CHANNEL_ERROR_CODE_MAX]);
void datum_sv2_channel_close(T_DATUM_SV2_CHANNEL_PROTO *ch);

// The channel's extranonce prefix (the first 4 of DATUM's 12 bytes on an
// extended channel, all 12 on a standard one), and how many bytes the
// miner rolls after it
const unsigned char *datum_sv2_channel_extranonce_prefix(const T_DATUM_SV2_CHANNEL_PROTO *ch, unsigned int *len);
uint16_t datum_sv2_channel_extranonce_size(const T_DATUM_SV2_CHANNEL_PROTO *ch);

// The target of the jobs that follow: what SetTarget tells the miner.
// Jobs already sent keep the target they were sent at.
int datum_sv2_channel_set_target(T_DATUM_SV2_CHANNEL_PROTO *ch, const unsigned char target[32]);

// UpdateChannel: 0, or -1 with the UpdateChannel.Error code.  A max_target
// below the channel's target is accepted (spec 5.3.7); the gateway answers
// it with a SetTarget at or below it before the next job.
int datum_sv2_channel_update(T_DATUM_SV2_CHANNEL_PROTO *ch, float nominal_hash_rate, const unsigned char max_target[32], char error_code[DATUM_SV2_CHANNEL_ERROR_CODE_MAX]);

// A job as the bytes of the NewExtendedMiningJob the gateway sends
typedef struct {
	// sent without min_ntime, to be activated by datum_sv2_channel_activate_job();
	// otherwise active under the channel's chain tip, with the previous job
	// kept for the shares still coming on it
	bool future;
	uint32_t min_ntime;                   // an active job's min_ntime as sent, never below the tip's
	uint32_t version;
	const unsigned char *coinbase_prefix; // with the difficulty byte and the quick diff tail in place
	unsigned int coinbase_prefix_len;
	const unsigned char *coinbase_suffix;
	unsigned int coinbase_suffix_len;
	const unsigned char *merkle_path;     // merkle_path_count * 32 bytes
	unsigned int merkle_path_count;
	uint32_t ref;                         // the gateway's reference for the job, handed back with its shares
	uint64_t diff;                        // the difficulty of the job's target and difficulty byte, handed back too
} T_DATUM_SV2_CHANNEL_JOB;

// Register a job: *job_id is the id the miner is told, and merkle_root (32
// bytes) receives the merkle root of a standard channel's NewMiningJob.
int datum_sv2_channel_new_job(T_DATUM_SV2_CHANNEL_PROTO *ch, const T_DATUM_SV2_CHANNEL_JOB *job, uint32_t *job_id, unsigned char *merkle_root);

// SetNewPrevHash: the future job job_id is the active job under this tip,
// and every other job of the channel goes stale.
int datum_sv2_channel_activate_job(T_DATUM_SV2_CHANNEL_PROTO *ch, uint32_t job_id, const unsigned char prev_hash[32], uint32_t nbits, uint32_t min_ntime);

typedef struct {
	uint32_t sequence_number;
	uint32_t job_id;
	uint32_t nonce;
	uint32_t ntime;
	uint32_t version;
	const unsigned char *extranonce; // the rollable bytes of an extended share; none on a standard channel
	unsigned int extranonce_len;
} T_DATUM_SV2_CHANNEL_SHARE;

typedef struct {
	bool accepted;                              // the share passes the layer's checks
	char error_code[DATUM_SV2_CHANNEL_ERROR_CODE_MAX]; // otherwise, the SubmitShares.Error code
	bool known_job;                             // ref and diff are valid: the share names a job the channel had
	uint32_t ref;                               // that job's ref
	uint64_t diff;                              // and the difficulty it was sent at: a job index sent again
	                                            // at another difficulty keeps its own shares' credit
	bool block;                                 // the hash meets the network target
	bool close;                                 // the channel can take no more shares and should be closed
	unsigned char hash[32];                     // the share hash, when accepted or block
	unsigned char extranonce[12];               // the full extranonce the share was mined with, when the job is known
} T_DATUM_SV2_CHANNEL_SHARE_RESULT;

// The protocol's checks on a share: the job it names, the extranonce size,
// the version bits, the hash against the job's target, and that the same
// share was not accepted before.
void datum_sv2_channel_check_share(T_DATUM_SV2_CHANNEL_PROTO *ch, const T_DATUM_SV2_CHANNEL_SHARE *s, T_DATUM_SV2_CHANNEL_SHARE_RESULT *r);

// The layer's own self-tests, run by datum_gateway --test
void datum_sv2_channel_tests(void);

#endif
