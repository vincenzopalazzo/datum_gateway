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

// The SRI build's channel layer (datum/datum_sv2_channel.h) on
// channels_sv2's server channels, through sv2_sri.h.  Installed by
// datum/build.sh as src/datum_sv2_channel.c in place of
// datum/datum_sv2_channel.c; see doc/SRI_BACKEND.md.
//
// What the crate does: it allocates the extranonce prefix (one allocator
// per server thread, tagged with the thread so no two threads' prefixes
// can meet), issues the job ids, keeps every job it is given with the
// target it was sent at, and validates the shares: unknown or stale job
// id, extranonce size, version bits, ntime against the tip, the job's
// target, duplicates, and whether the hash meets the network target.  A
// share is credited at the difficulty of its job's target as the crate
// holds it.
//
// What stays here: the gateway's references for the jobs, which the crate
// knows nothing of.  Its job ids are sequential per channel, so a small
// ring maps them back to the reference the gateway registered the job
// with.

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <sv2_sri.h>

#include "datum_conf.h"
#include "datum_logger.h"
#include "datum_sv2.h"
#include "datum_sv2_channel.h"
#include "datum_utils.h"

#include "sv2_msg_mining.h"

// More than the jobs a channel has at once: the active one, up to 16 past
// ones, the stale ones until the next activation, and the future ones.
#define SV2_SRI_JOB_REFS 64

// An allocator hands out 2 bytes of index after a 2 byte thread tag, so a
// thread can have this many channels at once.
#define SV2_SRI_CHANNELS_PER_THREAD 65535

struct T_DATUM_SV2_CHANNEL_PROTO {
	bool extended;
	Sv2SriExtendedChannel *ext;
	Sv2SriStandardChannel *std;
	unsigned char extranonce_prefix[12];
	unsigned char extranonce_prefix_len;
	uint16_t extranonce_size;
	
	// the target the gateway last set: the crate's UpdateChannel derives its
	// own from the nominal hashrate, and the jobs that follow must keep the
	// one the miner was sent
	unsigned char target[32];
	
	// the crate's job ids to the gateway's references
	struct {
		uint32_t job_id;
		uint32_t ref;
	} refs[SV2_SRI_JOB_REFS];
	
	struct T_DATUM_SV2_CHANNEL_PROTO *next_free;
};

// The C side of a channel is allocated once, at startup, like the default
// build's; the crate's side is allocated per channel.
static pthread_mutex_t datum_sv2_channel_lock = PTHREAD_MUTEX_INITIALIZER;
static T_DATUM_SV2_CHANNEL_PROTO *datum_sv2_channel_free = NULL;
static Sv2SriExtranonceAllocator **sv2_allocators = NULL;
static int sv2_allocator_count = 0;

int datum_sv2_channel_layer_init(int max_threads, int max_channels) {
	T_DATUM_SV2_CHANNEL_PROTO *pool;
	int i;
	pool = calloc((size_t)max_channels, sizeof(*pool));
	sv2_allocators = calloc((size_t)max_threads, sizeof(*sv2_allocators));
	if (!pool || !sv2_allocators) return -1;
	sv2_allocator_count = max_threads;
	for (i = max_channels - 1; i >= 0; i--) {
		pool[i].next_free = datum_sv2_channel_free;
		datum_sv2_channel_free = &pool[i];
	}
	return 0;
}

// One allocator per thread.  Its 2 byte tag is the start of the session
// id the default build would give the thread's channels, in extranonce
// byte order, so the prefixes keep the layout V1's extranonce1 has and the
// property that matters: no V1 miner and no other thread's channel can get
// the same 4 bytes.
int datum_sv2_channel_thread_init(int thread_id) {
	unsigned char tag[2];
	uint32_t sid;
	if (thread_id < 0 || thread_id >= sv2_allocator_count) return -1;
	sid = datum_sv2_session_id(thread_id, 0, 0);
	tag[0] = (unsigned char)(sid >> 24);
	tag[1] = (unsigned char)(sid >> 16);
	sv2_allocators[thread_id] = sv2_sri_extranonce_allocator_new(tag, sizeof(tag), 12, SV2_SRI_CHANNELS_PER_THREAD);
	return sv2_allocators[thread_id] ? 0 : -1;
}

static void datum_sv2_channel_error(char *error_code, int status, const char *fallback) {
	Sv2SriBytes code = sv2_sri_channel_error_code(status);
	if (!code.len || code.len >= DATUM_SV2_CHANNEL_ERROR_CODE_MAX) {
		strncpy(error_code, fallback, DATUM_SV2_CHANNEL_ERROR_CODE_MAX - 1);
		error_code[DATUM_SV2_CHANNEL_ERROR_CODE_MAX - 1] = 0;
		return;
	}
	memcpy(error_code, code.data, code.len);
	error_code[code.len] = 0;
}

static void datum_sv2_channel_release(T_DATUM_SV2_CHANNEL_PROTO *ch) {
	sv2_sri_extended_channel_free(ch->ext);
	sv2_sri_standard_channel_free(ch->std);
	ch->ext = NULL;
	ch->std = NULL;
	pthread_mutex_lock(&datum_sv2_channel_lock);
	ch->next_free = datum_sv2_channel_free;
	datum_sv2_channel_free = ch;
	pthread_mutex_unlock(&datum_sv2_channel_lock);
}

T_DATUM_SV2_CHANNEL_PROTO *datum_sv2_channel_open(int thread_id, T_DATUM_MINER_DATA *m, const T_DATUM_SV2_CHANNEL_OPEN *o, char error_code[DATUM_SV2_CHANNEL_ERROR_CODE_MAX]) {
	T_DATUM_SV2_CHANNEL_PROTO *ch;
	Sv2SriChannelOpen so;
	int status = SV2_SRI_OK, len = 0, past;
	
	(void)m;
	if (thread_id < 0 || thread_id >= sv2_allocator_count || !sv2_allocators[thread_id]) {
		datum_sv2_channel_error(error_code, SV2_SRI_ERR_CH_OTHER, "channel-limit-reached");
		return NULL;
	}
	pthread_mutex_lock(&datum_sv2_channel_lock);
	ch = datum_sv2_channel_free;
	if (ch) datum_sv2_channel_free = ch->next_free;
	pthread_mutex_unlock(&datum_sv2_channel_lock);
	if (!ch) {
		datum_sv2_channel_error(error_code, SV2_SRI_ERR_CH_CAPACITY, "channel-limit-reached");
		return NULL;
	}
	memset(ch, 0, sizeof(*ch));
	ch->extended = o->extended;
	
	so.channel_id = o->channel_id;
	so.user_identity.data = (const uint8_t *)o->user_identity;
	so.user_identity.len = (uint32_t)strlen(o->user_identity);
	so.nominal_hash_rate = o->nominal_hash_rate;
	so.max_target = o->max_target;
	so.min_extranonce_size = o->min_extranonce_size;
	// every share is answered on its own, as the gateway does on V1
	so.share_batch_size = 1;
	// the share rate vardiff aims at sizes the crate's duplicate check
	so.expected_shares_per_minute = (float)datum_config.stratum_v1_vardiff_target_shares_min;
	// The crate keeps past jobs, each with its coinbase bytes, for shares
	// still coming on them.  DATUM takes a share on any job younger than
	// share_stale_seconds + work_update_seconds: twice the routine jobs of
	// that window is kept (quick diff and vardiff send more), at most the
	// crate's 16.
	past = 16;
	if (datum_config.bitcoind_work_update_seconds > 0) {
		past = 2 * ((datum_config.stratum_v1_share_stale_seconds + datum_config.bitcoind_work_update_seconds) / datum_config.bitcoind_work_update_seconds + 1);
	}
	so.max_past_jobs = (uint32_t)(past < 4 ? 4 : (past > 16 ? 16 : past));
	// miners roll the version bits on SV2 as on V1
	so.no_version_rolling = false;

	if (o->extended) {
		ch->ext = sv2_sri_extended_channel_new(sv2_allocators[thread_id], &so, &status);
		if (ch->ext) {
			len = sv2_sri_extended_channel_extranonce_prefix(ch->ext, ch->extranonce_prefix, sizeof(ch->extranonce_prefix));
			ch->extranonce_size = (uint16_t)sv2_sri_extranonce_allocator_rollable_size(sv2_allocators[thread_id]);
		}
	} else {
		ch->std = sv2_sri_standard_channel_new(sv2_allocators[thread_id], &so, &status);
		if (ch->std) {
			len = sv2_sri_standard_channel_extranonce_prefix(ch->std, ch->extranonce_prefix, sizeof(ch->extranonce_prefix));
			ch->extranonce_size = 0;
		}
	}
	if (!ch->ext && !ch->std) {
		// the crate refuses a user identity that is not UTF-8 as an invalid
		// argument; anything else it refuses has an error code of its own
		if (status == SV2_SRI_ERR_INVALID) {
			strncpy(error_code, "unknown-user", DATUM_SV2_CHANNEL_ERROR_CODE_MAX - 1);
			error_code[DATUM_SV2_CHANNEL_ERROR_CODE_MAX - 1] = 0;
		} else {
			datum_sv2_channel_error(error_code, status, "channel-limit-reached");
		}
		DLOG_DEBUG("channels_sv2 refused the channel (%d: %s)", status, error_code);
		datum_sv2_channel_release(ch);
		return NULL;
	}
	if (len != (o->extended ? 4 : 12)) {
		DLOG_ERROR("channels_sv2 gave a %d byte extranonce prefix; DATUM's layout needs %d", len, o->extended ? 4 : 12);
		datum_sv2_channel_error(error_code, SV2_SRI_ERR_CH_OTHER, "channel-limit-reached");
		datum_sv2_channel_release(ch);
		return NULL;
	}
	ch->extranonce_prefix_len = (unsigned char)len;
	
	// the crate derived a target from the nominal hashrate; the gateway's
	// starting difficulty is the one the miner is told
	if (datum_sv2_channel_set_target(ch, o->target) < 0) {
		datum_sv2_channel_error(error_code, SV2_SRI_ERR_CH_TARGET, "max-target-out-of-range");
		datum_sv2_channel_release(ch);
		return NULL;
	}
	return ch;
}

void datum_sv2_channel_close(T_DATUM_SV2_CHANNEL_PROTO *ch) {
	if (ch) datum_sv2_channel_release(ch);
}

const unsigned char *datum_sv2_channel_extranonce_prefix(const T_DATUM_SV2_CHANNEL_PROTO *ch, unsigned int *len) {
	*len = ch->extranonce_prefix_len;
	return ch->extranonce_prefix;
}

uint16_t datum_sv2_channel_extranonce_size(const T_DATUM_SV2_CHANNEL_PROTO *ch) {
	return ch->extranonce_size;
}

int datum_sv2_channel_set_target(T_DATUM_SV2_CHANNEL_PROTO *ch, const unsigned char target[32]) {
	int status = ch->extended ? sv2_sri_extended_channel_set_target(ch->ext, target) : sv2_sri_standard_channel_set_target(ch->std, target);
	if (status != SV2_SRI_OK) {
		DLOG_ERROR("channels_sv2 refused the target (%d)", status);
		return -1;
	}
	memcpy(ch->target, target, 32);
	return 0;
}

// The crate checks the hashrate and max_target, then sets a target of its
// own from the hashrate, at or below max_target; the gateway's vardiff
// decides the target, so the last one it set goes back.  A max_target
// below that one is accepted all the same (spec 5.3.7), but the crate
// takes no target above max_target any more: its own stands until the
// gateway's SetTarget for the new floor, which the UpdateChannel's answer
// sends before the next job (datum_sv2.c).
int datum_sv2_channel_update(T_DATUM_SV2_CHANNEL_PROTO *ch, float nominal_hash_rate, const unsigned char max_target[32], char error_code[DATUM_SV2_CHANNEL_ERROR_CODE_MAX]) {
	int status = ch->extended ? sv2_sri_extended_channel_update(ch->ext, nominal_hash_rate, max_target) : sv2_sri_standard_channel_update(ch->std, nominal_hash_rate, max_target);
	if (status != SV2_SRI_OK) {
		datum_sv2_channel_error(error_code, status, SV2_ERROR_MAX_TARGET_OUT_OF_RANGE);
		return -1;
	}
	if (compare_hashes(ch->target, max_target) > 0) return 0;
	if (datum_sv2_channel_set_target(ch, ch->target) < 0) {
		datum_sv2_channel_error(error_code, SV2_SRI_ERR_CH_TARGET, SV2_ERROR_MAX_TARGET_OUT_OF_RANGE);
		return -1;
	}
	return 0;
}

int datum_sv2_channel_new_job(T_DATUM_SV2_CHANNEL_PROTO *ch, const T_DATUM_SV2_CHANNEL_JOB *job, uint32_t *job_id, unsigned char *merkle_root) {
	Sv2SriPrebuiltJob j;
	unsigned char root[32];
	int status;
	
	// A job active at once carries its own ntime_start, the min_ntime the
	// miner is sent, and takes shares from there to two hours past it.
	j.has_ntime_start = !job->future;
	j.ntime_start = job->min_ntime;
	j.version = job->version;
	j.coinbase_tx_prefix.data = job->coinbase_prefix;
	j.coinbase_tx_prefix.len = job->coinbase_prefix_len;
	j.coinbase_tx_suffix.data = job->coinbase_suffix;
	j.coinbase_tx_suffix.len = job->coinbase_suffix_len;
	j.merkle_path.data = job->merkle_path;
	j.merkle_path.len = job->merkle_path_count * 32;
	
	if (ch->extended) {
		status = sv2_sri_extended_channel_prebuilt_job(ch->ext, &j, job_id);
	} else {
		status = sv2_sri_standard_channel_prebuilt_job(ch->std, &j, job_id, merkle_root ? merkle_root : root);
	}
	if (status != SV2_SRI_OK) {
		DLOG_ERROR("channels_sv2 refused the job (%d)", status);
		return -1;
	}
	ch->refs[*job_id % SV2_SRI_JOB_REFS].job_id = *job_id;
	ch->refs[*job_id % SV2_SRI_JOB_REFS].ref = job->ref;
	return 0;
}

int datum_sv2_channel_activate_job(T_DATUM_SV2_CHANNEL_PROTO *ch, uint32_t job_id, const unsigned char prev_hash[32], uint32_t nbits, uint32_t min_ntime) {
	int status = ch->extended ? sv2_sri_extended_channel_activate_job(ch->ext, job_id, prev_hash, nbits, min_ntime) : sv2_sri_standard_channel_activate_job(ch->std, job_id, prev_hash, nbits, min_ntime);
	if (status != SV2_SRI_OK) {
		DLOG_ERROR("channels_sv2 refused to activate job %u (%d)", job_id, status);
		return -1;
	}
	return 0;
}

// The difficulty job_id was sent at, from the target the crate holds for
// it, which goes to target; 0 for a job the crate takes no shares on.  The
// gateway sets only DATUM difficulties, powers of two, so a job's target
// gives back exactly the difficulty its coinbase was built with.  Any
// other target is one the crate derived itself after an UpdateChannel,
// which no job is sent under: the share is refused, not credited at a
// guess.
static uint64_t datum_sv2_channel_job_diff(T_DATUM_SV2_CHANNEL_PROTO *ch, uint32_t job_id, unsigned char target[32]) {
	unsigned char t[32];
	uint64_t d;
	int status = ch->extended ? sv2_sri_extended_channel_job_target(ch->ext, job_id, target) : sv2_sri_standard_channel_job_target(ch->std, job_id, target);
	if (status != SV2_SRI_OK) return 0;
	d = datum_sv2_diff_from_max_target(target);
	if (!d || d == DATUM_SV2_DIFF_UNREACHABLE) return 0;
	get_target_from_diff(t, d);
	if (memcmp(t, target, 32) != 0) {
		DLOG_ERROR("channels_sv2 holds job %u at a target that is no DATUM difficulty", job_id);
		return 0;
	}
	return d;
}

void datum_sv2_channel_check_share(T_DATUM_SV2_CHANNEL_PROTO *ch, const T_DATUM_SV2_CHANNEL_SHARE *s, T_DATUM_SV2_CHANNEL_SHARE_RESULT *r) {
	unsigned char job_target[32];
	int status;
	unsigned int slot = s->job_id % SV2_SRI_JOB_REFS;
	
	memset(r, 0, sizeof(*r));
	
	if (ch->extended) {
		Sv2SriSubmitSharesExtended rec;
		rec.channel_id = 0;
		rec.sequence_number = s->sequence_number;
		rec.job_id = s->job_id;
		rec.nonce = s->nonce;
		rec.ntime = s->ntime;
		rec.version = s->version;
		rec.extranonce.data = s->extranonce;
		rec.extranonce.len = s->extranonce_len;
		status = sv2_sri_extended_channel_validate_share(ch->ext, &rec, r->hash, NULL, 0, NULL);
	} else {
		Sv2SriSubmitSharesStandard rec;
		rec.channel_id = 0;
		rec.sequence_number = s->sequence_number;
		rec.job_id = s->job_id;
		rec.nonce = s->nonce;
		rec.ntime = s->ntime;
		rec.version = s->version;
		status = sv2_sri_standard_channel_validate_share(ch->std, &rec, r->hash, NULL, 0, NULL);
	}
	
	// the crate's job ids start at 1, so a cleared ring entry matches
	// nothing; a job the crate has dropped (stale, or past the jobs it
	// keeps) has no target, and the crate's verdict on the share stands
	if (s->job_id && ch->refs[slot].job_id == s->job_id && (r->diff = datum_sv2_channel_job_diff(ch, s->job_id, job_target)) > 0) {
		r->known_job = true;
		r->ref = ch->refs[slot].ref;
		memcpy(r->extranonce, ch->extranonce_prefix, ch->extranonce_prefix_len);
		if (ch->extended && s->extranonce_len == ch->extranonce_size && ch->extranonce_prefix_len + s->extranonce_len <= sizeof(r->extranonce)) {
			memcpy(r->extranonce + ch->extranonce_prefix_len, s->extranonce, s->extranonce_len);
		}
	}
	
	// DATUM takes nothing easier than difficulty 1 as a share or a block
	// (client_mining_submit(), and the default layer): the crate calls any
	// hash under the network target a block, and only regtest's target is
	// easier than that.
	if ((status == SV2_SRI_SHARE_VALID || status == SV2_SRI_SHARE_BLOCK) && (r->hash[28] | r->hash[29] | r->hash[30] | r->hash[31])) {
		strncpy(r->error_code, SV2_ERROR_DIFFICULTY_TOO_LOW, DATUM_SV2_CHANNEL_ERROR_CODE_MAX - 1);
		r->error_code[DATUM_SV2_CHANNEL_ERROR_CODE_MAX - 1] = 0;
		return;
	}
	
	if (status == SV2_SRI_SHARE_VALID || status == SV2_SRI_SHARE_BLOCK) {
		// the gateway needs the job's reference to credit or submit a share;
		// the ring always names the crate's live jobs, so this is defensive
		if (!r->known_job) {
			strncpy(r->error_code, SV2_ERROR_INVALID_JOB_ID, DATUM_SV2_CHANNEL_ERROR_CODE_MAX - 1);
			r->error_code[DATUM_SV2_CHANNEL_ERROR_CODE_MAX - 1] = 0;
			return;
		}
		r->block = status == SV2_SRI_SHARE_BLOCK;
		// The crate checks the network target before the job's and credits
		// a block that misses the job's at the network difficulty.  That
		// only happens where the network target is the easier one, on a
		// test network.  The block goes to the node either way; the share is
		// credited only if it meets its job's target, as in the default
		// layer and on V1, since the pool would refuse it below that.
		if (r->block) {
			if (compare_hashes(r->hash, job_target) > 0) {
				strncpy(r->error_code, SV2_ERROR_DIFFICULTY_TOO_LOW, DATUM_SV2_CHANNEL_ERROR_CODE_MAX - 1);
				r->error_code[DATUM_SV2_CHANNEL_ERROR_CODE_MAX - 1] = 0;
				return;
			}
		}
		r->accepted = true;
		return;
	}
	datum_sv2_channel_error(r->error_code, status, "invalid-share");
	// a panic inside the crate leaves the channel unusable: drop the
	// connection, which frees it
	r->close = status == SV2_SRI_ERR_SHARE_BUDGET || status == SV2_SRI_ERR_INTERNAL;
}

// channels_sv2's rules on this layer's calls are tested where the crate is
// reachable without a node: sri-capi's cargo tests (src/channels/), with a
// hand-built coinbase.  Nothing here needs a test of its own beyond them.
void datum_sv2_channel_tests(void) {
}
