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

// The default build's channel layer (datum_sv2_channel.h): the session id
// is the extranonce prefix, laid out like V1's extranonce1; a job id is
// the gateway's own reference, so the share path finds the DATUM job in it
// without a table; a share is hashed from DATUM's job tables, the way
// client_mining_submit() hashes a V1 share, and checked against the target
// the job was sent at.

// NOTE: Like the rest of DATUM Gateway this assumes a little endian host.

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "datum_conf.h"
#include "datum_stratum.h"
#include "datum_stratum_dupes.h"
#include "datum_sv2.h"
#include "datum_sv2_channel.h"
#include "datum_utils.h"

#include "sv2_msg_mining.h"

// General purpose version bits a miner may roll (BIP 320)
#define SV2_VERSION_ROLLING_MASK 0x1fffe000u

struct T_DATUM_SV2_CHANNEL_PROTO {
	T_DATUM_MINER_DATA *m;
	bool extended;
	unsigned char extranonce_prefix[12];
	unsigned char extranonce_prefix_len;
	uint16_t extranonce_size;
	
	// the target of the jobs that follow; each job keeps its own in the
	// miner data's job tables
	unsigned char target[32];
	
	// job->tsms at the time each job index was sent, so a share against a
	// recycled index is rejected instead of validated against the wrong job
	uint64_t job_tsms_sent[MAX_STRATUM_JOBS];
	
	// the variants of each job index this channel was sent
	// (sv2_job_variant_bit()), so a job id naming another coinbase or flag
	// of the same index is refused like an id never handed out
	uint16_t job_variants_sent[MAX_STRATUM_JOBS];
	
	struct T_DATUM_SV2_CHANNEL_PROTO *next_free;
};

// Channel state is allocated once, at startup, like DATUM's client slots:
// a pool of max_channels entries feeds a free list.
static pthread_mutex_t datum_sv2_channel_lock = PTHREAD_MUTEX_INITIALIZER;
static T_DATUM_SV2_CHANNEL_PROTO *datum_sv2_channel_free = NULL;

int datum_sv2_channel_layer_init(int max_threads, int max_channels) {
	T_DATUM_SV2_CHANNEL_PROTO *pool;
	int i;
	(void)max_threads;
	pool = calloc((size_t)max_channels, sizeof(*pool));
	if (!pool) return -1;
	for (i = max_channels - 1; i >= 0; i--) {
		pool[i].next_free = datum_sv2_channel_free;
		datum_sv2_channel_free = &pool[i];
	}
	return 0;
}

int datum_sv2_channel_thread_init(int thread_id) {
	(void)thread_id;
	return 0;
}

static void datum_sv2_channel_error(char *error_code, const char *code) {
	strncpy(error_code, code, DATUM_SV2_CHANNEL_ERROR_CODE_MAX - 1);
	error_code[DATUM_SV2_CHANNEL_ERROR_CODE_MAX - 1] = 0;
}

// One bit per variant of a job index: bit 2 * coinbase + quickdiff, with
// the empty (subsidy-only) coinbase after the last coinbase index.
#if (MAX_COINBASE_TYPES + 1) * 2 > 16
#error "job_variants_sent needs a wider type for this many coinbase types"
#endif
static uint16_t sv2_job_variant_bit(unsigned int cbidx, unsigned int flags) {
	unsigned int base = (flags & DATUM_SV2_JOB_FLAG_EMPTY) ? MAX_COINBASE_TYPES : cbidx;
	return (uint16_t)(1u << ((base << 1) | ((flags & DATUM_SV2_JOB_FLAG_QUICKDIFF) ? 1u : 0u)));
}

T_DATUM_SV2_CHANNEL_PROTO *datum_sv2_channel_open(int thread_id, T_DATUM_MINER_DATA *m, const T_DATUM_SV2_CHANNEL_OPEN *o, char error_code[DATUM_SV2_CHANNEL_ERROR_CODE_MAX]) {
	T_DATUM_SV2_CHANNEL_PROTO *ch;
	uint32_t sid = o->channel_id;
	uint32_t sid_inv;
	
	(void)thread_id;
	pthread_mutex_lock(&datum_sv2_channel_lock);
	ch = datum_sv2_channel_free;
	if (ch) datum_sv2_channel_free = ch->next_free;
	pthread_mutex_unlock(&datum_sv2_channel_lock);
	if (!ch) {
		// the pool holds max_clients entries and the gateway counts its
		// channels against the same limit first, so this does not happen
		datum_sv2_channel_error(error_code, "channel-limit-reached");
		return NULL;
	}
	
	memset(ch, 0, sizeof(*ch));
	ch->m = m;
	ch->extended = o->extended;
	
	// the session id is the extranonce prefix, laid out exactly like V1's
	// extranonce1: the id's bytes in reverse order
	sid_inv = ((sid >> 24) & 0xff) | (((sid >> 16) & 0xff) << 8) | (((sid >> 8) & 0xff) << 16) | ((sid & 0xff) << 24);
	pk_u32le(ch->extranonce_prefix, 0, sid_inv);
	if (o->extended) {
		ch->extranonce_prefix_len = 4;
		ch->extranonce_size = 8;
	} else {
		// the fixed half of a standard channel's extranonce is random so two
		// channels in the same slot never repeat work
		sv2_crypto_random(ch->extranonce_prefix + 4, 8);
		ch->extranonce_prefix_len = 12;
		ch->extranonce_size = 0;
	}
	memcpy(ch->target, o->target, 32);
	return ch;
}

void datum_sv2_channel_close(T_DATUM_SV2_CHANNEL_PROTO *ch) {
	if (!ch) return;
	pthread_mutex_lock(&datum_sv2_channel_lock);
	ch->next_free = datum_sv2_channel_free;
	datum_sv2_channel_free = ch;
	pthread_mutex_unlock(&datum_sv2_channel_lock);
}

const unsigned char *datum_sv2_channel_extranonce_prefix(const T_DATUM_SV2_CHANNEL_PROTO *ch, unsigned int *len) {
	*len = ch->extranonce_prefix_len;
	return ch->extranonce_prefix;
}

uint16_t datum_sv2_channel_extranonce_size(const T_DATUM_SV2_CHANNEL_PROTO *ch) {
	return ch->extranonce_size;
}

int datum_sv2_channel_set_target(T_DATUM_SV2_CHANNEL_PROTO *ch, const unsigned char target[32]) {
	memcpy(ch->target, target, 32);
	return 0;
}

// The gateway checks max_target against what a 64-bit difficulty reaches
// before asking; nothing is kept here.
int datum_sv2_channel_update(T_DATUM_SV2_CHANNEL_PROTO *ch, float nominal_hash_rate, const unsigned char max_target[32], char error_code[DATUM_SV2_CHANNEL_ERROR_CODE_MAX]) {
	(void)ch;
	(void)nominal_hash_rate;
	(void)max_target;
	(void)error_code;
	return 0;
}

// The merkle root of a block whose coinbase hashes to cb_hash, from the
// path the job carries
static void sv2_merkle_root_from_path(const unsigned char *cb_hash, const unsigned char *path, unsigned int count, unsigned char *out) {
	unsigned char pair[64];
	unsigned int i;
	memcpy(out, cb_hash, 32);
	for (i = 0; i < count; i++) {
		memcpy(pair, out, 32);
		memcpy(pair + 32, path + (size_t)i * 32, 32);
		double_sha256(out, pair, 64);
	}
}

// The job id is the gateway's reference itself (datum_sv2_job_id_pack()):
// the DATUM job index, the coinbase index and the quick diff and empty
// flags, which the share path needs to find the job again.
int datum_sv2_channel_new_job(T_DATUM_SV2_CHANNEL_PROTO *ch, const T_DATUM_SV2_CHANNEL_JOB *job, uint32_t *job_id, unsigned char *merkle_root) {
	unsigned int gidx, cbidx, flags;
	T_DATUM_STRATUM_JOB *j;
	
	if (!datum_sv2_job_id_unpack(job->ref, &gidx, &cbidx, &flags)) return -1;
	j = global_cur_stratum_jobs[gidx];
	if (!j) return -1;
	
	*job_id = job->ref;
	if (ch->job_tsms_sent[gidx] != j->tsms) {
		ch->job_tsms_sent[gidx] = j->tsms;
		ch->job_variants_sent[gidx] = 0;
	}
	ch->job_variants_sent[gidx] |= sv2_job_variant_bit(cbidx, flags);
	if (flags & DATUM_SV2_JOB_FLAG_QUICKDIFF) {
		memcpy(ch->m->quickdiff_target, ch->target, 32);
	} else {
		memcpy(ch->m->stratum_job_targets[gidx], ch->target, 32);
	}
	
	if (!ch->extended && merkle_root) {
		// Standard channel: the whole extranonce is fixed, so the merkle
		// root is ours to compute.
		unsigned char full_cb[MAX_COINBASE_TXN_SIZE_BYTES];
		unsigned char cb_hash[32];
		size_t len = (size_t)job->coinbase_prefix_len + 12 + job->coinbase_suffix_len;
		if (len > sizeof(full_cb)) return -1;
		memcpy(full_cb, job->coinbase_prefix, job->coinbase_prefix_len);
		memcpy(full_cb + job->coinbase_prefix_len, ch->extranonce_prefix, 12);
		memcpy(full_cb + job->coinbase_prefix_len + 12, job->coinbase_suffix, job->coinbase_suffix_len);
		double_sha256(cb_hash, full_cb, len);
		sv2_merkle_root_from_path(cb_hash, job->merkle_path, job->merkle_path_count, merkle_root);
	}
	return 0;
}

// The gateway sends SetNewPrevHash itself and keeps the tip it activated;
// the jobs of the previous tip are refused through job->is_stale_prevblock
// and the job age, which the gateway checks after this layer.
int datum_sv2_channel_activate_job(T_DATUM_SV2_CHANNEL_PROTO *ch, uint32_t job_id, const unsigned char prev_hash[32], uint32_t nbits, uint32_t min_ntime) {
	(void)ch;
	(void)job_id;
	(void)prev_hash;
	(void)nbits;
	(void)min_ntime;
	return 0;
}

// The checks client_mining_submit() makes, in the same order, from binary
// inputs.  The gateway repeats the template rules after this layer for
// the SRI build's sake; here they have already passed.
void datum_sv2_channel_check_share(T_DATUM_SV2_CHANNEL_PROTO *ch, const T_DATUM_SV2_CHANNEL_SHARE *s, T_DATUM_SV2_CHANNEL_SHARE_RESULT *r) {
	T_DATUM_MINER_DATA *m = ch->m;
	T_DATUM_STRATUM_JOB *job;
	T_DATUM_STRATUM_COINBASE *cb;
	unsigned int gidx, cbidx, flags;
	bool quickdiff, empty_work;
	unsigned char block_header[80];
	unsigned char digest_temp[32];
	unsigned char full_cb_txn[MAX_COINBASE_TXN_SIZE_BYTES];
	uint64_t extranonce_aligned[2];
	size_t cb_len;
	
	memset(r, 0, sizeof(*r));
	
	if (!datum_sv2_job_id_unpack(s->job_id, &gidx, &cbidx, &flags)) {
		datum_sv2_channel_error(r->error_code, SV2_ERROR_INVALID_JOB_ID);
		return;
	}
	quickdiff = (flags & DATUM_SV2_JOB_FLAG_QUICKDIFF) != 0;
	empty_work = (flags & DATUM_SV2_JOB_FLAG_EMPTY) != 0;
	job = global_cur_stratum_jobs[gidx];
	if (!job || ch->job_tsms_sent[gidx] != job->tsms || !(ch->job_variants_sent[gidx] & sv2_job_variant_bit(cbidx, flags))) {
		datum_sv2_channel_error(r->error_code, SV2_ERROR_INVALID_JOB_ID);
		return;
	}
	r->known_job = true;
	r->ref = s->job_id;
	// the difficulty the share is hashed at below: the index's current one,
	// so a share on an earlier sending of the index at another difficulty
	// fails the hash, as in V1
	r->diff = quickdiff ? m->quickdiff_value : m->stratum_job_diffs[gidx];
	
	if ((s->version & ~SV2_VERSION_ROLLING_MASK) != (job->version_uint & ~SV2_VERSION_ROLLING_MASK)) {
		datum_sv2_channel_error(r->error_code, "invalid-version");
		return;
	}
	
	// extranonce: the prefix, then the miner's rollable bytes
	if (ch->extended) {
		if (s->extranonce_len != ch->extranonce_size) {
			datum_sv2_channel_error(r->error_code, "invalid-extranonce-size");
			return;
		}
		memcpy(r->extranonce, ch->extranonce_prefix, 4);
		memcpy(r->extranonce + 4, s->extranonce, 8);
	} else {
		memcpy(r->extranonce, ch->extranonce_prefix, 12);
	}
	
	cb = empty_work ? &job->subsidy_only_coinbase : &job->coinbase[cbidx];
	
	// Mirrors client_mining_submit(): never-generated coinbase slots have
	// coinb1_len == 0, and quickdiff patches at coinb1_len - 2, so a share
	// against an empty slot would read before the buffer.
	if (cb->coinb1_len < 2) {
		datum_sv2_channel_error(r->error_code, SV2_ERROR_INVALID_JOB_ID);
		return;
	}
	
	pk_u32le(block_header, 0, s->version);
	memcpy(&block_header[4], job->prevhash_bin, 32);
	
	memcpy(&full_cb_txn[0], cb->coinb1_bin, cb->coinb1_len);
	memcpy(&full_cb_txn[cb->coinb1_len], r->extranonce, 12);
	memcpy(&full_cb_txn[cb->coinb1_len + 12], cb->coinb2_bin, cb->coinb2_len);
	cb_len = cb->coinb1_len + 12 + cb->coinb2_len;
	
	if (quickdiff) {
		if (upk_u16le(full_cb_txn, cb->coinb1_len - 2) != 0x5144) {
			pk_u16le(full_cb_txn, cb->coinb1_len - 2, 0x5144);
		} else {
			pk_u16le(full_cb_txn, cb->coinb1_len - 2, 0xAEBB);
		}
		full_cb_txn[job->target_pot_index] = floorPoT(m->quickdiff_value);
	} else {
		full_cb_txn[job->target_pot_index] = floorPoT(m->stratum_job_diffs[gidx]);
	}
	
	if (job->merklebranch_count && !empty_work) {
		double_sha256(digest_temp, full_cb_txn, cb_len);
		stratum_job_merkle_root_calc(job, digest_temp, &block_header[36]);
	} else {
		double_sha256(&block_header[36], full_cb_txn, cb_len);
	}
	
	pk_u32le(block_header, 68, s->ntime);
	memcpy(&block_header[72], &job->nbits_bin[0], sizeof(uint32_t));
	pk_u32le(block_header, 76, s->nonce);
	
	my_sha256(digest_temp, block_header, 80);
	my_sha256(r->hash, digest_temp, 32);
	
	if (upk_u32le(r->hash, 28) != 0) {
		datum_sv2_channel_error(r->error_code, SV2_ERROR_DIFFICULTY_TOO_LOW);
		return;
	}
	
	r->block = compare_hashes(r->hash, job->block_target) <= 0;
	
	// A block is submitted whatever follows, as V1 does.  The template
	// rules come before the duplicate table, as in V1: the table's cleanup
	// stops at the first entry with ntime 0, so a refused share with ntime
	// 0 (or ~0 on quickdiff) must never be stored.
	if (job->is_stale_prevblock) {
		datum_sv2_channel_error(r->error_code, SV2_ERROR_STALE_SHARE);
		return;
	}
	if (s->ntime < job->block_template->mintime) {
		datum_sv2_channel_error(r->error_code, "time-too-old");
		return;
	}
	if (s->ntime > (job->block_template->curtime + 7200)) {
		datum_sv2_channel_error(r->error_code, "time-too-new");
		return;
	}
	
	if (compare_hashes(r->hash, quickdiff ? m->quickdiff_target : m->stratum_job_targets[gidx]) > 0) {
		datum_sv2_channel_error(r->error_code, SV2_ERROR_DIFFICULTY_TOO_LOW);
		return;
	}
	
	if (m->sdata->loop_tsms > (job->tsms + ((datum_config.stratum_v1_share_stale_seconds + datum_config.bitcoind_work_update_seconds) * 1000))) {
		datum_sv2_channel_error(r->error_code, SV2_ERROR_STALE_SHARE);
		return;
	}
	
	// the dupe table reads the extranonce as a uint64_t and a uint32_t;
	// r->extranonce sits at no 8 byte boundary in the result
	memcpy(extranonce_aligned, r->extranonce, 12);
	if (datum_stratum_check_for_dupe(m->sdata, s->nonce, (unsigned short)gidx, quickdiff ? (~s->ntime) : s->ntime, s->version, (unsigned char *)extranonce_aligned)) {
		datum_sv2_channel_error(r->error_code, "duplicate-share");
		return;
	}
	
	r->accepted = true;
}

/////////////////////////////////
// Self-tests (datum_gateway --test)
/////////////////////////////////

static void sv2_test_share(T_DATUM_SV2_CHANNEL_PROTO *ch, uint32_t job_id, uint32_t version, T_DATUM_SV2_CHANNEL_SHARE_RESULT *r) {
	static const unsigned char rollable[8] = { 0 };
	T_DATUM_SV2_CHANNEL_SHARE s;
	
	memset(&s, 0, sizeof(s));
	s.job_id = job_id;
	s.version = version;
	s.extranonce = rollable;
	s.extranonce_len = sizeof(rollable);
	datum_sv2_channel_check_share(ch, &s, r);
}

// A job id names one variant of a job index (a coinbase, or the empty
// one, with or without quick diff): a channel takes shares only on the
// variants it was sent, until the index is recycled, and a share comes
// back with the difficulty its job was sent at.  None of these shares
// meets a target, so each stops at the hash.
void datum_sv2_channel_tests(void) {
	static T_DATUM_STRATUM_JOB job;
	static T_DATUM_MINER_DATA m;
	const unsigned int gidx = 7;
	T_DATUM_SV2_CHANNEL_OPEN o;
	T_DATUM_SV2_CHANNEL_PROTO *ch;
	T_DATUM_SV2_CHANNEL_JOB sj;
	T_DATUM_SV2_CHANNEL_SHARE_RESULT r;
	unsigned char target[32];
	char error_code[DATUM_SV2_CHANNEL_ERROR_CODE_MAX];
	uint32_t job_id;
	int i;
	
	datum_test(datum_sv2_channel_layer_init(1, 1) == 0);
	memset(target, 0xFF, sizeof(target));
	memset(&o, 0, sizeof(o));
	o.extended = true;
	o.channel_id = 0x12345678;
	o.user_identity = "test";
	o.max_target = target;
	o.target = target;
	ch = datum_sv2_channel_open(0, &m, &o, error_code);
	datum_test(ch != NULL);
	if (!ch) return;
	
	job.tsms = 1000;
	job.global_index = (int)gidx;
	job.version_uint = 0x20000000;
	for (i = 0; i < MAX_COINBASE_TYPES; i++) {
		job.coinbase[i].coinb1_len = 8;
		job.coinbase[i].coinb2_len = 4;
	}
	job.subsidy_only_coinbase.coinb1_len = 8;
	job.subsidy_only_coinbase.coinb2_len = 4;
	global_cur_stratum_jobs[gidx] = &job;
	
	memset(&sj, 0, sizeof(sj));
	sj.ref = datum_sv2_job_id_pack(gidx, 0, 0);
	sj.diff = 1000;
	datum_test(datum_sv2_channel_new_job(ch, &sj, &job_id, NULL) == 0 && job_id == sj.ref);
	m.stratum_job_diffs[gidx] = 1000;
	
	sv2_test_share(ch, datum_sv2_job_id_pack(gidx, 0, 0), job.version_uint, &r);
	datum_test(r.known_job && r.ref == datum_sv2_job_id_pack(gidx, 0, 0) && r.diff == 1000 && !r.accepted);
	
	// another coinbase, the quick diff tail or the empty coinbase of the
	// same index were never sent
	sv2_test_share(ch, datum_sv2_job_id_pack(gidx, 1, 0), job.version_uint, &r);
	datum_test(!r.known_job && !strcmp(r.error_code, SV2_ERROR_INVALID_JOB_ID));
	sv2_test_share(ch, datum_sv2_job_id_pack(gidx, 0, DATUM_SV2_JOB_FLAG_QUICKDIFF), job.version_uint, &r);
	datum_test(!r.known_job);
	sv2_test_share(ch, datum_sv2_job_id_pack(gidx, 255, DATUM_SV2_JOB_FLAG_EMPTY), job.version_uint, &r);
	datum_test(!r.known_job);
	
	// the quick diff variant once sent, at its own difficulty; the first
	// sending still stands
	sj.ref = datum_sv2_job_id_pack(gidx, 0, DATUM_SV2_JOB_FLAG_QUICKDIFF);
	sj.diff = 2048;
	datum_test(datum_sv2_channel_new_job(ch, &sj, &job_id, NULL) == 0);
	m.quickdiff_value = 2048;
	sv2_test_share(ch, datum_sv2_job_id_pack(gidx, 0, DATUM_SV2_JOB_FLAG_QUICKDIFF), job.version_uint, &r);
	datum_test(r.known_job && r.diff == 2048);
	sv2_test_share(ch, datum_sv2_job_id_pack(gidx, 0, 0), job.version_uint, &r);
	datum_test(r.known_job && r.diff == 1000);
	
	// a recycled index forgets every variant sent for the old job
	job.tsms = 2000;
	sv2_test_share(ch, datum_sv2_job_id_pack(gidx, 0, 0), job.version_uint, &r);
	datum_test(!r.known_job);
	sj.ref = datum_sv2_job_id_pack(gidx, 1, 0);
	sj.diff = 1000;
	datum_test(datum_sv2_channel_new_job(ch, &sj, &job_id, NULL) == 0);
	sv2_test_share(ch, datum_sv2_job_id_pack(gidx, 1, 0), job.version_uint, &r);
	datum_test(r.known_job);
	sv2_test_share(ch, datum_sv2_job_id_pack(gidx, 0, DATUM_SV2_JOB_FLAG_QUICKDIFF), job.version_uint, &r);
	datum_test(!r.known_job);
	
	// version bits outside BIP 320's mask are refused for a known job
	sv2_test_share(ch, datum_sv2_job_id_pack(gidx, 1, 0), job.version_uint | 0x00000002, &r);
	datum_test(r.known_job && !r.accepted && !strcmp(r.error_code, "invalid-version"));
	
	global_cur_stratum_jobs[gidx] = NULL;
	datum_sv2_channel_close(ch);
}
