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

// NOTE: Like the rest of DATUM Gateway this assumes a little endian host.

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "datum_blocktemplates.h"
#include "datum_conf.h"
#include "datum_gateway.h"
#include "datum_logger.h"
#include "datum_protocol.h"
#include "datum_sockets.h"
#include "datum_stratum.h"
#include "datum_stratum_dupes.h"
#include "datum_sv2.h"
#include "datum_sv2_channel.h"
#include "datum_utils.h"

#include "sv2_msg_common.h"
#include "sv2_msg_mining.h"

T_DATUM_SOCKET_APP *global_sv2_app = NULL;

static unsigned char sv2_authority_sk[32];
static unsigned char sv2_authority_pk[32];
static char sv2_authority_pk_b58[64];
static bool sv2_authority_ready = false;

// SV2 job IDs are 32 bits per channel.  We pack the same things the V1 job
// ID string carries so a share can be routed back to the DATUM job:
//   bits  0..7   global stratum job index
//   bits  8..15  coinbase index (255 = subsidy-only empty coinbase)
//   bit  16      quick diff job (coinbase tail tweaked, target from quickdiff)
//   bit  17      empty (new block) job
uint32_t datum_sv2_job_id_pack(unsigned int gidx, unsigned int cbidx, unsigned int flags) {
	return ((uint32_t)gidx & 0xFFu) | (((uint32_t)cbidx & 0xFFu) << 8) | (((uint32_t)flags & 0xFFu) << 16);
}

// False for ids that could never have been handed out: unused bits set,
// index out of range, unknown flags, or a coinbase index that does not
// match the empty flag.
bool datum_sv2_job_id_unpack(uint32_t job_id, unsigned int *gidx, unsigned int *cbidx, unsigned int *flags) {
	*gidx = job_id & 0xFFu;
	*cbidx = (job_id >> 8) & 0xFFu;
	*flags = (job_id >> 16) & 0xFFu;
	if (job_id >> 24) return false;
	if (*gidx >= MAX_STRATUM_JOBS) return false;
	if (*flags & ~(unsigned int)(DATUM_SV2_JOB_FLAG_QUICKDIFF | DATUM_SV2_JOB_FLAG_EMPTY)) return false;
	if (*flags & DATUM_SV2_JOB_FLAG_EMPTY) {
		if (*cbidx != 255) return false;
	} else {
		if (*cbidx >= MAX_COINBASE_TYPES) return false;
	}
	return true;
}

/////////////////////////////////
// Authority key
/////////////////////////////////

static int hexnib(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static int load_authority_key(const char *path) {
	char hex[80];
	FILE *f = fopen(path, "r");
	int i, hi, lo;
	
	if (!f) return -1;
	if (!fgets(hex, sizeof(hex), f)) {
		fclose(f);
		sodium_memzero(hex, sizeof(hex));
		return -2;
	}
	fclose(f);
	
	for (i = 0; i < 32; i++) {
		hi = hexnib(hex[i * 2]);
		lo = hexnib(hex[i * 2 + 1]);
		if (hi < 0 || lo < 0) break;
		sv2_authority_sk[i] = (unsigned char)((hi << 4) | lo);
	}
	// the secret's hex goes like save_authority_key()'s copy does
	sodium_memzero(hex, sizeof(hex));
	return (i == 32) ? 0 : -3;
}

static int save_authority_key(const char *path) {
	static const char hexd[] = "0123456789abcdef";
	char hex[66];
	int fd, i;
	ssize_t w;
	
	for (i = 0; i < 32; i++) {
		hex[i * 2] = hexd[sv2_authority_sk[i] >> 4];
		hex[i * 2 + 1] = hexd[sv2_authority_sk[i] & 15];
	}
	hex[64] = '\n';
	hex[65] = 0;
	
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) return -1;
	w = write(fd, hex, 65);
	close(fd);
	sodium_memzero(hex, sizeof(hex));
	return (w == 65) ? 0 : -2;
}

int datum_sv2_init(void) {
	secp256k1_context *secp;
	T_SV2_NOISE_RESPONDER_KEYS probe;
	const char *path = datum_config.stratum_v2_authority_key_file;
	int r;
	
	if (sv2_crypto_init() != SV2_OK) {
		DLOG_FATAL("Could not initialize crypto for Stratum V2");
		return -1;
	}
	
	if (!path[0]) {
		DLOG_FATAL("stratum_v2.authority_key_file must be set");
		return -1;
	}
	
	r = load_authority_key(path);
	if (r == -1 && errno == ENOENT) {
		secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
		r = sv2_noise_responder_keys_init(&probe, secp, NULL, 3600, (uint32_t)time(NULL));
		secp256k1_context_destroy(secp);
		if (r != SV2_OK) {
			DLOG_FATAL("Could not generate a Stratum V2 authority key");
			return -1;
		}
		memcpy(sv2_authority_sk, probe.authority_sk, 32);
		sodium_memzero(&probe, sizeof(probe));
		if (save_authority_key(path) != 0) {
			DLOG_FATAL("Could not write the Stratum V2 authority key to %s: %s", path, strerror(errno));
			return -1;
		}
		DLOG_INFO("Generated a new Stratum V2 authority key in %s", path);
	} else if (r != 0) {
		DLOG_FATAL("Could not read the Stratum V2 authority key from %s (%d)", path, r);
		return -1;
	}
	
	// derive the public key once and keep the text form for logs and the API
	secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	r = sv2_noise_responder_keys_init(&probe, secp, sv2_authority_sk, 3600, (uint32_t)time(NULL));
	secp256k1_context_destroy(secp);
	if (r != SV2_OK) {
		DLOG_FATAL("The Stratum V2 authority key in %s is not a valid secp256k1 secret key", path);
		return -1;
	}
	memcpy(sv2_authority_pk, probe.authority_pk, 32);
	sodium_memzero(&probe, sizeof(probe));
	sv2_noise_authority_pk_to_base58(sv2_authority_pk, sv2_authority_pk_b58, sizeof(sv2_authority_pk_b58));
	sv2_authority_ready = true;
	
	DLOG_INFO("Stratum V2 authority public key: %s", sv2_authority_pk_b58);
	return 0;
}

const char *datum_sv2_authority_pubkey_base58(void) {
	return sv2_authority_ready ? sv2_authority_pk_b58 : "";
}

/////////////////////////////////
// Sending
/////////////////////////////////

// Write buffer room jobs leave free.  Share replies and other short
// answers cannot wait for the buffer to drain (a client whose buffer is
// full is dropped), while a job can (sv2_send_job()).
#define SV2_JOB_RESERVE 4096

// Requests are consumed only while this much of the write buffer is free:
// a burst of them, such as a proxy opening dozens of channels at once, can
// otherwise need more room for its answers than the buffer has.  The rest
// of the burst waits in the client's read buffer, which the socket layer
// keeps filling, until the thread loop has flushed the answers
// (sv2_resume_input()); a client that fills it while its answers are
// stuck is dropped as for any unread input.  Every non-job answer to one
// request fits in it.
#define SV2_REPLY_HEADROOM 2048

// Encrypt the frame in the thread's scratch buffer and queue it on the
// client's write buffer.  Unlike the V1 string sender this never truncates:
// a truncated ciphertext would desynchronise the Noise stream, so a client
// whose buffer is full is dropped instead.
static int sv2_queue_frame(T_DATUM_CLIENT_DATA *c, int frame_len) {
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)c->datum_thread->app_thread_data;
	T_DATUM_SV2_CLIENT *cl = c->app_client_data;
	int n;
	
	if (frame_len < 0) {
		DLOG_ERROR("SV2 frame encode failed (%d) for client %d/%d", frame_len, c->datum_thread->thread_id, c->cid);
		return -1;
	}
	// Check the room before encrypting: encryption consumes a nonce, and a
	// frame that is encrypted but never sent would desynchronise the stream.
	n = (int)sv2_noise_encrypted_frame_size((uint32_t)frame_len);
	if (c->out_buf + n >= CLIENT_BUFFER) {
		DLOG_WARN("SV2 client %d/%d (%s) write buffer full (%d + %d), dropping client", c->datum_thread->thread_id, c->cid, c->rem_host, c->out_buf, n);
		return -1;
	}
	n = sv2_noise_encrypt_frame(&cl->noise, td->frame, (uint32_t)frame_len, td->wire, sizeof(td->wire));
	if (n < 0) {
		DLOG_ERROR("SV2 frame encrypt failed (%d) for client %d/%d", n, c->datum_thread->thread_id, c->cid);
		return -1;
	}
	return datum_socket_send_chars_to_client(c, (char *)td->wire, n) == n ? 0 : -1;
}

static void sv2_kill(T_DATUM_CLIENT_DATA *c) {
	c->kill_request = true;
	c->datum_thread->has_client_kill_request = true;
}

// Queue SetupConnection.Error and let the thread loop drop the client once
// the reply has left the write buffer; returning an error from the receive
// callback would close the socket before the reply is flushed.  flags are
// the requested features we do not support (§3.6.3), 0 for other reasons.
static int sv2_send_setup_error(T_DATUM_CLIENT_DATA *c, const char *code, uint32_t flags) {
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)c->datum_thread->app_thread_data;
	T_DATUM_SV2_CLIENT *cl = c->app_client_data;
	T_SV2_MSG_SETUP_CONNECTION_ERROR e;
	e.flags = flags;
	e.error_code = sv2_str(code);
	if (sv2_queue_frame(c, sv2_msg_setup_connection_error_encode(td->frame, sizeof(td->frame), &e)) < 0) return -1;
	cl->state = DATUM_SV2_STATE_CLOSING;
	return 0;
}

static int sv2_send_open_channel_error(T_DATUM_CLIENT_DATA *c, uint32_t request_id, const char *code) {
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)c->datum_thread->app_thread_data;
	T_SV2_MSG_OPEN_MINING_CHANNEL_ERROR e;
	e.request_id = request_id;
	e.error_code = sv2_str(code);
	return sv2_queue_frame(c, sv2_msg_open_mining_channel_error_encode(td->frame, sizeof(td->frame), &e));
}

static int sv2_send_share_error(T_DATUM_CLIENT_DATA *c, uint32_t channel_id, uint32_t seq, const char *code) {
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)c->datum_thread->app_thread_data;
	T_SV2_MSG_SUBMIT_SHARES_ERROR e;
	e.channel_id = channel_id;
	e.sequence_number = seq;
	e.error_code = sv2_str(code);
	return sv2_queue_frame(c, sv2_msg_submit_shares_error_encode(td->frame, sizeof(td->frame), &e));
}

static int sv2_send_update_channel_error(T_DATUM_CLIENT_DATA *c, uint32_t channel_id, const char *code) {
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)c->datum_thread->app_thread_data;
	T_SV2_MSG_UPDATE_CHANNEL_ERROR e;
	e.channel_id = channel_id;
	e.error_code = sv2_str(code);
	return sv2_queue_frame(c, sv2_msg_update_channel_error_encode(td->frame, sizeof(td->frame), &e));
}

static int sv2_send_close_channel(T_DATUM_CLIENT_DATA *c, uint32_t channel_id, const char *reason) {
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)c->datum_thread->app_thread_data;
	T_SV2_MSG_CLOSE_CHANNEL m;
	m.channel_id = channel_id;
	m.reason_code = sv2_str(reason);
	return sv2_queue_frame(c, sv2_msg_close_channel_encode(td->frame, sizeof(td->frame), &m));
}

// The channel moves to its current difficulty: the jobs that follow are
// built and checked at it.  The miner learns it from the SetTarget frame,
// which is queued apart (sv2_queue_set_target()) because a channel's first
// job has to reach the miner before it.
static int sv2_apply_target(T_DATUM_SV2_CHANNEL *ch) {
	T_DATUM_MINER_DATA *m = &ch->m;
	unsigned char target[32];
	
	if (!m->current_diff) {
		m->current_diff = datum_config.stratum_v1_vardiff_min;
	}
	get_target_from_diff(target, m->current_diff);
	m->last_sent_diff = m->current_diff;
	return datum_sv2_channel_set_target(ch->proto, target);
}

// SetTarget for the difficulty the channel was last moved to
static int sv2_queue_set_target(T_DATUM_CLIENT_DATA *c, T_DATUM_SV2_CHANNEL *ch) {
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)c->datum_thread->app_thread_data;
	T_SV2_MSG_SET_TARGET t;

	t.channel_id = ch->channel_id;
	get_target_from_diff(t.maximum_target, ch->m.last_sent_diff);
	return sv2_queue_frame(c, sv2_msg_set_target_encode(td->frame, sizeof(td->frame), &t));
}

/////////////////////////////////
// Channels
/////////////////////////////////

#define SV2_SESSION_ID_XOR 0xB10CF00Du

// The channel slot sits in bits 12..21 of the session id, next to a client
// slot that has to fit in bits 0..11.
#if MAX_CLIENTS_THREAD > 4096 || MAX_THREADS + 512 > 1024
#error "datum_sv2_session_id() packs the client slot in 12 bits and the thread id, offset by 512, in 10"
#endif

uint32_t datum_sv2_session_id(int thread_id, int cid, int slot) {
	// Same construction as get_new_session_id(), offset so an SV2 thread can
	// never collide with a V1 thread of the same index.  The extranonce
	// prefix is derived from this, and it has to be unique per gateway.
	//   bits  0..11  client slot (below MAX_CLIENTS_THREAD)
	//   bits 12..21  channel slot on the connection.  V1 never sets these:
	//                its client slots are below MAX_CLIENTS_THREAD too.
	//   bits 22..31  thread id + 512 (V1 threads are below MAX_THREADS)
	// Channel slot 0 gives what a connection's only channel always had.
	uint32_t i = ((uint32_t)cid) & 0x00000FFFu;
	i |= (((uint32_t)slot) << 12) & 0x003FF000u;
	i |= (((uint32_t)thread_id + 512u) << 22) & 0xFFC00000u;
	return i ^ SV2_SESSION_ID_XOR;
}

static unsigned int sv2_session_id_slot(uint32_t sid) {
	return ((sid ^ SV2_SESSION_ID_XOR) >> 12) & 0x3FFu;
}

// A client's first channel lives in its client slot; further channels come
// from this pool.  Pool memory is never returned to the system: the API
// reads client data from its own threads without locks, as it does for V1,
// so a channel it is reading must stay valid memory even if it closes
// meanwhile.  Every open channel counts against stratum_v2.max_clients,
// which therefore also bounds the pool.
static pthread_mutex_t sv2_channel_lock = PTHREAD_MUTEX_INITIALIZER;
static T_DATUM_SV2_CHANNEL *sv2_channel_free = NULL;
static int sv2_channels_open = 0;

// NULL when the server already has stratum_v2.max_clients channels open
static T_DATUM_SV2_CHANNEL *sv2_channel_alloc(T_DATUM_SV2_CLIENT *cl) {
	T_DATUM_SV2_CHANNEL *ch = NULL;
	pthread_mutex_lock(&sv2_channel_lock);
	if (sv2_channels_open < datum_config.stratum_v2_max_clients) {
		if (!cl->first_in_use) {
			ch = &cl->first;
			cl->first_in_use = true;
		} else if (sv2_channel_free) {
			// the pool holds max_clients channels, so one is free whenever
			// the count allows
			ch = sv2_channel_free;
			sv2_channel_free = ch->next_free;
		}
		if (ch) sv2_channels_open++;
	}
	pthread_mutex_unlock(&sv2_channel_lock);
	return ch;
}

static void sv2_channel_release(T_DATUM_SV2_CLIENT *cl, T_DATUM_SV2_CHANNEL *ch) {
	pthread_mutex_lock(&sv2_channel_lock);
	sv2_channels_open--;
	if (ch == &cl->first) {
		cl->first_in_use = false;
	} else {
		ch->next_free = sv2_channel_free;
		sv2_channel_free = ch;
	}
	pthread_mutex_unlock(&sv2_channel_lock);
}

// The client's open channel with this id, or NULL
static T_DATUM_SV2_CHANNEL *sv2_channel_find(T_DATUM_CLIENT_DATA *c, uint32_t channel_id) {
	T_DATUM_SV2_CLIENT *cl = c->app_client_data;
	unsigned int slot = sv2_session_id_slot(channel_id);
	T_DATUM_SV2_CHANNEL *ch;
	
	if ((int)slot >= cl->slots_used) return NULL;
	ch = cl->channels[slot];
	if (!ch || !ch->m.subscribed || ch->channel_id != channel_id) return NULL;
	return ch;
}

static void sv2_channel_close(T_DATUM_CLIENT_DATA *c, T_DATUM_SV2_CHANNEL *ch) {
	T_DATUM_SV2_CLIENT *cl = c->app_client_data;
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)c->datum_thread->app_thread_data;
	
	if (!ch->m.subscribed) return;
	ch->m.subscribed = false;
	if (ch->job_pending) {
		ch->job_pending = false;
		cl->pending_jobs--;
	}
	cl->channels[sv2_session_id_slot(ch->channel_id)] = NULL;
	cl->channel_count--;
	if (!cl->channel_count) cl->no_channel_since_tsms = td->sdata.loop_tsms;
	datum_sv2_channel_close(ch->proto);
	ch->proto = NULL;
	sv2_channel_release(cl, ch);
}

T_DATUM_MINER_DATA *datum_sv2_client_next_channel(T_DATUM_CLIENT_DATA *c, int *pos) {
	T_DATUM_SV2_CLIENT *cl = c->app_client_data;
	T_DATUM_SV2_CHANNEL *ch;
	int n = cl->slots_used;
	
	while (*pos >= 0 && *pos < n) {
		ch = cl->channels[(*pos)++];
		if (ch && ch->m.subscribed) return &ch->m;
	}
	return NULL;
}

/////////////////////////////////
// Vardiff
/////////////////////////////////

static int sv2_send_job(T_DATUM_CLIENT_DATA *c, T_DATUM_SV2_CHANNEL *ch, bool activate_prev_hash, bool quickdiff, bool new_block);

// Same policy as stratum_update_vardiff(), per channel, except a quick
// diff bump sends an SV2 job instead of a V1 notify.
static void sv2_update_vardiff(T_DATUM_CLIENT_DATA *c, T_DATUM_SV2_CHANNEL *ch, bool no_quick) {
	T_DATUM_MINER_DATA *m = &ch->m;
	uint64_t delta_tsms;
	uint64_t ms_per_share;
	uint64_t target_ms_share;
	
	if (m->current_diff != m->last_sent_diff) return;
	if ((!no_quick) && (m->share_count_since_snap < (uint64_t)datum_config.stratum_v1_vardiff_quickdiff_count)) return;
	
	delta_tsms = m->sdata->loop_tsms - m->share_snap_tsms;
	
	if (!m->share_count_since_snap) {
		if (delta_tsms > 60000) {
			m->current_diff = m->current_diff >> 1;
			if (m->current_diff < m->forced_high_min_diff) m->current_diff = m->forced_high_min_diff;
			if (m->current_diff < (uint64_t)datum_config.stratum_v1_vardiff_min) m->current_diff = datum_config.stratum_v1_vardiff_min;
			m->share_count_since_snap = 0;
			m->share_diff_since_snap = 0;
			m->share_snap_tsms = m->sdata->loop_tsms;
		}
		return;
	}
	
	if (delta_tsms < 1000) return;
	
	ms_per_share = delta_tsms / m->share_count_since_snap;
	if (!ms_per_share) ms_per_share = 1;
	target_ms_share = (uint64_t)60000 / (uint64_t)datum_config.stratum_v1_vardiff_target_shares_min;
	
	if ((!m->quickdiff_active) && (!no_quick) && (ms_per_share < (target_ms_share / (uint64_t)datum_config.stratum_v1_vardiff_quickdiff_delta))) {
		delta_tsms = roundDownToPowerOfTwo_64((target_ms_share / ms_per_share) * m->current_diff);
		if (delta_tsms < (m->current_diff << 2)) delta_tsms = (m->current_diff << 2);
		m->current_diff = delta_tsms;
		if (sv2_send_job(c, ch, false, true, false) < 0) sv2_kill(c);
		m->share_count_since_snap = 0;
		m->share_diff_since_snap = 0;
		m->share_snap_tsms = m->sdata->loop_tsms;
		return;
	}
	
	if (ms_per_share > (target_ms_share * 2)) {
		m->current_diff = m->current_diff >> 1;
		if (m->current_diff < m->forced_high_min_diff) m->current_diff = m->forced_high_min_diff;
		if (m->current_diff < (uint64_t)datum_config.stratum_v1_vardiff_min) m->current_diff = datum_config.stratum_v1_vardiff_min;
		m->share_count_since_snap = 0;
		m->share_diff_since_snap = 0;
		m->share_snap_tsms = m->sdata->loop_tsms;
		return;
	}
	
	if (m->share_count_since_snap < 16) return;
	
	if (ms_per_share < (target_ms_share / 2)) {
		m->current_diff = m->current_diff << 1;
		m->share_count_since_snap = 0;
		m->share_diff_since_snap = 0;
		m->share_snap_tsms = m->sdata->loop_tsms;
		return;
	}
}

/////////////////////////////////
// Jobs
/////////////////////////////////

// Build the client's coinbase prefix (coinb1 with the PoT difficulty byte
// and, for quick diff jobs, the tweaked tail) into out.  Returns its length.
static int sv2_build_prefix(const T_DATUM_STRATUM_JOB *j, const T_DATUM_STRATUM_COINBASE *cb, uint64_t diff, bool quickdiff, unsigned char *out) {
	memcpy(out, cb->coinb1_bin, cb->coinb1_len);
	out[j->target_pot_index] = floorPoT(diff);
	if (quickdiff) {
		// NOTE: These constants are also used by the DATUM server.  DO NOT CHANGE THEM.
		if (upk_u16le(cb->coinb1_bin, cb->coinb1_len - 2) != 0x5144) {
			pk_u16le(out, cb->coinb1_len - 2, 0x5144);
		} else {
			pk_u16le(out, cb->coinb1_len - 2, 0xAEBB);
		}
	}
	return cb->coinb1_len;
}

// Most write buffer a job can take: SetTarget, the job, SetNewPrevHash
static int sv2_job_wire_size(const T_DATUM_STRATUM_JOB *j, const T_DATUM_STRATUM_COINBASE *cb, bool extended, bool new_block) {
	uint32_t job_len = SV2_FRAME_HEADER_SIZE + 64;
	if (extended) {
		job_len += (new_block ? 0 : (uint32_t)j->merklebranch_count * 32) + cb->coinb1_len + cb->coinb2_len;
	}
	return (int)(sv2_noise_encrypted_frame_size(SV2_FRAME_HEADER_SIZE + 36) + sv2_noise_encrypted_frame_size(job_len) + sv2_noise_encrypted_frame_size(SV2_FRAME_HEADER_SIZE + 48));
}

static void sv2_set_job_pending(T_DATUM_CLIENT_DATA *c, T_DATUM_SV2_CHANNEL *ch, bool pending) {
	T_DATUM_SV2_CLIENT *cl = c->app_client_data;
	if (ch->job_pending == pending) return;
	ch->job_pending = pending;
	if (pending) {
		if (!cl->pending_jobs++) DLOG_DEBUG("SV2 client %d/%d (%s): a job did not fit in the write buffer (%d bytes queued); holding jobs back until it drains", c->datum_thread->thread_id, c->cid, c->rem_host, c->out_buf);
		((T_DATUM_SV2_THREAD_DATA *)c->datum_thread->app_thread_data)->has_pending_jobs = true;
	} else {
		cl->pending_jobs--;
	}
}

// Mirrors send_mining_notify(), for one channel.  activate_prev_hash sends
// the job as a future job followed by SetNewPrevHash, which is how a
// channel gets its first job and how a new block is announced.
static int sv2_send_job(T_DATUM_CLIENT_DATA *c, T_DATUM_SV2_CHANNEL *ch, bool activate_prev_hash, bool quickdiff, bool new_block) {
	T_DATUM_THREAD_DATA *t = c->datum_thread;
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)t->app_thread_data;
	T_DATUM_STRATUM_JOB *j = td->sdata.cur_stratum_job;
	T_DATUM_MINER_DATA *m = &ch->m;
	T_DATUM_STRATUM_COINBASE *cb;
	unsigned char prefix[STRATUM_COINBASE1_MAX_LEN / 2 + 16];
	unsigned char merkle_root[32];
	T_DATUM_SV2_CHANNEL_JOB job;
	unsigned int cbselect;
	unsigned int flags = 0;
	uint32_t job_id, min_ntime;
	int prefix_len, len;
	bool set_target_after_job = false;
	
	if (!j || !ch->m.subscribed) return -1;
	
	if (new_block) {
		quickdiff = false;
		activate_prev_hash = true;
	}
	
	// V1 repeats the prev hash and nbits in every mining.notify, and the
	// template thread waits only for the V1 threads to send the empty
	// new-block job.  An SV2 thread can therefore go straight from the old
	// block's job to the new block's full job; without a SetNewPrevHash the
	// miner would keep hashing on the old prev hash and every share would be
	// rejected.  The same holds for nbits alone, which testnet's
	// minimum-difficulty rule changes without a new block.
	if (!ch->has_active_prevhash || memcmp(ch->active_prevhash, j->prevhash_bin, 32) != 0 || ch->active_nbits != j->nbits_uint) {
		quickdiff = false;
		activate_prev_hash = true;
	}
	
	// The miner starts its ntime at the job's min_ntime, the template's
	// curtime, and the SRI build takes the job's shares up to two hours past
	// it.  A job active at once may not start below its tip, should a
	// template's curtime ever step back.
	min_ntime = (uint32_t)j->block_template->curtime;
	if (!activate_prev_hash && min_ntime < ch->active_min_ntime) min_ntime = ch->active_min_ntime;
	
	// coinbase selection follows the V1 rules exactly
	if (new_block) {
		cbselect = 255;
		cb = &j->subsidy_only_coinbase;
		flags |= DATUM_SV2_JOB_FLAG_EMPTY;
	} else {
		cbselect = 0;
		if (j->job_state >= JOB_STATE_FULL_PRIORITY_WAIT_COINBASER && td->sdata.full_coinbase_ready) {
			cbselect = m->coinbase_selection;
		}
		cb = &j->coinbase[cbselect];
	}
	
	// The write buffer is flushed between thread loop passes, and a round of
	// jobs for many channels on one connection can outgrow it.  A job that
	// does not fit waits for the next pass instead of costing the client its
	// connection, and is then sent as whatever job is current.  Nothing has
	// changed for the channel yet, so a later send starts from scratch.
	if (c->out_buf + sv2_job_wire_size(j, cb, ch->extended, new_block) >= CLIENT_BUFFER - SV2_JOB_RESERVE) {
		ch->job_pending_quickdiff = quickdiff;
		sv2_set_job_pending(c, ch, true);
		return 0;
	}
	sv2_set_job_pending(c, ch, false);
	
	if (!quickdiff) {
		sv2_update_vardiff(c, ch, true);
	}
	if (j->is_datum_job && m->current_diff < datum_config.override_vardiff_min) {
		m->current_diff = datum_config.override_vardiff_min;
	}
	if (m->last_sent_diff != m->current_diff) {
		// The job is built and checked at the new difficulty either way.
		// The miner is normally told first.  Not for a channel's first job,
		// which MUST be the first message after the channel's Success (spec
		// 5.3.15 and 5.3.16): there the SetTarget follows the job, which is a
		// future job, so the new target holds for it, and comes before the
		// SetNewPrevHash that starts the miner on it.  A channel opens at the
		// difficulty of its first job (sv2_open_channel()), so this is only
		// for a first job that had to wait for the write buffer and goes out
		// under another difficulty: the pool's minimum once the job is the
		// pool's, or a vardiff step.
		if (sv2_apply_target(ch) < 0) return -1;
		if (!ch->has_active_prevhash) {
			set_target_after_job = true;
		} else if (sv2_queue_set_target(c, ch) < 0) {
			return -1;
		}
	}
	
	if (!quickdiff) {
		m->stratum_job_diffs[j->global_index] = m->last_sent_diff;
		m->quickdiff_active = false;
	} else {
		m->quickdiff_active = true;
		m->quickdiff_value = m->last_sent_diff;
		flags |= DATUM_SV2_JOB_FLAG_QUICKDIFF;
	}
	
	prefix_len = sv2_build_prefix(j, cb, m->last_sent_diff, quickdiff, prefix);
	ch->job_tsms_sent[j->global_index] = j->tsms;
	
	// The channel layer issues the job id and keeps the job under the
	// channel's current target; the gateway's reference to the DATUM job
	// comes back with every share on it.  A standard channel's merkle root
	// is the layer's too: the whole extranonce is fixed.
	job.future = activate_prev_hash;
	job.min_ntime = min_ntime;
	job.version = j->version_uint;
	job.coinbase_prefix = prefix;
	job.coinbase_prefix_len = (unsigned int)prefix_len;
	job.coinbase_suffix = cb->coinb2_bin;
	job.coinbase_suffix_len = cb->coinb2_len;
	job.merkle_path = (const unsigned char *)j->merklebranches_bin;
	job.merkle_path_count = new_block ? 0 : (unsigned int)j->merklebranch_count;
	job.ref = datum_sv2_job_id_pack(j->global_index, cbselect, flags);
	job.diff = m->last_sent_diff;
	if (datum_sv2_channel_new_job(ch->proto, &job, &job_id, merkle_root) < 0) {
		DLOG_ERROR("SV2 channel %08x of client %s: the channel layer refused job %u/%u", ch->channel_id, c->rem_host, j->global_index, cbselect);
		return -1;
	}
	
	if (ch->extended) {
		T_SV2_MSG_NEW_EXTENDED_MINING_JOB msg;
		msg.channel_id = ch->channel_id;
		msg.job_id = job_id;
		msg.has_min_ntime = !activate_prev_hash;
		msg.min_ntime = min_ntime;
		msg.version = j->version_uint;
		msg.version_rolling_allowed = true;
		msg.merkle_path_count = job.merkle_path_count;
		msg.merkle_path = sv2_bytes(j->merklebranches_bin, (uint32_t)msg.merkle_path_count * 32);
		msg.coinbase_tx_prefix = sv2_bytes(prefix, (uint32_t)prefix_len);
		msg.coinbase_tx_suffix = sv2_bytes(cb->coinb2_bin, (uint32_t)cb->coinb2_len);
		len = sv2_msg_new_extended_mining_job_encode(td->frame, sizeof(td->frame), &msg);
	} else {
		T_SV2_MSG_NEW_MINING_JOB msg;
		msg.channel_id = ch->channel_id;
		msg.job_id = job_id;
		msg.has_min_ntime = !activate_prev_hash;
		msg.min_ntime = min_ntime;
		msg.version = j->version_uint;
		memcpy(msg.merkle_root, merkle_root, 32);
		len = sv2_msg_new_mining_job_encode(td->frame, sizeof(td->frame), &msg);
	}
	if (sv2_queue_frame(c, len) < 0) return -1;
	if (set_target_after_job && sv2_queue_set_target(c, ch) < 0) return -1;
	
	if (activate_prev_hash) {
		T_SV2_MSG_SET_NEW_PREV_HASH p;
		p.channel_id = ch->channel_id;
		p.job_id = job_id;
		memcpy(p.prev_hash, j->prevhash_bin, 32);
		p.min_ntime = min_ntime;
		p.nbits = j->nbits_uint;
		if (datum_sv2_channel_activate_job(ch->proto, job_id, p.prev_hash, p.nbits, p.min_ntime) < 0) return -1;
		if (sv2_queue_frame(c, sv2_msg_set_new_prev_hash_encode(td->frame, sizeof(td->frame), &p)) < 0) return -1;
		memcpy(ch->active_prevhash, j->prevhash_bin, 32);
		ch->active_nbits = j->nbits_uint;
		ch->active_min_ntime = p.min_ntime;
		ch->has_active_prevhash = true;
	}
	
	m->last_sent_stratum_job_index = j->global_index;
	return 0;
}

/////////////////////////////////
// Shares
/////////////////////////////////

// A share on a channel the client does not have is answered by
// sv2_send_share_error() on the channel id it named, and counted nowhere.
static int sv2_reject_share(T_DATUM_CLIENT_DATA *c, T_DATUM_SV2_CHANNEL *ch, uint32_t seq, uint64_t diff, const char *code) {
	ch->m.share_count_rejected++;
	ch->m.share_diff_rejected += diff;
	return sv2_send_share_error(c, ch->channel_id, seq, code);
}

// The SV2 twin of client_mining_submit().  The channel layer checks the
// share against the job it names and the target that job was sent at
// (datum_sv2_channel.h); what follows is DATUM's: the coinbase and header
// the pool submission is made from, the block, the template's stale and
// time rules, and the stats.
static int sv2_handle_share(T_DATUM_CLIENT_DATA *c, T_DATUM_SV2_CHANNEL *ch, uint32_t seq, uint32_t job_id, uint32_t nonce_val, uint32_t ntime_val, uint32_t bver, T_SV2_BYTES extranonce) {
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)c->datum_thread->app_thread_data;
	T_DATUM_MINER_DATA *m = &ch->m;
	T_DATUM_SV2_CHANNEL_SHARE s;
	T_DATUM_SV2_CHANNEL_SHARE_RESULT r;
	T_SV2_MSG_SUBMIT_SHARES_SUCCESS ok;
	T_DATUM_STRATUM_JOB *job;
	T_DATUM_STRATUM_COINBASE *cb;
	unsigned int g_job_index, coinbase_index, flags;
	bool quickdiff, empty_work;
	bool was_block = false;
	unsigned char block_header[80];
	unsigned char digest_temp[32];
	unsigned char full_cb_txn[MAX_COINBASE_TXN_SIZE_BYTES];
	char new_notify_blockhash[65];
	char username_buf[0x100];
	const char *username_s = m->last_auth_username;
	uint64_t job_diff;
	size_t cb_len;
	int i;
	
	s.sequence_number = seq;
	s.job_id = job_id;
	s.nonce = nonce_val;
	s.ntime = ntime_val;
	s.version = bver;
	s.extranonce = extranonce.data;
	s.extranonce_len = extranonce.len;
	datum_sv2_channel_check_share(ch->proto, &s, &r);
	
	if (r.close) {
		// the layer can no longer tell a repeated share from a new one
		DLOG_WARN("SV2 channel %08x of client %s can take no more shares under this block (%s); closing it", ch->channel_id, c->rem_host, r.error_code);
		if (sv2_reject_share(c, ch, seq, m->last_sent_diff, r.error_code) < 0) return -1;
		if (sv2_send_close_channel(c, ch->channel_id, r.error_code) < 0) return -1;
		sv2_channel_close(c, ch);
		return 0;
	}
	
	if (!r.known_job) return sv2_reject_share(c, ch, seq, m->last_sent_diff, r.error_code);
	
	// the job the reference names, unless its index has been recycled since
	if (!datum_sv2_job_id_unpack(r.ref, &g_job_index, &coinbase_index, &flags)) {
		return sv2_reject_share(c, ch, seq, m->last_sent_diff, SV2_ERROR_INVALID_JOB_ID);
	}
	quickdiff = (flags & DATUM_SV2_JOB_FLAG_QUICKDIFF) != 0;
	empty_work = (flags & DATUM_SV2_JOB_FLAG_EMPTY) != 0;
	job = global_cur_stratum_jobs[g_job_index];
	if (!job || ch->job_tsms_sent[g_job_index] != job->tsms) {
		return sv2_reject_share(c, ch, seq, m->last_sent_diff, SV2_ERROR_INVALID_JOB_ID);
	}
	// The difficulty the job was sent at, which its coinbase's difficulty
	// byte and its target were set from.  The index's current one can be
	// higher: quick diff and vardiff send an index again at another
	// difficulty, and the SRI build keeps validating the earlier sending.
	job_diff = r.diff;
	cb = empty_work ? &job->subsidy_only_coinbase : &job->coinbase[coinbase_index];
	if (cb->coinb1_len < 2) return sv2_reject_share(c, ch, seq, job_diff, SV2_ERROR_INVALID_JOB_ID);
	
	// The coinbase and the header the pool submission is made from: the
	// layer's hash is of these bytes.  The merkle root is computed only for
	// a block; the submission needs the fields.
	memcpy(&full_cb_txn[0], cb->coinb1_bin, cb->coinb1_len);
	memcpy(&full_cb_txn[cb->coinb1_len], r.extranonce, 12);
	memcpy(&full_cb_txn[cb->coinb1_len + 12], cb->coinb2_bin, cb->coinb2_len);
	cb_len = cb->coinb1_len + 12 + cb->coinb2_len;
	if (quickdiff) {
		if (upk_u16le(full_cb_txn, cb->coinb1_len - 2) != 0x5144) {
			pk_u16le(full_cb_txn, cb->coinb1_len - 2, 0x5144);
		} else {
			pk_u16le(full_cb_txn, cb->coinb1_len - 2, 0xAEBB);
		}
	}
	full_cb_txn[job->target_pot_index] = floorPoT(job_diff);
	
	pk_u32le(block_header, 0, bver);
	memcpy(&block_header[4], job->prevhash_bin, 32);
	memset(&block_header[36], 0, 32);
	pk_u32le(block_header, 68, ntime_val);
	memcpy(&block_header[72], &job->nbits_bin[0], sizeof(uint32_t));
	pk_u32le(block_header, 76, nonce_val);
	
	if (datum_config.stratum_username_mod) {
		const char *tilde = strchr(username_s, '~');
		if (tilde) {
			const char *modname = &tilde[1];
			const size_t modname_len = strlen(modname);
			const uint16_t share_rnd = upk_u16le(r.hash, 0);
			username_s = datum_stratum_mod_username(username_s, username_buf, sizeof(username_buf), share_rnd, modname, modname_len);
		}
	}
	
	if (r.block) {
		was_block = true;
		if (job->merklebranch_count && !empty_work) {
			double_sha256(digest_temp, full_cb_txn, cb_len);
			stratum_job_merkle_root_calc(job, digest_temp, &block_header[36]);
		} else {
			double_sha256(&block_header[36], full_cb_txn, cb_len);
		}
		new_notify_blockhash[64] = 0;
		for (i = 0; i < 32; i++) {
			uchar_to_hex((char *)&new_notify_blockhash[(31 - i) << 1], r.hash[i]);
		}
		DLOG_WARN("************************************************************************************************");
		DLOG_WARN("******** BLOCK FOUND (SV2) - %s ********", new_notify_blockhash);
		DLOG_WARN("************************************************************************************************");
	
		i = assembleBlockAndSubmit(block_header, full_cb_txn, cb_len, job, &td->sdata, new_notify_blockhash, empty_work);
		if (i) {
			datum_blocktemplates_notifynew(new_notify_blockhash, job->height + 1);
		}
		if (job->is_datum_job) {
			datum_protocol_pow_submit(c, job, username_s, was_block, empty_work, quickdiff, block_header, job_diff, full_cb_txn, cb, r.extranonce, (unsigned char)coinbase_index);
		}
	}
	
	if (!r.accepted) return sv2_reject_share(c, ch, seq, job_diff, r.error_code);
	
	if (job->is_stale_prevblock) return sv2_reject_share(c, ch, seq, job_diff, SV2_ERROR_STALE_SHARE);
	if (ntime_val < job->block_template->mintime) return sv2_reject_share(c, ch, seq, job_diff, "time-too-old");
	if (ntime_val > (job->block_template->curtime + 7200)) return sv2_reject_share(c, ch, seq, job_diff, "time-too-new");
	
	if (m->sdata->loop_tsms > (job->tsms + ((datum_config.stratum_v1_share_stale_seconds + datum_config.bitcoind_work_update_seconds) * 1000))) {
		return sv2_reject_share(c, ch, seq, job_diff, SV2_ERROR_STALE_SHARE);
	}
	
	if (!was_block && job->is_datum_job) {
		datum_protocol_pow_submit(c, job, username_s, was_block, empty_work, quickdiff, block_header, job_diff, full_cb_txn, cb, r.extranonce, (unsigned char)coinbase_index);
	}
	
	ok.channel_id = ch->channel_id;
	ok.last_sequence_number = seq;
	ok.new_submits_accepted_count = 1;
	ok.new_shares_sum = job_diff;
	if (sv2_queue_frame(c, sv2_msg_submit_shares_success_encode(td->frame, sizeof(td->frame), &ok)) < 0) return -1;
	
	m->share_diff_accepted += job_diff;
	m->share_count_accepted++;
	m->share_count_since_snap++;
	m->share_diff_since_snap += job_diff;
	
	stratum_update_miner_stats_accepted(m, job_diff);
	sv2_update_vardiff(c, ch, false);
	return 0;
}

/////////////////////////////////
// Connection setup and channels
/////////////////////////////////

// Difficulty implied by a miner's max_target (the hardest work it will
// accept), as a power of two (DATUM's difficulties are) whose target does
// not exceed it: SetTarget.target MUST NOT exceed the max_target accepted
// for the channel (spec 5.3.21), so the work handed out is never easier
// than asked.
uint64_t datum_sv2_diff_from_max_target(const unsigned char max_target[32]) {
	unsigned char t[32];
	uint64_t d;
	int hb = -1, i, b;
	for (i = 31; i >= 0 && hb < 0; i--) {
		for (b = 7; b >= 0; b--) {
			if (max_target[i] & (1 << b)) {
				hb = i * 8 + b;
				break;
			}
		}
	}
	// difficulty 1 has its highest bit at 223 (0x00000000FFFF0000...);
	// anything easier than that is "no floor", and nothing is at or
	// below zero
	if (hb < 0) return DATUM_SV2_DIFF_UNREACHABLE;
	if (hb > 223) return 0;
	if (223 - hb > 63) return DATUM_SV2_DIFF_UNREACHABLE;
	d = (uint64_t)1 << (223 - hb);
	// the highest bit alone rounds the difficulty down, and that
	// difficulty's target can still be above max_target (0x5555... has
	// the top bit of difficulty 2, whose target 0x7FFF8000... is easier);
	// the next power of two is always below it
	get_target_from_diff(t, d);
	if (compare_hashes(t, max_target) > 0) {
		if (d == (uint64_t)1 << 63) return DATUM_SV2_DIFF_UNREACHABLE;
		d <<= 1;
	}
	return d;
}

// addr_2_output_script() takes mainnet and testnet addresses alike, so the
// network comes from the prefix: bc1, 1 and 3 are mainnet
static bool sv2_address_is_mainnet(const char *addr) {
	return !strncmp(addr, "bc1", 3) || addr[0] == '1' || addr[0] == '3';
}

bool datum_sv2_username_is_address(const char *username, const char *pool_address) {
	char addr[128];
	unsigned char script[64];
	const size_t len = strcspn(username, ".~");
	
	if (!len || len >= sizeof(addr)) return false;
	memcpy(addr, username, len);
	addr[len] = 0;
	if (!addr_2_output_script(addr, script, sizeof(script))) return false;
	return sv2_address_is_mainnet(addr) == sv2_address_is_mainnet(pool_address);
}

static int sv2_handle_setup_connection(T_DATUM_CLIENT_DATA *c, const T_SV2_MSG_SETUP_CONNECTION *m) {
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)c->datum_thread->app_thread_data;
	T_DATUM_SV2_CLIENT *cl = c->app_client_data;
	T_DATUM_MINER_DATA *fm = &cl->first.m;
	T_SV2_MSG_SETUP_CONNECTION_SUCCESS ok;
	char vendor[64], firmware[64];
	char raw[130];
	
	if (cl->state != DATUM_SV2_STATE_SETUP) return -1;
	
	if (m->protocol != SV2_PROTOCOL_MINING) return sv2_send_setup_error(c, SV2_ERROR_UNSUPPORTED_PROTOCOL, 0);
	if (m->min_version > SV2_PROTOCOL_VERSION || m->max_version < SV2_PROTOCOL_VERSION) return sv2_send_setup_error(c, SV2_ERROR_PROTOCOL_VERSION_MISMATCH, 0);
	if (m->flags & SV2_SETUP_FLAG_REQUIRES_WORK_SELECTION) return sv2_send_setup_error(c, SV2_ERROR_UNSUPPORTED_FEATURE_FLAGS, SV2_SETUP_FLAG_REQUIRES_WORK_SELECTION);
	
	// Strings from the wire are only used after the same character filter
	// V1 applies to user agents, so they cannot forge log lines.
	vendor[0] = 0;
	firmware[0] = 0;
	if (sv2_str_copy(raw, sizeof(raw), m->vendor)) strncpy_uachars(vendor, raw, sizeof(vendor) - 1);
	if (sv2_str_copy(raw, sizeof(raw), m->firmware)) strncpy_uachars(firmware, raw, sizeof(firmware) - 1);
	vendor[sizeof(vendor) - 1] = 0;
	firmware[sizeof(firmware) - 1] = 0;
	
	// Feed the V1 fingerprinting the same way a user agent would, so the
	// coinbase size and any per-model minimum difficulty carry over.  No
	// channel is open yet, so the first channel's miner data is free to
	// work in; every channel starts from what it ends up with.
	snprintf(fm->useragent, sizeof(fm->useragent), "%s %s", vendor, firmware);
	fm->coinbase_selection = 2;
	fm->current_diff = datum_config.stratum_v1_vardiff_min;
	fm->forced_high_min_diff = 0;
	if (datum_config.stratum_v1_fingerprint_miners) {
		if (strncasecmp(vendor, "bitaxe", 6) == 0) {
			// ESP-Miner drops the connection on any SV2 frame larger than
			// its receive buffer: 2 KB up to 2.14, 8 KB from 2.15.  It sends
			// no firmware version, so every Bitaxe gets the 500 byte
			// coinbase, whose largest job (24 merkle branches) stays under
			// 2 KB.  The 2.25 KB one made OCEAN's jobs 2237 bytes on 2.14.2.
			// Not the 755 byte one: it carries the extranonce in an OP_RETURN
			// output, and ESP-Miner reads the payouts it shows right after
			// an extranonce that ends the scriptSig, as SV2 lays it out.
			fm->coinbase_selection = 1;
		} else {
			datum_stratum_fingerprint_by_UA(fm);
		}
		if (fm->current_diff < (uint64_t)datum_config.stratum_v1_vardiff_min) fm->current_diff = datum_config.stratum_v1_vardiff_min;
	}
	memcpy(cl->useragent, fm->useragent, sizeof(cl->useragent));
	cl->coinbase_selection = fm->coinbase_selection;
	cl->start_diff = fm->current_diff;
	cl->fingerprint_min_diff = fm->forced_high_min_diff;
	
	cl->setup_flags = m->flags;
	cl->state = DATUM_SV2_STATE_READY;
	DLOG_DEBUG("SV2 SetupConnection from %s: vendor=\"%s\" firmware=\"%s\" flags=0x%x", c->rem_host, vendor, firmware, m->flags);
	
	ok.used_version = SV2_PROTOCOL_VERSION;
	ok.flags = 0;
	return sv2_queue_frame(c, sv2_msg_setup_connection_success_encode(td->frame, sizeof(td->frame), &ok));
}

static int sv2_open_channel(T_DATUM_CLIENT_DATA *c, uint32_t request_id, T_SV2_BYTES user_identity, float nominal_hash_rate, const unsigned char max_target[32], uint16_t min_extranonce_size, bool extended) {
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)c->datum_thread->app_thread_data;
	T_DATUM_SV2_CLIENT *cl = c->app_client_data;
	const int max_channels = datum_config.stratum_v2_max_channels_per_connection;
	T_DATUM_SV2_CHANNEL *ch;
	T_DATUM_MINER_DATA *m;
	T_DATUM_SV2_CHANNEL_OPEN o;
	char username[sizeof(ch->m.last_auth_username)];
	char error_code[DATUM_SV2_CHANNEL_ERROR_CODE_MAX];
	unsigned char target[32];
	const unsigned char *prefix;
	unsigned int prefix_len;
	uint32_t sid;
	uint64_t d, max_diff;
	int len, slot, i;
	
	if (cl->state != DATUM_SV2_STATE_READY) return -1;
	// The refusals are what a misconfigured SRI Translator Proxy runs into,
	// and it exits on them, so say why here.
	if (cl->channel_count >= max_channels) {
		DLOG_INFO("SV2 client %s asked for more than %d channels on one connection (stratum_v2.max_channels_per_connection)", c->rem_host, max_channels);
		return sv2_send_open_channel_error(c, request_id, "channel-limit-reached");
	}
	if (extended && min_extranonce_size > 8) {
		DLOG_WARN("SV2 client %s asked for %u rollable extranonce bytes; DATUM rolls 8 (SRI Translator Proxy: downstream_extranonce2_size at most 6)", c->rem_host, (unsigned int)min_extranonce_size);
		return sv2_send_open_channel_error(c, request_id, "extranonce-size-unsupported");
	}
	max_diff = datum_sv2_diff_from_max_target(max_target);
	if (max_diff == DATUM_SV2_DIFF_UNREACHABLE) {
		DLOG_WARN("SV2 client %s asked for a max_target no difficulty meets", c->rem_host);
		return sv2_send_open_channel_error(c, request_id, SV2_ERROR_MAX_TARGET_OUT_OF_RANGE);
	}
	if (!sv2_str_copy(username, sizeof(username), user_identity) || !username[0]) {
		return sv2_send_open_channel_error(c, request_id, SV2_ERROR_UNKNOWN_USER);
	}
	if (datum_config.stratum_v2_require_address_usernames && !datum_sv2_username_is_address(username, datum_config.mining_pool_address)) {
		DLOG_INFO("SV2 client %s asked for a channel as \"%s\", which is not a Bitcoin address on this network (stratum_v2.require_address_usernames)", c->rem_host, username);
		return sv2_send_open_channel_error(c, request_id, SV2_ERROR_UNKNOWN_USER);
	}
	
	// The next free slot after the last one handed out, so a slot, and with
	// it a channel id and an extranonce prefix, comes back as late as
	// possible after its channel closes.  One exists: fewer than
	// max_channels are open.
	slot = cl->next_slot;
	for (i = 0; i < max_channels; i++) {
		slot = (cl->next_slot + i) % max_channels;
		if (!cl->channels[slot]) break;
	}
	
	ch = sv2_channel_alloc(cl);
	if (!ch) {
		DLOG_INFO("SV2 client %s asked for a channel, but the server has stratum_v2.max_clients (%d) channels open", c->rem_host, datum_config.stratum_v2_max_clients);
		return sv2_send_open_channel_error(c, request_id, "channel-limit-reached");
	}
	
	// a fresh miner, with what the connection told us about the device
	memset(ch, 0, sizeof(*ch));
	m = &ch->m;
	m->sdata = &td->sdata;
	m->unique_id = cl->unique_id;
	m->connect_tsms = cl->connect_tsms;
	memcpy(m->useragent, cl->useragent, sizeof(m->useragent));
	m->coinbase_selection = cl->coinbase_selection;
	m->current_diff = cl->start_diff;
	memcpy(m->last_auth_username, username, sizeof(m->last_auth_username));
	m->authorized = true;
	
	// the session id is the channel id; the channel layer derives the
	// extranonce prefix from it (default build) or allocates one (SRI)
	sid = datum_sv2_session_id(c->datum_thread->thread_id, c->cid, slot);
	m->sid = sid;
	m->sid_inv = ((sid >> 24) & 0xff) | (((sid >> 16) & 0xff) << 8) | (((sid >> 8) & 0xff) << 16) | ((sid & 0xff) << 24);
	ch->channel_id = sid;
	ch->extended = extended;
	
	// a miner that only accepts hard work sets a low max_target; the
	// fingerprint floor stays in force underneath it
	m->forced_high_min_diff = (max_diff > cl->fingerprint_min_diff) ? max_diff : cl->fingerprint_min_diff;
	if (m->current_diff < m->forced_high_min_diff) m->current_diff = m->forced_high_min_diff;
	
	// start vardiff near the right place from the declared hashrate:
	// shares per minute target -> hashes per share -> difficulty
	if (nominal_hash_rate > 0.0f && nominal_hash_rate < 1.0e18f) {
		double per_share = ((double)nominal_hash_rate * 60.0) / (double)datum_config.stratum_v1_vardiff_target_shares_min;
		d = (uint64_t)(per_share / 4294967296.0);
		if (d) {
			d = roundDownToPowerOfTwo_64(d);
			if (d > m->current_diff) m->current_diff = d;
		}
	}
	
	// A pool's job is never sent below the pool's minimum difficulty
	// (sv2_send_job()), and the channel's first job MUST be the first message
	// after the Success (spec 5.3.15 and 5.3.16), which leaves no room for a
	// SetTarget between the two: the channel opens at the minimum, and the
	// Success carries it, as V1's first mining.set_difficulty does.
	if (td->sdata.cur_stratum_job && td->sdata.cur_stratum_job->is_datum_job && m->current_diff < datum_config.override_vardiff_min) {
		m->current_diff = datum_config.override_vardiff_min;
	}

	// the channel layer's side: the extranonce prefix, and the rules of the
	// protocol on the request
	get_target_from_diff(target, m->current_diff);
	o.extended = extended;
	o.channel_id = sid;
	o.user_identity = username;
	o.nominal_hash_rate = nominal_hash_rate;
	o.max_target = max_target;
	o.min_extranonce_size = min_extranonce_size;
	o.target = target;
	ch->proto = datum_sv2_channel_open(c->datum_thread->thread_id, m, &o, error_code);
	if (!ch->proto) {
		DLOG_INFO("SV2 client %s: channel refused by the channel layer (%s)", c->rem_host, error_code);
		sv2_channel_release(cl, ch);
		return sv2_send_open_channel_error(c, request_id, error_code);
	}
	
	m->subscribed = true;
	m->subscribe_tsms = td->sdata.loop_tsms;

	// the hashrate estimate's first window starts now; from 0, as a V1
	// client's does, it spans the epoch and reads about zero until a share
	// comes a minute after the first, about 20 minutes for a Bitaxe at
	// OCEAN's minimum difficulty
	m->stats.last_swap_tsms = td->sdata.loop_tsms;

	// fresh vardiff window before the first job, or the "no shares for a
	// minute" rule would halve the starting difficulty immediately
	m->share_count_since_snap = 0;
	m->share_diff_since_snap = 0;
	m->share_snap_tsms = td->sdata.loop_tsms;
	
	cl->channels[slot] = ch;
	cl->channel_count++;
	if (slot >= cl->slots_used) cl->slots_used = slot + 1;
	cl->next_slot = (slot + 1) % max_channels;
	
	prefix = datum_sv2_channel_extranonce_prefix(ch->proto, &prefix_len);
	if (extended) {
		T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS ok;
		ok.request_id = request_id;
		ok.channel_id = ch->channel_id;
		get_target_from_diff(ok.target, m->current_diff);
		ok.extranonce_size = datum_sv2_channel_extranonce_size(ch->proto);
		ok.extranonce_prefix = sv2_bytes(prefix, prefix_len);
		ok.group_channel_id = 0; // no group channels: nothing is ever sent to one
		len = sv2_msg_open_extended_mining_channel_success_encode(td->frame, sizeof(td->frame), &ok);
	} else {
		T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS ok;
		ok.request_id = request_id;
		ok.channel_id = ch->channel_id;
		get_target_from_diff(ok.target, m->current_diff);
		ok.extranonce_prefix = sv2_bytes(prefix, prefix_len);
		ok.group_channel_id = 0; // no group channels: nothing is ever sent to one
		len = sv2_msg_open_standard_mining_channel_success_encode(td->frame, sizeof(td->frame), &ok);
	}
	m->last_sent_diff = m->current_diff;
	if (sv2_queue_frame(c, len) < 0) return -1;
	
	DLOG_DEBUG("SV2 %s channel %08x opened for %s (%s), diff %"PRIu64", %d open on the connection", extended ? "extended" : "standard", ch->channel_id, m->last_auth_username, c->rem_host, m->current_diff, cl->channel_count);
	
	// first job: future job plus SetNewPrevHash
	return sv2_send_job(c, ch, true, false, false);
}

static int sv2_handle_frame(T_DATUM_CLIENT_DATA *c, const unsigned char *frame, uint32_t len) {
	T_DATUM_SV2_CLIENT *cl = c->app_client_data;
	T_DATUM_SV2_CHANNEL *ch;
	T_SV2_MESSAGE m;
	int r;
	
	// an error reply is queued; nothing more from this client matters
	if (cl->state == DATUM_SV2_STATE_CLOSING) return 0;
	
	r = sv2_msg_decode_frame(frame, len, &m);
	if (r == SV2_ERR_UNSUPPORTED) {
		// A well-formed frame the protocol layer has no decoder for: an
		// extension (we negotiated none, so its frames are ignored, spec
		// section 3.4.1) or a message type outside the mining protocol.
		// Before SetupConnection nothing else is acceptable.
		if (cl->state == DATUM_SV2_STATE_SETUP) return -1;
		DLOG_DEBUG("SV2 client %s sent extension 0x%04x message type 0x%02x (%u bytes), ignored", c->rem_host, (unsigned int)(m.extension_type & SV2_EXTENSION_MASK), m.msg_type, len - SV2_FRAME_HEADER_SIZE);
		return 0;
	}
	if (r != SV2_OK) return -1;
	
	if (cl->state == DATUM_SV2_STATE_SETUP) {
		if (m.msg_type != SV2_MSG_SETUP_CONNECTION) return -1;
		return sv2_handle_setup_connection(c, &m.u.setup_connection);
	}
	
	switch (m.msg_type) {
		case SV2_MSG_SETUP_CONNECTION: {
			return -1;
		}
		case SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL: {
			const T_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL *o = &m.u.open_extended_mining_channel;
			return sv2_open_channel(c, o->request_id, o->user_identity, o->nominal_hash_rate, o->max_target, o->min_extranonce_size, true);
		}
		case SV2_MSG_OPEN_STANDARD_MINING_CHANNEL: {
			const T_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL *o = &m.u.open_standard_mining_channel;
			return sv2_open_channel(c, o->request_id, o->user_identity, o->nominal_hash_rate, o->max_target, 0, false);
		}
		case SV2_MSG_SUBMIT_SHARES_EXTENDED: {
			const T_SV2_MSG_SUBMIT_SHARES_EXTENDED *s = &m.u.submit_shares_extended;
			ch = sv2_channel_find(c, s->channel_id);
			if (!ch) return sv2_send_share_error(c, s->channel_id, s->sequence_number, SV2_ERROR_INVALID_CHANNEL_ID);
			if (!ch->extended) return sv2_reject_share(c, ch, s->sequence_number, ch->m.last_sent_diff, SV2_ERROR_INVALID_CHANNEL_ID);
			return sv2_handle_share(c, ch, s->sequence_number, s->job_id, s->nonce, s->ntime, s->version, s->extranonce);
		}
		case SV2_MSG_SUBMIT_SHARES_STANDARD: {
			const T_SV2_MSG_SUBMIT_SHARES_STANDARD *s = &m.u.submit_shares_standard;
			ch = sv2_channel_find(c, s->channel_id);
			if (!ch) return sv2_send_share_error(c, s->channel_id, s->sequence_number, SV2_ERROR_INVALID_CHANNEL_ID);
			if (ch->extended) return sv2_reject_share(c, ch, s->sequence_number, ch->m.last_sent_diff, SV2_ERROR_INVALID_CHANNEL_ID);
			return sv2_handle_share(c, ch, s->sequence_number, s->job_id, s->nonce, s->ntime, s->version, sv2_bytes(NULL, 0));
		}
		case SV2_MSG_UPDATE_CHANNEL: {
			const T_SV2_MSG_UPDATE_CHANNEL *u = &m.u.update_channel;
			char error_code[DATUM_SV2_CHANNEL_ERROR_CODE_MAX];
			uint64_t d;
			ch = sv2_channel_find(c, u->channel_id);
			if (!ch) return sv2_send_update_channel_error(c, u->channel_id, SV2_ERROR_INVALID_CHANNEL_ID);
			d = datum_sv2_diff_from_max_target(u->maximum_target);
			if (d == DATUM_SV2_DIFF_UNREACHABLE) return sv2_send_update_channel_error(c, u->channel_id, SV2_ERROR_MAX_TARGET_OUT_OF_RANGE);
			if (datum_sv2_channel_update(ch->proto, u->nominal_hash_rate, u->maximum_target, error_code) < 0) {
				return sv2_send_update_channel_error(c, u->channel_id, error_code);
			}
			ch->m.forced_high_min_diff = (d > cl->fingerprint_min_diff) ? d : cl->fingerprint_min_diff;
			if (ch->m.current_diff < ch->m.forced_high_min_diff) ch->m.current_diff = ch->m.forced_high_min_diff;
			// The miner MUST get a SetTarget at or below the new max_target
			// (spec 5.3.7): it follows whenever the target it was last sent
			// is easier, even with a harder one from vardiff still waiting
			// for the next job.
			if (ch->m.last_sent_diff < ch->m.forced_high_min_diff) return sv2_send_job(c, ch, false, true, false);
			return 0;
		}
		case SV2_MSG_CLOSE_CHANNEL: {
			// only the channel goes; the connection may open others, and
			// one left without any is dropped by the idle rules
			ch = sv2_channel_find(c, m.u.close_channel.channel_id);
			if (ch) {
				DLOG_DEBUG("SV2 client %s closed channel %08x, %d left on the connection", c->rem_host, m.u.close_channel.channel_id, cl->channel_count - 1);
				sv2_channel_close(c, ch);
			}
			return 0;
		}
		default: {
			DLOG_DEBUG("SV2 client %s sent unhandled message type 0x%02x (%u bytes)", c->rem_host, m.msg_type, len - SV2_FRAME_HEADER_SIZE);
			return 0;
		}
	}
}

/////////////////////////////////
// Socket app callbacks
/////////////////////////////////

// Binary-mode receive callback: consume as many complete units as the
// buffer holds and return how many bytes were used, or negative to drop
// the client.
int datum_sv2_socket_thread_client_data(T_DATUM_CLIENT_DATA *c, unsigned char *buf, int len) {
	T_DATUM_SV2_CLIENT *cl = c->app_client_data;
	int consumed = 0;
	int r;
	
	if (cl->state == DATUM_SV2_STATE_HANDSHAKE) {
		unsigned char act2[SV2_NOISE_ACT2_SIZE];
		if (len < SV2_NOISE_ACT1_SIZE) return 0;
		r = sv2_noise_responder_act2(&cl->noise, buf, act2, (uint32_t)time(NULL));
		if (r != SV2_OK) {
			DLOG_DEBUG("SV2 handshake failed for %s (%d)", c->rem_host, r);
			return -1;
		}
		if (c->out_buf + (int)sizeof(act2) >= CLIENT_BUFFER) return -1;
		datum_socket_send_chars_to_client(c, (char *)act2, sizeof(act2));
		cl->state = DATUM_SV2_STATE_SETUP;
		consumed = SV2_NOISE_ACT1_SIZE;
		buf += SV2_NOISE_ACT1_SIZE;
		len -= SV2_NOISE_ACT1_SIZE;
	}
	
	cl->input_held = false;
	while (len > 0) {
		uint32_t out_len = 0, used = 0;
		if (c->out_buf >= CLIENT_BUFFER - SV2_REPLY_HEADROOM) {
			DLOG_DEBUG("SV2 client %d/%d (%s): write buffer nearly full (%d bytes queued); reading its requests on once it drains", c->datum_thread->thread_id, c->cid, c->rem_host, c->out_buf);
			cl->input_held = true;
			((T_DATUM_SV2_THREAD_DATA *)c->datum_thread->app_thread_data)->has_held_input = true;
			break;
		}
		r = sv2_noise_read_frame(&cl->noise, buf, (uint32_t)len, cl->rx_frame, sizeof(cl->rx_frame), &out_len, &used);
		consumed += (int)used;
		buf += used;
		len -= (int)used;
		if (r == SV2_NEED_MORE) break;
		if (r != SV2_OK) {
			DLOG_DEBUG("SV2 frame from %s rejected (%d)", c->rem_host, r);
			return -1;
		}
		if (sv2_handle_frame(c, cl->rx_frame, out_len) < 0) return -1;
	}
	return consumed;
}

void datum_sv2_socket_thread_client_new(T_DATUM_CLIENT_DATA *c) {
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)c->datum_thread->app_thread_data;
	T_DATUM_SV2_CLIENT *cl = c->app_client_data;
	static uint64_t unique_id_ctr = 0;
	
	// A kill asked for the slot's previous connection is still set when that
	// connection closed on its own first: the socket layer only clears the
	// flag of slots it kills.  It would hold this connection's input and
	// drop it at the thread's next kill.
	c->kill_request = false;
	
	// all but the channel table, which belongs to the client slot
	memset(cl, 0, offsetof(T_DATUM_SV2_CLIENT, channels));
	memset(cl->channels, 0, sizeof(*cl->channels) * (size_t)datum_config.stratum_v2_max_channels_per_connection);
	
	cl->unique_id = 0x5200000000000000ULL | unique_id_ctr++;
	cl->connect_tsms = td->sdata.loop_tsms > 0 ? td->sdata.loop_tsms : current_time_millis();
	cl->no_channel_since_tsms = cl->connect_tsms;
	cl->first.m.sdata = &td->sdata;
	cl->first.m.unique_id = cl->unique_id;
	cl->first.m.connect_tsms = cl->connect_tsms;
	cl->state = DATUM_SV2_STATE_HANDSHAKE;
	
	if (sv2_noise_init_responder(&cl->noise, td->secp, &td->keys) != SV2_OK) {
		DLOG_ERROR("Could not initialise Noise for SV2 client %s", c->rem_host);
		sv2_kill(c);
		return;
	}
	DLOG_DEBUG("New SV2 client connected. %d (%s)", c->fd, c->rem_host);
}

// Also called, by the socket layer, for a slot whose new connection failed
// before client_new ran; there is nothing open then and nothing to do.
void datum_sv2_socket_thread_client_closed(T_DATUM_CLIENT_DATA *c, const char *msg) {
	T_DATUM_SV2_CLIENT *cl = c->app_client_data;
	int slot;
	sv2_noise_clear(&cl->noise);
	for (slot = 0; slot < cl->slots_used; slot++) {
		if (cl->channels[slot]) sv2_channel_close(c, cl->channels[slot]);
	}
	
	// The listener can hand the slot to a new connection before this
	// thread's next pass sets it up, and the loop's scans run in between:
	// they must find nothing to act on, not a closing connection to drop
	// or an idle one to kick.
	cl->state = DATUM_SV2_STATE_HANDSHAKE;
	cl->slots_used = 0;
	cl->channel_count = 0;
	cl->pending_jobs = 0;
	cl->input_held = false;
	cl->no_channel_since_tsms = UINT64_MAX;
	DLOG_DEBUG("SV2 client connection closed. (%s)", msg);
}

void datum_sv2_socket_thread_init(T_DATUM_THREAD_DATA *my) {
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)my->app_thread_data;
	unsigned char seed[32];
	
	pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
	td->sdata.latest_stratum_job_index = global_latest_stratum_job_index;
	td->sdata.cur_stratum_job = global_cur_stratum_jobs[global_latest_stratum_job_index];
	pthread_rwlock_unlock(&stratum_global_job_ptr_lock);
	td->sdata.new_job = false;
	td->sdata.last_sent_job_state = 0;
	td->sdata.next_kick_check_tsms = current_time_millis() + 10000;
	
	datum_stratum_dupes_init(&td->sdata);
	
	if (datum_sv2_channel_thread_init(my->thread_id) != 0) {
		DLOG_FATAL("Could not set up the SV2 channel layer for thread %d", my->thread_id);
		panic_from_thread(__LINE__);
		return;
	}
	
	td->secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	sv2_crypto_random(seed, sizeof(seed));
	if (!td->secp || !secp256k1_context_randomize(td->secp, seed)) {
		DLOG_FATAL("Could not create a secp256k1 context for SV2 thread %d", my->thread_id);
		panic_from_thread(__LINE__);
		return;
	}
	sodium_memzero(seed, sizeof(seed));
	
	if (sv2_noise_responder_keys_init(&td->keys, td->secp, sv2_authority_sk, (uint32_t)datum_config.stratum_v2_certificate_validity_hours * 3600u, (uint32_t)time(NULL)) != SV2_OK) {
		DLOG_FATAL("Could not derive SV2 keys for thread %d", my->thread_id);
		panic_from_thread(__LINE__);
		return;
	}
	td->next_cert_check_tsms = current_time_millis() + 60000;
}

static int sv2_thread_channel_count(T_DATUM_THREAD_DATA *my) {
	int i, n = 0;
	for (i = 0; i < my->app->max_clients_thread; i++) {
		T_DATUM_SV2_CLIENT *cl = my->client_data[i].app_client_data;
		if (my->client_data[i].fd) n += cl->channel_count;
	}
	return n;
}

static void sv2_send_job_to_all(T_DATUM_THREAD_DATA *my, bool activate_prev_hash, bool new_block) {
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)my->app_thread_data;
	int i, slot;
	
	td->last_broadcast_new_block = new_block;
	for (i = 0; i < my->app->max_clients_thread; i++) {
		T_DATUM_CLIENT_DATA *c = &my->client_data[i];
		T_DATUM_SV2_CLIENT *cl = c->app_client_data;
		if (!c->fd) continue;
		for (slot = 0; slot < cl->slots_used; slot++) {
			if (cl->channels[slot] && sv2_send_job(c, cl->channels[slot], activate_prev_hash, false, new_block) < 0) {
				sv2_kill(c);
				break;
			}
		}
	}
}

// Requests left unread for lack of room to answer them are read once the
// write buffer has drained, the way the socket layer hands over new data:
// what is not consumed stays at the start of the client's buffer.
static void sv2_resume_input(T_DATUM_THREAD_DATA *my) {
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)my->app_thread_data;
	bool left = false;
	int i, used;
	
	for (i = 0; i < my->app->max_clients_thread; i++) {
		T_DATUM_CLIENT_DATA *c = &my->client_data[i];
		T_DATUM_SV2_CLIENT *cl = c->app_client_data;
		if (!c->fd || !cl->input_held || c->kill_request) continue;
		if (c->out_buf >= CLIENT_BUFFER - SV2_REPLY_HEADROOM) {
			left = true;
			continue;
		}
		used = datum_sv2_socket_thread_client_data(c, (unsigned char *)c->buffer, c->in_buf);
		if (used < 0 || used > c->in_buf) {
			sv2_kill(c);
			continue;
		}
		if (used > 0 && used < c->in_buf) memmove(c->buffer, c->buffer + used, c->in_buf - used);
		c->in_buf -= used;
		if (cl->input_held) left = true;
	}
	td->has_held_input = left;
}

// Channels whose job did not fit in the write buffer get the current job
// once there is room, as if it had been sent to them with the last round.
static void sv2_send_pending_jobs(T_DATUM_THREAD_DATA *my) {
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)my->app_thread_data;
	bool left = false;
	int i, slot;
	
	for (i = 0; i < my->app->max_clients_thread; i++) {
		T_DATUM_CLIENT_DATA *c = &my->client_data[i];
		T_DATUM_SV2_CLIENT *cl = c->app_client_data;
		if (!c->fd || !cl->pending_jobs) continue;
		for (slot = 0; slot < cl->slots_used && cl->pending_jobs; slot++) {
			T_DATUM_SV2_CHANNEL *ch = cl->channels[slot];
			if (!ch || !ch->job_pending) continue;
			if (sv2_send_job(c, ch, false, ch->job_pending_quickdiff, td->last_broadcast_new_block) < 0) {
				sv2_kill(c);
				break;
			}
			if (ch->job_pending) break; // still full; try again next pass
		}
		if (cl->pending_jobs) left = true;
	}
	td->has_pending_jobs = left;
}

// Why a channel is past the stratum idle timeouts, or NULL
static const char *sv2_channel_idle_reason(const T_DATUM_SV2_CHANNEL *ch, uint64_t tsms2, uint64_t tsms3) {
	if (ch->m.share_count_accepted > 0) return ch->m.stats.last_share_tsms < tsms3 ? "idle-since-last-share" : NULL;
	return ch->m.subscribe_tsms < tsms2 ? "idle-without-shares" : NULL;
}

// V1's idle rules, per channel.  A channel V1 would kick is closed; a
// connection whose every channel would be kicked is dropped, which for a
// connection with one channel is exactly what V1 does.  A connection that
// has not finished SetupConnection is V1's client that never subscribes.
// One that has but holds no channel, a proxy waiting for its first miner
// or whose miners have left, is treated as a subscribed V1 client that
// sends no shares: dropped idle_timeout_no_shares seconds after it
// connected or its last channel closed.  Closing idle channels stops at
// the reply headroom and goes on at the next check, so a burst of them
// cannot cost a proxy its connection.
static void sv2_idle_kicks(T_DATUM_THREAD_DATA *my, uint64_t tsms, uint64_t tsms2, uint64_t tsms3) {
	int i, slot, idle;
	
	for (i = 0; i < my->app->max_clients_thread; i++) {
		T_DATUM_CLIENT_DATA *c = &my->client_data[i];
		T_DATUM_SV2_CLIENT *cl = c->app_client_data;
		if (!c->fd) continue;
		if (!cl->channel_count) {
			if (cl->state != DATUM_SV2_STATE_READY && cl->no_channel_since_tsms < tsms) {
				DLOG_DEBUG("Kicking SV2 client %d/%d (%s) for being idle > %d seconds without finishing SetupConnection.", my->thread_id, i, c->rem_host, datum_config.stratum_v1_idle_timeout_no_subscribe);
				sv2_kill(c);
			} else if (cl->state == DATUM_SV2_STATE_READY && cl->no_channel_since_tsms < tsms2) {
				DLOG_DEBUG("Kicking SV2 client %d/%d (%s) for being idle > %d seconds without a channel.", my->thread_id, i, c->rem_host, datum_config.stratum_v1_idle_timeout_no_share);
				sv2_kill(c);
			}
			continue;
		}
		// a connection whose every channel is idle goes; otherwise the idle
		// channels are closed and the rest carry on
		for (slot = 0, idle = 0; slot < cl->slots_used; slot++) {
			if (cl->channels[slot] && sv2_channel_idle_reason(cl->channels[slot], tsms2, tsms3)) idle++;
		}
		if (!idle) continue;
		if (idle == cl->channel_count) {
			DLOG_DEBUG("Kicking SV2 client %d/%d (%s): every channel is idle beyond the stratum idle timeouts.", my->thread_id, i, c->rem_host);
			sv2_kill(c);
			continue;
		}
		for (slot = 0; slot < cl->slots_used; slot++) {
			T_DATUM_SV2_CHANNEL *ch = cl->channels[slot];
			const char *why = ch ? sv2_channel_idle_reason(ch, tsms2, tsms3) : NULL;
			if (!why) continue;
			if (c->out_buf >= CLIENT_BUFFER - SV2_REPLY_HEADROOM) break;
			DLOG_DEBUG("Closing SV2 channel %08x of client %d/%d (%s): %s", ch->channel_id, my->thread_id, i, c->rem_host, why);
			if (sv2_send_close_channel(c, ch->channel_id, why) < 0) {
				sv2_kill(c);
				break;
			}
			sv2_channel_close(c, ch);
		}
	}
}

// How many Stratum V2 socket threads run.  The V1 server waits for each
// of them, as for its own, to send empty work on a new block before the
// template thread publishes the full job.
int datum_sv2_active_threads(void) {
	return global_sv2_app ? global_sv2_app->datum_active_threads : 0;
}

// The V1 thread loop, with SV2 sends.  The job state machine and the pacing
// of routine updates are kept identical so both servers behave the same
// way on a new block.
void datum_sv2_socket_thread_loop(T_DATUM_THREAD_DATA *my) {
	T_DATUM_SV2_THREAD_DATA *td = (T_DATUM_SV2_THREAD_DATA *)my->app_thread_data;
	T_DATUM_STRATUM_THREADPOOL_DATA *sdata = &td->sdata;
	T_DATUM_STRATUM_JOB *job;
	bool change_ready = true;
	uint64_t tsms, tsms2, tsms3;
	int i;
	
	pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
	if (global_latest_stratum_job_index != sdata->latest_stratum_job_index) {
		change_ready = true;
		if (sdata->last_was_empty && global_cur_stratum_jobs[global_latest_stratum_job_index]->job_state >= JOB_STATE_FULL_PRIORITY_WAIT_COINBASER) {
			if (!stratum_job_coinbaser_ready(sdata, global_cur_stratum_jobs[global_latest_stratum_job_index])) {
				if (sdata->last_job_height == global_cur_stratum_jobs[global_latest_stratum_job_index]->height) {
					change_ready = false;
				}
			}
		}
		if (change_ready) {
			sdata->cur_stratum_job = global_cur_stratum_jobs[global_latest_stratum_job_index];
			sdata->latest_stratum_job_index = global_latest_stratum_job_index;
			sdata->new_job = true;
			if (sdata->cur_stratum_job->job_state == JOB_STATE_EMPTY_PLUS) {
				sdata->last_was_empty = false;
			}
			sdata->notify_remaining_count = 0;
			sdata->full_coinbase_ready = false;
			sdata->last_job_height = sdata->cur_stratum_job->height;
		}
	}
	pthread_rwlock_unlock(&stratum_global_job_ptr_lock);
	
	sdata->loop_tsms = current_time_millis();
	
	job = sdata->cur_stratum_job;
	if (sdata->new_job && job) {
		switch (job->job_state) {
			case JOB_STATE_EMPTY_ONLY: {
				sdata->full_coinbase_ready = false;
				sv2_send_job_to_all(my, true, true);
				stratum_latest_empty_increment_complete(sdata->latest_stratum_job_index, sv2_thread_channel_count(my));
				sdata->new_job = false;
				sdata->last_was_empty = true;
				sdata->last_sent_job_state = JOB_STATE_EMPTY_ONLY;
				break;
			}
			case JOB_STATE_EMPTY_PLUS: {
				sdata->full_coinbase_ready = false;
				if (!sdata->last_was_empty) {
					sv2_send_job_to_all(my, true, true);
					// the template thread holds the full job until every thread,
					// V1's and these, has sent the empty one: otherwise this thread
					// can miss it and leave its miners on the old tip while the
					// full job waits for the coinbaser
					stratum_latest_empty_increment_complete(sdata->latest_stratum_job_index, sv2_thread_channel_count(my));
					sdata->last_was_empty = true;
					sdata->last_sent_job_state = JOB_STATE_EMPTY_PLUS;
					break;
				}
				if (stratum_latest_empty_check_ready_for_full()) {
					sv2_send_job_to_all(my, false, false);
					sdata->new_job = false;
					sdata->last_was_empty = false;
					sdata->last_sent_job_state = JOB_STATE_EMPTY_PLUS;
				}
				break;
			}
			case JOB_STATE_FULL_PRIORITY: {
				sdata->full_coinbase_ready = false;
				sv2_send_job_to_all(my, false, false);
				sdata->new_job = false;
				sdata->last_was_empty = false;
				sdata->last_sent_job_state = JOB_STATE_FULL_PRIORITY;
				break;
			}
			case JOB_STATE_FULL_PRIORITY_WAIT_COINBASER: {
				sdata->full_coinbase_ready = false;
				if (stratum_job_coinbaser_ready(sdata, job)) {
					sv2_send_job_to_all(my, false, false);
					sdata->new_job = false;
					sdata->last_was_empty = false;
					sdata->last_sent_job_state = JOB_STATE_FULL_PRIORITY_WAIT_COINBASER;
				}
				break;
			}
			case JOB_STATE_FULL_NORMAL_WAIT_COINBASER: {
				sdata->full_coinbase_ready = false;
				if (stratum_job_coinbaser_ready(sdata, job)) {
					if (sdata->last_was_empty) {
						sv2_send_job_to_all(my, false, false);
					} else {
						// a channel still waiting for the last round gets this job
						td->last_broadcast_new_block = false;
						sdata->notify_remaining_count = sv2_thread_channel_count(my);
						if (sdata->notify_remaining_count > 0) {
							td->notify_next_cid = 0;
							td->notify_next_slot = 0;
							sdata->notify_start_time = sdata->loop_tsms;
							sdata->notify_delay_per_slot_tsms = ((datum_config.bitcoind_work_update_seconds - 3) * 1000) / sdata->notify_remaining_count;
							if (!sdata->notify_delay_per_slot_tsms) sdata->notify_delay_per_slot_tsms = 1;
							sdata->notify_last_time = sdata->loop_tsms - ((sdata->notify_delay_per_slot_tsms / my->app->max_threads) * my->thread_id);
						}
					}
					sdata->new_job = false;
					sdata->last_was_empty = false;
					sdata->last_sent_job_state = JOB_STATE_FULL_NORMAL_WAIT_COINBASER;
				}
				break;
			}
			default: break;
		}
	}
	
	// routine job updates are spread over the work update interval, one
	// channel per slot of time
	if (sdata->notify_remaining_count > 0) {
		tsms = sdata->loop_tsms - sdata->notify_last_time;
		if ((!tsms) || (tsms >= sdata->notify_delay_per_slot_tsms)) {
			int slot = td->notify_next_slot;
			tsms = tsms / sdata->notify_delay_per_slot_tsms;
			if (!tsms) tsms = 1;
			for (i = td->notify_next_cid; i < my->app->max_clients_thread; i++, slot = 0) {
				T_DATUM_CLIENT_DATA *c = &my->client_data[i];
				T_DATUM_SV2_CLIENT *cl = c->app_client_data;
				if (!c->fd) continue;
				for (; slot < cl->slots_used && tsms; slot++) {
					T_DATUM_SV2_CHANNEL *ch = cl->channels[slot];
					if (!ch || ch->m.subscribe_tsms > sdata->notify_start_time) continue;
					sdata->notify_remaining_count--;
					tsms--;
					if (sv2_send_job(c, ch, false, false, false) < 0) {
						sv2_kill(c);
						slot = cl->slots_used;
						break;
					}
				}
				if (!tsms) break;
			}
			td->notify_next_cid = i;
			td->notify_next_slot = slot;
			if (i >= my->app->max_clients_thread || sdata->notify_remaining_count <= 0) sdata->notify_remaining_count = 0;
			sdata->notify_last_time = sdata->loop_tsms;
		}
	}
	
	if (td->has_pending_jobs) {
		sv2_send_pending_jobs(my);
	}
	if (td->has_held_input) {
		sv2_resume_input(my);
	}
	
	// clients that were sent a fatal error reply go once it is flushed
	for (i = 0; i < my->app->max_clients_thread; i++) {
		T_DATUM_SV2_CLIENT *cl = my->client_data[i].app_client_data;
		if (my->client_data[i].fd && cl->state == DATUM_SV2_STATE_CLOSING && my->client_data[i].out_buf == 0) {
			sv2_kill(&my->client_data[i]);
		}
	}
	
	// certificate renewal, well before expiry
	if (sdata->loop_tsms >= td->next_cert_check_tsms) {
		bool renewed = false;
		if (sv2_noise_responder_keys_refresh(&td->keys, td->secp, (uint32_t)time(NULL), &renewed) != SV2_OK) {
			DLOG_ERROR("SV2 certificate renewal failed on thread %d", my->thread_id);
		} else if (renewed) {
			DLOG_DEBUG("SV2 certificate renewed on thread %d", my->thread_id);
		}
		td->next_cert_check_tsms = sdata->loop_tsms + 60000;
	}
	
	// idle kicks, same settings as V1
	if (sdata->loop_tsms >= sdata->next_kick_check_tsms) {
		if ((datum_config.stratum_v1_idle_timeout_no_subscribe > 0) || (datum_config.stratum_v1_idle_timeout_no_share > 0) || (datum_config.stratum_v1_idle_timeout_max_last_work)) {
			tsms = 1;
			tsms2 = 1;
			tsms3 = 1;
			if (datum_config.stratum_v1_idle_timeout_no_subscribe > 0) tsms = sdata->loop_tsms - (datum_config.stratum_v1_idle_timeout_no_subscribe * 1000);
			if (datum_config.stratum_v1_idle_timeout_no_share > 0) tsms2 = sdata->loop_tsms - (datum_config.stratum_v1_idle_timeout_no_share * 1000);
			if (datum_config.stratum_v1_idle_timeout_max_last_work > 0) tsms3 = sdata->loop_tsms - (datum_config.stratum_v1_idle_timeout_max_last_work * 1000);
			sv2_idle_kicks(my, tsms, tsms2, tsms3);
		}
		sdata->next_kick_check_tsms = sdata->loop_tsms + 11150;
	}
}

/////////////////////////////////
// Server
/////////////////////////////////

int datum_sv2_global_client_count(void) {
	int n;
	pthread_mutex_lock(&sv2_channel_lock);
	n = sv2_channels_open;
	pthread_mutex_unlock(&sv2_channel_lock);
	return n;
}

double datum_sv2_est_total_th_sec(void) {
	double hr, thr = 0.0;
	unsigned char astat;
	uint64_t tsms;
	int j, ii, pos;
	T_DATUM_MINER_DATA *m;
	
	if (!global_sv2_app) return 0;
	tsms = current_time_millis();
	for (j = 0; j < global_sv2_app->max_threads; j++) {
		for (ii = 0; ii < global_sv2_app->max_clients_thread; ii++) {
			T_DATUM_CLIENT_DATA *c = &global_sv2_app->datum_threads[j].client_data[ii];
			if (c->fd <= 0) continue;
			for (pos = 0; (m = datum_sv2_client_next_channel(c, &pos)) != NULL;) {
				astat = m->stats.active_index ? 0 : 1;
				hr = 0.0;
				if ((m->stats.last_swap_ms > 0) && (m->stats.diff_accepted[astat] > 0)) {
					hr = ((double)m->stats.diff_accepted[astat] / (double)((double)m->stats.last_swap_ms / 1000.0)) * 0.004294967296;
				}
				if (((double)(tsms - m->stats.last_swap_tsms) / 1000.0) < 180.0) thr += hr;
			}
		}
	}
	return thr;
}

void datum_sv2_shutdown_all(void) {
	int tid;
	if (!global_sv2_app) return;
	for (tid = 0; tid < global_sv2_app->max_threads; ++tid) {
		if (!global_sv2_app->datum_threads[tid].is_active) continue;
		pthread_mutex_lock(&global_sv2_app->datum_threads[tid].thread_data_lock);
		global_sv2_app->datum_threads[tid].empty_request = true;
		pthread_mutex_unlock(&global_sv2_app->datum_threads[tid].thread_data_lock);
	}
}

void *datum_sv2_socket_server(void *arg) {
	T_DATUM_SOCKET_APP *app;
	T_DATUM_SV2_CHANNEL **channel_tables;
	T_DATUM_SV2_CHANNEL *channel_pool;
	pthread_t listener;
	int i, j, ret;
	uint64_t ram_allocated = 0;
	
	(void)arg;
	DLOG_DEBUG("Stratum V2 server startup");
	
	if (!sv2_authority_ready) {
		DLOG_FATAL("datum_sv2_init() must run before the SV2 server starts");
		panic_from_thread(__LINE__);
		return NULL;
	}
	
	app = (T_DATUM_SOCKET_APP *)calloc(1, sizeof(T_DATUM_SOCKET_APP));
	if (!app) {
		DLOG_FATAL("Could not allocate memory for Stratum V2 server app metadata!");
		panic_from_thread(__LINE__);
		return NULL;
	}
	ram_allocated += sizeof(T_DATUM_SOCKET_APP);
	
	strcpy(app->name, "Stratum V2 Server");
	app->init_func = datum_sv2_socket_thread_init;
	app->loop_func = datum_sv2_socket_thread_loop;
	app->client_cmd_func = NULL;
	app->client_data_func = datum_sv2_socket_thread_client_data;
	app->closed_client_func = datum_sv2_socket_thread_client_closed;
	app->new_client_func = datum_sv2_socket_thread_client_new;
	
	snprintf(app->listen_addr, sizeof(app->listen_addr), "%s", datum_config.stratum_v2_listen_addr);
	app->listen_port = datum_config.stratum_v2_listen_port;
	app->max_clients_thread = datum_config.stratum_v2_max_clients_per_thread;
	app->max_threads = datum_config.stratum_v2_max_threads;
	app->max_clients = datum_config.stratum_v2_max_clients;
	
	app->datum_threads = (T_DATUM_THREAD_DATA *)calloc(app->max_threads + 1, sizeof(T_DATUM_THREAD_DATA));
	if (!app->datum_threads) {
		DLOG_FATAL("Could not allocate memory for Stratum V2 server thread pool data!");
		panic_from_thread(__LINE__);
		return NULL;
	}
	ram_allocated += sizeof(T_DATUM_THREAD_DATA) * (app->max_threads + 1);
	
	app->datum_threads[0].app_thread_data = calloc(app->max_threads + 1, sizeof(T_DATUM_SV2_THREAD_DATA));
	if (!app->datum_threads[0].app_thread_data) {
		DLOG_FATAL("Could not allocate memory for Stratum V2 server thread pool app data!");
		panic_from_thread(__LINE__);
		return NULL;
	}
	for (i = 1; i < app->max_threads; i++) {
		app->datum_threads[i].app_thread_data = &((char *)app->datum_threads[0].app_thread_data)[sizeof(T_DATUM_SV2_THREAD_DATA) * i];
	}
	ram_allocated += sizeof(T_DATUM_SV2_THREAD_DATA) * (app->max_threads + 1);
	
	app->datum_threads[0].client_data[0].app_client_data = calloc((app->max_threads * app->max_clients_thread) + 1, sizeof(T_DATUM_SV2_CLIENT));
	if (!app->datum_threads[0].client_data[0].app_client_data) {
		DLOG_FATAL("Could not allocate memory for Stratum V2 server per-client data!");
		panic_from_thread(__LINE__);
		return NULL;
	}
	ram_allocated += ((app->max_threads * app->max_clients_thread) + 1) * sizeof(T_DATUM_SV2_CLIENT);
	
	// one channel table per client slot, and a pool for the channels
	// beyond each connection's first, allocated now so that nothing is
	// while miners are served
	channel_tables = calloc((size_t)app->max_threads * (size_t)app->max_clients_thread * (size_t)datum_config.stratum_v2_max_channels_per_connection, sizeof(*channel_tables));
	if (!channel_tables) {
		DLOG_FATAL("Could not allocate memory for Stratum V2 server channel tables!");
		panic_from_thread(__LINE__);
		return NULL;
	}
	ram_allocated += (uint64_t)app->max_threads * (uint64_t)app->max_clients_thread * (uint64_t)datum_config.stratum_v2_max_channels_per_connection * sizeof(*channel_tables);
	channel_pool = calloc((size_t)datum_config.stratum_v2_max_clients, sizeof(*channel_pool));
	if (!channel_pool) {
		DLOG_FATAL("Could not allocate memory for Stratum V2 server channels!");
		panic_from_thread(__LINE__);
		return NULL;
	}
	ram_allocated += (uint64_t)datum_config.stratum_v2_max_clients * sizeof(*channel_pool);
	for (i = datum_config.stratum_v2_max_clients - 1; i >= 0; i--) {
		channel_pool[i].next_free = sv2_channel_free;
		sv2_channel_free = &channel_pool[i];
	}
	if (datum_sv2_channel_layer_init(app->max_threads, datum_config.stratum_v2_max_clients) != 0) {
		DLOG_FATAL("Could not allocate memory for the Stratum V2 channel layer!");
		panic_from_thread(__LINE__);
		return NULL;
	}
	
	for (i = 0; i < app->max_threads; i++) {
		for (j = 0; j < app->max_clients_thread; j++) {
			if (!((i == 0) && (j == 0))) {
				app->datum_threads[i].client_data[j].app_client_data = &((char *)app->datum_threads[0].client_data[0].app_client_data)[((i * app->max_clients_thread) + j) * sizeof(T_DATUM_SV2_CLIENT)];
			}
			((T_DATUM_SV2_CLIENT *)app->datum_threads[i].client_data[j].app_client_data)->channels = &channel_tables[((size_t)i * (size_t)app->max_clients_thread + (size_t)j) * (size_t)datum_config.stratum_v2_max_channels_per_connection];
		}
	}
	
	// the V1 server owns the job locks and the submitblock thread; wait for
	// it to have a job before we accept anyone
	pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
	i = global_latest_stratum_job_index;
	pthread_rwlock_unlock(&stratum_global_job_ptr_lock);
	j = 0;
	while (i < 0 || !need_coinbaser_rwlocks_init_done) {
		usleep(50000);
		pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
		i = global_latest_stratum_job_index;
		pthread_rwlock_unlock(&stratum_global_job_ptr_lock);
		j++;
		if (j > 500 && j % 100 == 1) {
			DLOG_ERROR("SV2 server has not seen an initial stratum job after ~%d seconds.", j / 20);
		}
	}
	
	ret = pthread_create(&listener, NULL, datum_gateway_listener_thread, app);
	if (ret != 0) {
		DLOG_FATAL("Could not pthread_create for SV2 socket listener!: %s", strerror(ret));
		panic_from_thread(__LINE__);
		return NULL;
	}
	
	global_sv2_app = app;
	DLOG_INFO("Stratum V2 Server Init complete. Authority key: %s", sv2_authority_pk_b58);
	DLOG_DEBUG("%"PRIu64" MB of RAM allocated for Stratum V2 server data.", ram_allocated >> 20);
	
	while (1) {
		sleep(1);
	}
	return NULL;
}
