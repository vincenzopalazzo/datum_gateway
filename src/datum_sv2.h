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

#ifndef _DATUM_SV2_H_
#define _DATUM_SV2_H_

// Stratum V2 mining-protocol server for DATUM Gateway.
//
// A second socket app next to the Stratum V1 server: same epoll thread
// pool, same job pipeline, same DATUM pool submission, but the wire
// protocol is SV2 over Noise.  A connection opens up to
// stratum_v2.max_channels_per_connection mining channels, extended or
// standard, each with an extranonce layout that matches what DATUM already
// uses on V1:
//
//   extended:  extranonce_prefix = 4 bytes, 8 rollable bytes
//   standard:  extranonce_prefix = 4 bytes + 8 fixed bytes
//
// so the 12 byte extranonce, the coinbase parts and the DATUM protocol
// share path are untouched.  Every channel is a miner of its own to DATUM:
// it has its own session id, which is its channel id.  The session id is
// V1's construction with the channel's slot on the connection in bits V1
// never sets (datum_sv2_session_id()), so the first channel of a
// connection gets the id a one-channel client always had.  The channel
// layer (datum_sv2_channel.h) owns the prefix, the job ids and the share
// checks: the default build's makes the prefix from the session id, the
// SRI build's lets channels_sv2 allocate it.

#include <secp256k1.h>
#include <stdbool.h>
#include <stdint.h>

#include "datum_sockets.h"
#include "datum_stratum.h"
#include "datum_sv2_channel.h"
#include "sv2_noise.h"

// Largest plaintext frame we accept from a miner.  SetupConnection with
// every string at its 255 byte maximum is about 1.3 KB; SubmitShares is
// under 64 bytes.
#define DATUM_SV2_MAX_RX_FRAME 4096

// Largest frame we send: NewExtendedMiningJob with a maximum size coinbase
// and 24 merkle branches.
#define DATUM_SV2_MAX_TX_FRAME (SV2_FRAME_HEADER_SIZE + 64 + (24 * 32) + (STRATUM_COINBASE1_MAX_LEN / 2) + (STRATUM_COINBASE2_MAX_LEN / 2))
#define DATUM_SV2_MAX_TX_WIRE (DATUM_SV2_MAX_TX_FRAME + SV2_NOISE_ENC_HEADER_SIZE + (2 * SV2_AEAD_MAC_SIZE))

#define DATUM_SV2_STATE_HANDSHAKE 0 // waiting for the initiator's 64 byte act 1
#define DATUM_SV2_STATE_SETUP 1     // transport up, waiting for SetupConnection
#define DATUM_SV2_STATE_READY 2     // SetupConnection done
#define DATUM_SV2_STATE_CLOSING 3   // an error reply is queued; drop the client once it is flushed

// Per thread data.  T_DATUM_MINER_DATA.sdata points at the first member,
// so everything that works on a V1 thread's data works here too.
typedef struct {
	T_DATUM_STRATUM_THREADPOOL_DATA sdata;
	
	secp256k1_context *secp;
	T_SV2_NOISE_RESPONDER_KEYS keys;
	uint64_t next_cert_check_tsms;
	
	// the routine job spread goes channel by channel (V1's goes client by
	// client); it carries on from this client and channel slot
	int notify_next_cid;
	int notify_next_slot;
	
	// some channel's job did not fit in its client's write buffer and waits
	// for the buffer to drain (sv2_send_pending_jobs)
	bool has_pending_jobs;
	// whether the last job sent to every channel was the empty new-block
	// job, which is what a channel that is still behind must catch up with
	bool last_broadcast_new_block;
	// some client's input waits for its write buffer to drain
	// (sv2_resume_input)
	bool has_held_input;
	
	// scratch for encoding and encrypting one frame
	unsigned char frame[DATUM_SV2_MAX_TX_FRAME];
	unsigned char wire[DATUM_SV2_MAX_TX_WIRE];
} T_DATUM_SV2_THREAD_DATA;

// One mining channel.  T_DATUM_MINER_DATA comes first so the vardiff,
// stats, target table and DATUM submission code see an ordinary miner.
typedef struct T_DATUM_SV2_CHANNEL {
	T_DATUM_MINER_DATA m;
	
	bool extended;
	uint32_t channel_id;      // also the session id (m.sid)
	
	// the channel layer's side of the channel: extranonce prefix, job ids,
	// share checks (datum_sv2_channel.h)
	T_DATUM_SV2_CHANNEL_PROTO *proto;
	
	// a job could not be queued because the write buffer was full; the
	// thread loop sends the channel the current job once there is room,
	// as a quick diff job if that is what waited (a plain one would repeat
	// the job id the channel already has, with another difficulty)
	bool job_pending;
	bool job_pending_quickdiff;
	
	// job->tsms at the time each job index was sent, so the reference a
	// share comes back with is never resolved to a job that has recycled
	// the index since
	uint64_t job_tsms_sent[MAX_STRATUM_JOBS];
	
	// previous block hash and nbits the channel last received in
	// SetNewPrevHash.  SV2 carries both only there, so a job on any other
	// prev hash or nbits must activate them, even when this thread never saw
	// the empty new-block job.  nbits can change on the same prev hash: the
	// testnet minimum-difficulty rule does exactly that after 20 minutes.
	unsigned char active_prevhash[32];
	uint32_t active_nbits;
	uint32_t active_min_ntime; // the min_ntime the tip was last activated with
	bool has_active_prevhash;
	
	struct T_DATUM_SV2_CHANNEL *next_free; // channel pool free list
} T_DATUM_SV2_CHANNEL;

// Per client data.  The storage for the client's first channel comes
// first, so code that reads a client slot as T_DATUM_MINER_DATA (the API's
// kick command checks connect_tsms and unique_id) finds the connection's
// miner data there.  Further channels come from a pool shared by all
// threads.
typedef struct {
	T_DATUM_SV2_CHANNEL first;
	bool first_in_use;
	
	T_SV2_NOISE noise;
	int state;
	uint32_t setup_flags;
	
	// what SetupConnection told us about the device, copied into every
	// channel it opens: the fingerprinted coinbase size and starting
	// difficulty, and the per-model difficulty floor, kept apart from the
	// floor a miner asks for with max_target so neither can erase the other
	char useragent[128];
	unsigned char coinbase_selection;
	uint64_t start_diff;
	uint64_t fingerprint_min_diff;
	uint64_t unique_id;
	uint64_t connect_tsms;
	
	int channel_count;
	int slots_used;     // 1 + the highest slot this connection has used, 0 if it opened none
	int next_slot;      // where the search for a free slot starts
	int pending_jobs;   // channels with job_pending set
	bool input_held;    // requests wait in the client's read buffer for room to answer them
	uint64_t no_channel_since_tsms; // when the last channel closed, or the connect time
	
	unsigned char rx_frame[DATUM_SV2_MAX_RX_FRAME];
	
	// open channels by slot, stratum_v2.max_channels_per_connection
	// entries.  The table belongs to the client slot, set once at startup,
	// and comes last so a new connection can clear everything before it
	// while the API may be reading it.
	T_DATUM_SV2_CHANNEL **channels;
} T_DATUM_SV2_CLIENT;

// Load or create the authority key.  Call once before starting the server.
int datum_sv2_init(void);

// Server thread entry point (pthread)
void *datum_sv2_socket_server(void *arg);

// Socket app callbacks
void datum_sv2_socket_thread_init(T_DATUM_THREAD_DATA *my);
void datum_sv2_socket_thread_loop(T_DATUM_THREAD_DATA *my);
int datum_sv2_socket_thread_client_data(T_DATUM_CLIENT_DATA *c, unsigned char *buf, int len);
void datum_sv2_socket_thread_client_closed(T_DATUM_CLIENT_DATA *c, const char *msg);
void datum_sv2_socket_thread_client_new(T_DATUM_CLIENT_DATA *c);

// SV2 job ids pack the DATUM job index, the coinbase index and two flags;
// exposed for the self-tests and the API.
#define DATUM_SV2_JOB_FLAG_QUICKDIFF 1
#define DATUM_SV2_JOB_FLAG_EMPTY 2
uint32_t datum_sv2_job_id_pack(unsigned int gidx, unsigned int cbidx, unsigned int flags);
bool datum_sv2_job_id_unpack(uint32_t job_id, unsigned int *gidx, unsigned int *cbidx, unsigned int *flags);

// Difficulty for a miner's max_target: a power of two whose target is at
// or below it, 0 when any target is (the usual all-ones), and
// DATUM_SV2_DIFF_UNREACHABLE when none is (zero, or below what a 64-bit
// difficulty reaches), which the caller answers with max-target-out-of-range.
#define DATUM_SV2_DIFF_UNREACHABLE UINT64_MAX
uint64_t datum_sv2_diff_from_max_target(const unsigned char max_target[32]);

// Session id for channel slot `slot` of a client slot; unique across the
// V1 and V2 servers and across the channels of a connection.  Slot 0 is the
// id a connection's first channel gets.
uint32_t datum_sv2_session_id(int thread_id, int cid, int slot);

// Is the username a Bitcoin address, optionally followed by .worker or a
// ~modifier, on the same network as pool_address?  With
// stratum_v2.require_address_usernames, channels for any other username are
// refused, since datum.pool_pass_full_users sends it to the pool as the
// payout address.
bool datum_sv2_username_is_address(const char *username, const char *pool_address);

// The open channels of an SV2 client, for the API and the stats: start with
// *pos = 0 and call until it returns NULL.  Like the V1 API code this reads
// another thread's data without a lock; channel memory is never freed, so
// a channel closing meanwhile is at worst shown once more.
T_DATUM_MINER_DATA *datum_sv2_client_next_channel(T_DATUM_CLIENT_DATA *c, int *pos);

// Open channels on the whole server, and their estimated hashrate
int datum_sv2_global_client_count(void);
double datum_sv2_est_total_th_sec(void);
const char *datum_sv2_authority_pubkey_base58(void);
void datum_sv2_shutdown_all(void);

extern T_DATUM_SOCKET_APP *global_sv2_app;

#endif
