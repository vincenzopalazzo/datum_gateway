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

#include <string.h>

#include "datum_sockets.h"
#include "datum_stratum.h"
#include "datum_sv2.h"
#include "datum_sv2_channel.h"
#include "datum_utils.h"

void datum_sv2_tests(void) {
	unsigned int gidx, cbidx, flags;
	unsigned char target[32], check[32];
	uint32_t id;
	
	// job ids round trip and reject anything that was never handed out
	id = datum_sv2_job_id_pack(200, 3, DATUM_SV2_JOB_FLAG_QUICKDIFF);
	datum_test(id == (200u | (3u << 8) | (1u << 16)));
	datum_test(datum_sv2_job_id_unpack(id, &gidx, &cbidx, &flags));
	datum_test(gidx == 200 && cbidx == 3 && flags == DATUM_SV2_JOB_FLAG_QUICKDIFF);
	datum_test(datum_sv2_job_id_unpack(datum_sv2_job_id_pack(7, 255, DATUM_SV2_JOB_FLAG_EMPTY), &gidx, &cbidx, &flags));
	datum_test(!datum_sv2_job_id_unpack(datum_sv2_job_id_pack(7, 0, DATUM_SV2_JOB_FLAG_EMPTY), &gidx, &cbidx, &flags));
	datum_test(!datum_sv2_job_id_unpack(datum_sv2_job_id_pack(7, MAX_COINBASE_TYPES, 0), &gidx, &cbidx, &flags));
	datum_test(!datum_sv2_job_id_unpack(datum_sv2_job_id_pack(7, 0, 4), &gidx, &cbidx, &flags));
	datum_test(!datum_sv2_job_id_unpack(0x01000000u, &gidx, &cbidx, &flags));
	datum_test(datum_sv2_job_id_unpack(0, &gidx, &cbidx, &flags) && gidx == 0 && cbidx == 0 && flags == 0);
	
	// session ids never collide with the V1 construction for the same slot
	datum_test(datum_sv2_session_id(0, 0, 0) != (0u ^ 0xB10CF00Du));
	datum_test(datum_sv2_session_id(3, 17, 0) != datum_sv2_session_id(3, 18, 0));
	datum_test(datum_sv2_session_id(3, 17, 0) != datum_sv2_session_id(4, 17, 0));
	datum_test(((datum_sv2_session_id(5, 9, 0) ^ 0xB10CF00Du) >> 22) == 5u + 512u);
	
	// a connection's first channel keeps the id a one-channel client had,
	// V1's construction with the thread offset: client slot in the low bits
	datum_test(datum_sv2_session_id(2, 4095, 0) == ((4095u | ((2u + 512u) << 22)) ^ 0xB10CF00Du));
	
	// every channel slot of every client slot gets its own id, and none is
	// an id V1 hands out (its threads are below MAX_THREADS, its client
	// slots below MAX_CLIENTS_THREAD)
	{
		static const int cids[] = { 0, 1, 7, 4095 };
		static const int slots[] = { 0, 1, 2, 63, 64, 1023 };
		uint32_t ids[2 * 4 * 6];
		int n = 0, t, ci, si, a, b;
		for (t = 0; t < 2; t++) {
			for (ci = 0; ci < 4; ci++) {
				for (si = 0; si < 6; si++) {
					uint32_t raw;
					ids[n] = datum_sv2_session_id(t * (MAX_THREADS - 1), cids[ci], slots[si]);
					raw = ids[n] ^ 0xB10CF00Du;
					datum_test((raw & 0xFFFu) == (uint32_t)cids[ci]);
					datum_test(((raw >> 12) & 0x3FFu) == (uint32_t)slots[si]);
					datum_test((raw >> 22) >= 512u);
					n++;
				}
			}
		}
		for (a = 0; a < n; a++) {
			for (b = a + 1; b < n; b++) datum_test(ids[a] != ids[b]);
		}
	}
	
	// max_target to difficulty: all ones means no floor, the difficulty 1
	// target means 1, and each halving of the target doubles it
	memset(target, 0xFF, 32);
	datum_test(datum_sv2_diff_from_max_target(target) == 0);
	get_target_from_diff(target, 1);
	datum_test(datum_sv2_diff_from_max_target(target) == 1);
	get_target_from_diff(target, 1024);
	datum_test(datum_sv2_diff_from_max_target(target) == 1024);
	get_target_from_diff(target, 3000);
	datum_test(datum_sv2_diff_from_max_target(target) == 4096);
	get_target_from_diff(target, 4096);
	datum_test(datum_sv2_diff_from_max_target(target) == 4096);
	// between two power-of-two targets the difficulty rounds up: the
	// target handed out is never above max_target (vincenzopalazzo/sv2.cc#7)
	memset(target, 0, 32);
	memset(target, 0x55, 28);
	datum_test(datum_sv2_diff_from_max_target(target) == 4);
	get_target_from_diff(check, 4);
	datum_test(compare_hashes(check, target) <= 0);
	get_target_from_diff(target, 1);
	target[26] = 0xFE;
	datum_test(datum_sv2_diff_from_max_target(target) == 2);
	// zero cannot be met
	memset(target, 0, 32);
	datum_test(datum_sv2_diff_from_max_target(target) == DATUM_SV2_DIFF_UNREACHABLE);
	
	// a username is a payout address with stratum_v2.require_address_usernames:
	// the address before any .worker or ~modifier, on the pool address's
	// network
	{
		static const char main_pool[] = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
		static const char test_pool[] = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
		datum_test(datum_sv2_username_is_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", main_pool));
		datum_test(datum_sv2_username_is_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.rig1", main_pool));
		datum_test(datum_sv2_username_is_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4~mod", main_pool));
		datum_test(datum_sv2_username_is_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.rig1", main_pool));
		datum_test(datum_sv2_username_is_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", main_pool));
		datum_test(datum_sv2_username_is_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx.rig1", test_pool));
		// another network, a bad checksum, not an address, no address
		datum_test(!datum_sv2_username_is_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", main_pool));
		datum_test(!datum_sv2_username_is_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", test_pool));
		datum_test(!datum_sv2_username_is_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", main_pool));
		datum_test(!datum_sv2_username_is_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3", main_pool));
		datum_test(!datum_sv2_username_is_address("bitaxe1", main_pool));
		datum_test(!datum_sv2_username_is_address(".rig1", main_pool));
		datum_test(!datum_sv2_username_is_address("", main_pool));
	}
	
	// the channel layer this build has
	datum_sv2_channel_tests();
}
