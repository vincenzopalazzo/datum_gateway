# Stratum V2

DATUM Gateway can serve Stratum V2 mining devices next to its Stratum V1
server. A Stratum V2 miner connects to the gateway over an encrypted,
authenticated connection (the Noise NX handshake, with the gateway's
authority key), opens one or more mining channels and gets work built from
the gateway's own templates. Nothing changes upstream: the gateway keeps
talking to the pool over the DATUM protocol, and a Stratum V2 share goes to
the pool exactly as a Stratum V1 share does.

This is the Mining Protocol only. Templates keep coming from the node with
`getblocktemplate`, so Template Distribution and Job Declaration are not
used.

## Building

The server, `src/datum_sv2.c`, runs on a protocol layer (Noise, framing,
encoding and the mining channels) that is picked when the gateway is
configured:

| `-DDATUM_SV2_BACKEND=` | Protocol layer | Needs |
|------------------------|----------------|-------|
| `sri` (default) | The Stratum V2 Reference Implementation (SRI) crates, through the C API in `external/sri-c-ffi` | cargo and rustc 1.85 or newer, or an installed `libsv2_sri` that pkg-config finds as `sv2_sri` |
| `c` | The C core in `src/sv2` | libsecp256k1 0.4 or newer, built with the `ellswift`, `schnorrsig` and `extrakeys` modules |

The default build is the usual one:

    cmake -S . -B build
    cmake --build build

With no `sv2_sri` package installed, CMake builds `external/sri-c-ffi` with
cargo inside the build directory. The first build fetches the SRI crates
pinned by its `Cargo.lock`, so it needs network access. Without Rust, build
the C core instead:

    cmake -S . -B build -DDATUM_SV2_BACKEND=c

Debian and Ubuntu ship libsecp256k1 releases older than 0.4. Build it from
source in that case:

    git clone --depth 1 -b v0.7.1 https://github.com/bitcoin-core/secp256k1
    cmake -S secp256k1 -B secp256k1/build -DSECP256K1_ENABLE_MODULE_ELLSWIFT=ON \
        -DSECP256K1_BUILD_TESTS=OFF -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
        -DSECP256K1_BUILD_BENCHMARK=OFF
    cmake --build secp256k1/build && sudo cmake --install secp256k1/build

Both layers produce the same bytes for every message and accept each
other's handshakes. The SRI layer checks shares with `channels_sv2`'s own
rules, which differ from the C core's in a few details, such as the error
code a refused share gets. The SRI layer makes the binary larger
(about 2.2 MB stripped against 0.5 MB, mostly libsecp256k1's precomputed
tables, which the C core loads as a shared library instead). `external/README.md`
says why the SRI C API lives in this repository for now.

## Configuration

The `stratum_v2` section of the configuration file. Every key is optional;
the server is on by default.

| Key | Default | Meaning |
|-----|---------|---------|
| `listen_addr` | `""` (all addresses) | Address to listen on |
| `listen_port` | `23335` | Port to listen on; `0` disables the Stratum V2 server |
| `max_threads` | `4` | Server threads |
| `max_clients_per_thread` | `128` | Connections per thread |
| `max_clients` | `512` | Connections and open channels together, before more are refused |
| `max_channels_per_connection` | `64` | Mining channels one connection may open (1 to 1024); a proxy without channel aggregation opens one per miner |
| `authority_key_file` | `datum_sv2_authority.key` | The authority secret key; created with mode 0600 on first start if missing |
| `certificate_validity_hours` | `24` | Validity of the certificate each handshake carries; renewed at half life, at most a year |
| `require_address_usernames` | `false` | Refuse a channel whose username is not a Bitcoin address on this network (a `.worker` after it is fine) |

For example:

```json
"stratum_v2": {
	"listen_port": 23335,
	"authority_key_file": "datum_sv2_authority.key",
	"require_address_usernames": true
}
```

Difficulty, vardiff, idle timeouts and miner fingerprinting reuse the
`stratum` section's settings, applied to each channel. Every channel is a
miner of its own to the gateway: its own session id, target, vardiff and
share counts.

The authority public key is printed in the log at startup, in the base58
form miners ask for. Miners pin it to authenticate the gateway. Keep the key file safe: whoever has it can impersonate the
gateway to miners that trust its public key.

A gateway that serves miners other than its operator's, as a pool's hosted
endpoint does, should turn on `require_address_usernames`: with
`datum.pool_pass_full_users` the username is where the pool pays.

## Connecting a miner

A Bitaxe on AxeOS 2.14.2 or newer:

- Protocol: SV2
- URL: the gateway's address; port: `listen_port` (23335 by default)
- Channel type: extended
- Authority key: the one the gateway prints at startup
- User: a Bitcoin address, optionally followed by `.workername`

AxeOS up to 2.14 drops Stratum V2 frames over 2,048 bytes. The gateway
gives a Bitaxe DATUM's 500-byte coinbase, which keeps its jobs under that
limit.

Stratum V1 miners can join through SRI's Translator Proxy, with or without
channel aggregation.

## Monitoring

The gateway's periodic stats line in the log counts the open Stratum V2
channels and their estimated hashrate. The dashboard and the JSON API do
not show the Stratum V2 server yet.
