# External code

Code in this directory is not DATUM Gateway's own. It is kept here only
until it ships from its own project, and changes to it go to that project
first.

## sri-c-ffi

A C API over the Stratum V2 Reference Implementation crates
([stratum-mining/stratum](https://github.com/stratum-mining/stratum)): the
Noise handshake and encryption, Stratum V2 framing and encoding, the
message types and the server side of the mining channels (`channels_sv2`).
DATUM's Stratum V2 server runs on it when the gateway is built with
`-DDATUM_SV2_BACKEND=sri`, the default; `doc/STRATUM_V2.md` has the build
options.

This library is going to be upstreamed to SRI, as proposed in
[stratum-mining/stratum#2131](https://github.com/stratum-mining/stratum/issues/2131).
Once SRI releases it, DATUM links the released library, which CMake already
finds through pkg-config as `sv2_sri`, and this directory goes away. Until
then CMake builds it from here with cargo; nothing else in DATUM is Rust.

- Source: the sri-c-ffi repository, commit `ee3c33d`.
- License: MIT or Apache-2.0, at your option (`sri-c-ffi/LICENSE-MIT`,
  `sri-c-ffi/LICENSE-APACHE`).
- The public header is `sri-c-ffi/include/sv2_sri.h`. It is generated with
  cbindgen; `sri-c-ffi/build.sh` checks it against the sources when cbindgen
  is installed.
