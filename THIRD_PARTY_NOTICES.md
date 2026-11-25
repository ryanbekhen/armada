# Third-party notices

Armada is licensed under the [Apache License 2.0](LICENSE). It contains,
or downloads, software by others under their own licenses. Every one of
them allows commercial use; this file lists what each needs from people
who pass Armada on.

## Go modules

The `armada` and `armadad` binaries are built from Go modules under
Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, and CC0-1.0.
Release archives carry each module's license and notice files in
`licenses/go/`, written by `make licenses-save`. `make licenses` (run in
CI) fails when a module under any other license is added.

- **MPL-2.0:** `github.com/cyphar/filepath-securejoin` is used unmodified;
  its source is at <https://github.com/cyphar/filepath-securejoin>.

## The embedded container runtime

Linux release builds of `armadad` embed these programs (ADR 0011), exactly
as their projects release them; `internal/runtime/embedded/lock.go` pins
each by version and SHA-256.

| Component | Version | License | Source |
| --- | --- | --- | --- |
| containerd | 2.4.2 | Apache-2.0 | <https://github.com/containerd/containerd/tree/v2.4.2> |
| runc | 1.5.2 | Apache-2.0 | <https://github.com/opencontainers/runc/tree/v1.5.2> |
| cni-plugins | 1.9.1 | Apache-2.0 | <https://github.com/containernetworking/plugins/tree/v1.9.1> |
| tini | 0.19.0 | MIT ([text](third_party/licenses/MIT-tini.txt)) | <https://github.com/krallin/tini/tree/v0.19.0> |

These binaries are statically linked by their projects with libraries
under the [GNU Lesser General Public License 2.1](third_party/licenses/LGPL-2.1.txt):

- **runc** with libseccomp 2.6.1 (<https://github.com/seccomp/libseccomp/releases/tag/v2.6.1>)
  and the GNU C Library of Debian trixie (<https://sources.debian.org/src/glibc/>),
  as its release `Dockerfile` builds it.
- **containerd** with the GNU C Library of its release build
  (<https://github.com/containerd/containerd/blob/v2.4.2/RELEASES.md>).
- **tini** with the GNU C Library 2.23 (<https://ftp.gnu.org/gnu/glibc/glibc-2.23.tar.gz>).

Armada does not change these programs or libraries. You may replace any of
them with your own build, for example with another version of an LGPL
library: build the program from its source above, put its address and
SHA-256 into `internal/runtime/embedded/lock.go`, and build `armadad` with
`make build-bundle`. The complete corresponding source of the LGPL
libraries is at the addresses above.

## Armada's log writer, supervisor, and resolver

The runtime pack also carries `armada-log`, Armada's own log writer
(`logger/`, Apache-2.0), `armada-shim`, which supervises containers
without containerd (`shim/`, Apache-2.0), and `armada-dns`, the node-local
resolver of containers (`dns/`, Apache-2.0). All three are written in Rust
with no crates beyond the standard library and are linked statically with:

- the **Rust standard library** and its runtime libraries, under MIT or
  Apache-2.0 (Armada uses them under Apache-2.0), with LLVM's libunwind
  under Apache-2.0 WITH LLVM-exception. Source:
  <https://github.com/rust-lang/rust/tree/1.100.0/library>.
- the **musl** C library that Rust ships for its `*-linux-musl` targets,
  under the MIT license ([text](third_party/licenses/MIT-musl.txt)).
  Source: <https://git.musl-libc.org/cgit/musl>.

## armada-node

The runtime pack also carries `armada-node` (`node/`, Apache-2.0), the
node agent moving to Rust (ADR 0054). It is linked statically with the
Rust standard library and musl, as above, and with these crates from
<https://crates.io>. `armada-node` is a member of the Cargo workspace at
the repository's root (ADR 0055), whose one `Cargo.lock` holds every crate
of this section and the next; `cargo deny check licenses` (`deny.toml`)
keeps them to the licenses Armada allows. Release archives carry each
crate's license and notice files in `licenses/rust/`, written by
`scripts/rust-licenses.sh` (from `third_party/licenses/rust/` for a crate
published without them).

| Crate | License |
| --- | --- |
| adler2 | 0BSD, MIT, or Apache-2.0 (used under MIT) |
| block-buffer, cpufeatures, crypto-common, digest, sha2 (RustCrypto) | MIT or Apache-2.0 |
| cfg-if, libc | MIT or Apache-2.0 |
| crc32fast, flate2 | MIT or Apache-2.0 |
| curve25519-dalek, x25519-dalek, subtle (dalek-cryptography) | BSD-3-Clause |
| generic-array | MIT |
| getrandom, once_cell, zeroize | MIT or Apache-2.0 |
| itoa, serde, serde_core, serde_json | MIT or Apache-2.0 |
| memchr | MIT or Unlicense (used under MIT) |
| miniz_oxide | MIT, Zlib, or Apache-2.0 (used under MIT) |
| rand_core | MIT or Apache-2.0 |
| ring | Apache-2.0 and ISC |
| rustls | Apache-2.0, ISC, or MIT (used under Apache-2.0) |
| rustls-pki-types | MIT or Apache-2.0 |
| rustls-webpki, untrusted | ISC |
| ruzstd, simd-adler32, twox-hash | MIT |
| typenum | MIT or Apache-2.0 |
| zmij | MIT |

Used only while building, not linked: cc, curve25519-dalek-derive,
find-msvc-tools, proc-macro2, quote, rustc_version, semver, serde_derive,
shlex, syn, version_check (MIT or Apache-2.0), and unicode-ident (MIT or
Apache-2.0, with Unicode data under Unicode-3.0). ring's C and assembly
are compiled with clang into `armada-node`. fiat-crypto (MIT, Apache-2.0,
or BSD-1-Clause; used under MIT) is in the lock file as an optional
backend of curve25519-dalek that Armada's builds do not select, and so
are, for other operating systems only, wasi (Apache-2.0 with the LLVM
exception, Apache-2.0, or MIT) and windows-sys, windows-targets,
windows_aarch64_gnullvm, windows_aarch64_msvc, windows_i686_gnu,
windows_i686_gnullvm, windows_i686_msvc, windows_x86_64_gnu,
windows_x86_64_gnullvm, windows_x86_64_msvc (MIT or Apache-2.0).

## armada-proto

`armada-proto` (`proto/`, Apache-2.0) holds Armada's protocol in Rust
(ADR 0055). No released program links it yet; the programs that will are
built with it and these crates:

| Crate | License |
| --- | --- |
| base64 | MIT or Apache-2.0 |
| bytes | MIT |
| futures-core, futures-sink | MIT or Apache-2.0 |
| http, percent-encoding | MIT or Apache-2.0 |
| http-body, http-body-util | MIT |
| pbjson | MIT ([text](third_party/licenses/rust/pbjson/LICENSE)) |
| pin-project, pin-project-lite | Apache-2.0 or MIT (used under MIT) |
| prost | Apache-2.0 |
| sync_wrapper | Apache-2.0 |
| tokio, tokio-stream, tokio-util | MIT |
| tonic | MIT |
| tonic-prost | MIT ([text](third_party/licenses/rust/tonic-prost/LICENSE)) |
| tower-layer, tower-service | MIT |
| tracing, tracing-core | MIT |

Used only while building, not linked: anyhow, async-trait, either,
itertools, pin-project-internal (MIT or Apache-2.0), prost-derive
(Apache-2.0), and tracing-attributes (MIT).

It also holds code generated from the `.proto` files of etcd's API
(`go.etcd.io/etcd/api/v3`, under the [Apache License 2.0](proto/vendor/etcd/LICENSE)),
which `proto/vendor/etcd` keeps with the services Armada uses. Source:
<https://github.com/etcd-io/etcd/tree/v3.7.4/api>.

`proto/gen`, the generator `make proto` runs, is outside the workspace
with a `Cargo.lock` of its own: it writes `proto/src/gen` on a
developer's machine and is never built into anything Armada distributes.
Besides crates under the licenses above, prost-build brings foldhash
(Zlib) into it through petgraph.

## Downloaded at run time

Nodes pull the HAProxy image (`haproxy:3.2-alpine`, pinned by digest in
`internal/proxy/haproxy/engine.go`) from its registry and run it as a
separate container. HAProxy is under the GNU General Public License 2.0
and its image holds Alpine Linux packages under their own licenses;
Armada does not distribute, link, or change them, and talks to HAProxy
only through its configuration file and control socket. Source:
<https://github.com/haproxy/haproxy>.
