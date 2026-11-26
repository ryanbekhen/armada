# Third-party notices

Armada is licensed under the [Apache License 2.0](LICENSE). It contains,
or downloads, software by others under their own licenses. Every one of
them allows commercial use; this file lists what each needs from people
who pass Armada on.

One program in the runtime pack, crun, is under the GNU General Public
License (ADR 0056). It runs only as a process of its own, started by
Armada's programs; none of Armada's programs links it or any other GPL
code. Release archives carry its complete corresponding source and its
license texts (below).

## Armada's own code

The `armada` and `armadad` binaries are Rust programs (ADR 0055; their
crates are listed from "armada-node" on) and link no Go module; the
repository holds no Go code. Parts of the Rust code are ported from Go
code, listed under armada-spec below. The Go programs releases carry are
etcd's (below), with the license files of the modules they link.

## The runtime pack

Linux release builds of `armadad` embed these programs (ADR 0011, ADR 0055, ADR 0056), exactly
as their projects release them; `pack/lock.json` pins each by version and
SHA-256, and `armada-pack` (`pack/`, below) builds the pack from it.

| Component | Version | License | Source |
| --- | --- | --- | --- |
| crun | 1.31 | GPL-2.0-or-later | <https://github.com/containers/crun/tree/1.31>, and in every full Linux release archive (`source/runtime/crun-1.31/`) |
| runc | 1.5.2 | Apache-2.0 | <https://github.com/opencontainers/runc/tree/v1.5.2> |
| cni-plugins | 1.9.1 | Apache-2.0 | <https://github.com/containernetworking/plugins/tree/v1.9.1> |
| tini | 0.19.0 | MIT ([text](third_party/licenses/MIT-tini.txt)) | <https://github.com/krallin/tini/tree/v0.19.0> |
| etcd | 3.7.4 | Apache-2.0 | <https://github.com/etcd-io/etcd/tree/v3.7.4> |

From etcd's release the pack takes `etcd` and `etcdutl` (ADR 0055). They
are Go programs, linked statically by etcd's release build with the Go
standard library (BSD-3-Clause, [text](third_party/licenses/BSD-3-Clause-Go.txt))
and Go modules under Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, and ISC,
which each program names in its build information (`go version -m`
prints it). Release archives carry the license and notice files of every
one of those modules in `licenses/runtime/`, one directory per module and
version, with `MODULES.txt` naming the program that links each:
`make runtime-licenses` (`armada-pack licenses`) reads the module list
from both architectures' programs, takes each module from the Go module
proxy, and checks it against the go.sum hash the program records. etcd's
own modules (`go.etcd.io/etcd/...`, built from its repository) are under
its license above.

### crun

crun runs every container created since ADR 0056 (runc stays for the
containers it created before, until they are recreated). The pack holds
crun's own static release build without systemd support
(`crun-1.31-linux-<arch>-disable-systemd`), unchanged. crun is under the
[GNU General Public License 2.0 or later](third_party/licenses/GPL-2.0.txt);
its library part, libcrun, under the GNU Lesser General Public License 2.1
or later. Armada uses crun only by running it as a separate program (with
`--root`, `create`, `start`, `kill`, `delete`, `list`, and `exec`) and
links none of it.

Under section 3(a) of the GPL 2.0, every full Linux release archive
(`armada_<version>_linux_<arch>.tar.gz`, the one that carries `armadad`
and with it the pack) carries crun's complete corresponding source:

- `source/runtime/crun-1.31/crun-1.31.tar.gz`, crun's release source
  tarball (SHA-256 `17d04ba159fada1f1300a36b8afe869afb38bf1bbda28da052e83bb4bee20108`),
- `source/runtime/crun-1.31/build/`: `flake.nix`, `flake.lock`, and
  `nix/derivation.nix` and `nix/static.nix` of crun's tag 1.31, the scripts
  its static release programs are built with (`flake.lock` pins the
  nixpkgs revision `1d060086d60cb76a40cf37109f979d88a5bd6396`, which pins
  each library below and its source),
- `source/runtime/SOURCES.txt`, each file with its SHA-256 and address,

and `licenses/runtime/crun@1.31/` holds crun's `COPYING` (GPL 2.0) and
`COPYING.libcrun` (LGPL 2.1). `pack/lock.json` pins every one of these
files by SHA-256, as it pins the programs; `make runtime-sources`
(`armada-pack sources`) collects them when a release is built.

crun's static programs are linked with:

| Library | Version | License | In |
| --- | --- | --- | --- |
| GNU C Library | 2.44 | LGPL-2.1-or-later | amd64, arm64 |
| libgcc (GCC) | 16.2.0 | GPL-3.0-or-later WITH GCC-exception-3.1 | amd64, arm64 |
| libseccomp | 2.6.1 | LGPL-2.1-only | amd64, arm64 |
| libcap | 2.78 | BSD-3-Clause OR GPL-2.0-only (used under BSD-3-Clause) | amd64, arm64 |
| json-c | 0.18 | MIT | amd64, arm64 |
| libcriu (CRIU) | 4.1.1 | LGPL-2.1-only | amd64 |
| protobuf-c | 1.5.2 | BSD-2-Clause | amd64 |

and with code inside crun's own source: libocispec (crun's
`libocispec/`, under its own license with a special exception for the
parser it generates) and BLAKE3 (`src/libcrun/blake3`, CC0-1.0 or
Apache-2.0). The libraries' sources are those of the nixpkgs revision
above (<https://github.com/NixOS/nixpkgs/tree/1d060086d60cb76a40cf37109f979d88a5bd6396>,
each under `pkgs/by-name/`), which `flake.lock` pins.

### The other programs

These binaries are statically linked by their projects with libraries
under the [GNU Lesser General Public License 2.1](third_party/licenses/LGPL-2.1.txt):

- **runc** with libseccomp 2.6.1 (<https://github.com/seccomp/libseccomp/releases/tag/v2.6.1>)
  and the GNU C Library of Debian trixie (<https://sources.debian.org/src/glibc/>),
  as its release `Dockerfile` builds it.
- **tini** with the GNU C Library 2.23 (<https://ftp.gnu.org/gnu/glibc/glibc-2.23.tar.gz>).

Armada does not change these programs or libraries. You may replace any of
them with your own build, for example with another version of an LGPL
library: build the program from its source above, put its address and
SHA-256 into `pack/lock.json`, and build `armadad` with
`make build-bundle`. The complete corresponding source of the LGPL
libraries is at the addresses above.

## Armada's log writer, supervisor, and resolver

The runtime pack also carries `armada-log`, Armada's own log writer
(`logger/`, Apache-2.0), `armada-shim`, which supervises containers
(`shim/`, Apache-2.0), and `armada-dns`, the node-local
resolver of containers (`dns/`, Apache-2.0). All three are written in Rust
with no crates beyond the standard library and are linked statically with:

- the **Rust standard library** and its runtime libraries, under MIT or
  Apache-2.0 (Armada uses them under Apache-2.0), with LLVM's libunwind
  under Apache-2.0 WITH LLVM-exception. Source:
  <https://github.com/rust-lang/rust/tree/1.100.0/library>.
- the **musl** C library that Rust ships for its `*-linux-musl` targets,
  under the MIT license ([text](third_party/licenses/MIT-musl.txt)).
  Source: <https://git.musl-libc.org/cgit/musl>.

## armada-pack

`armada-pack` (`pack/`, Apache-2.0) builds the runtime pack and collects
`licenses/runtime/` when a release is built. It is never distributed. It
is built with crates of the next section (flate2 with miniz_oxide and its
dependencies, serde, serde_json, sha2) and downloads with `curl`.

## armada-node

The runtime pack also carries `armada-node` (`node/`, Apache-2.0), the
node agent moving to Rust (ADR 0054). It is linked statically with the
Rust standard library and musl, as above, and with these crates from
<https://crates.io>. `armada-node` is a member of the Cargo workspace at
the repository's root (ADR 0055), whose one `Cargo.lock` holds every crate
of this section and the next two; `cargo deny check licenses` (`deny.toml`)
keeps them to the licenses Armada allows. Release archives carry each
crate's license and notice files in `licenses/rust/`, written by
`scripts/rust-licenses.sh` (from `third_party/licenses/rust/` for a crate
published without them).

| Crate | License |
| --- | --- |
| adler2 | 0BSD, MIT, or Apache-2.0 (used under MIT) |
| block-buffer, const-oid, cpufeatures, crypto-common, digest, hybrid-array, sha2 (RustCrypto) | MIT or Apache-2.0 |
| cfg-if, libc | MIT or Apache-2.0 |
| crc32fast, flate2 | MIT or Apache-2.0 |
| curve25519-dalek, x25519-dalek, subtle (dalek-cryptography) | BSD-3-Clause |
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
shlex, syn (MIT or Apache-2.0), and unicode-ident (MIT or
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
(ADR 0055). `armada` and `armadad` link it; they are built with it and
these crates:

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

## armada-pki and armada-secrets

`armada-pki` (`pki/`), `armada-secrets` (`secrets/`), and `armada-fsutil`
(`fsutil/`, the standard library only), all Apache-2.0, hold the cluster's
CA, certificates, and secret encryption in Rust (ADR 0055). `armada` and
`armadad` link them; they are built with them, ring (above), and these
crates:

| Crate | License |
| --- | --- |
| asn1-rs, der-parser, oid-registry, rusticata-macros, x509-parser (rusticata) | MIT or Apache-2.0 |
| data-encoding | MIT |
| deranged, num-conv, powerfmt, time, time-core | MIT or Apache-2.0 |
| lazy_static | MIT or Apache-2.0 |
| minimal-lexical | MIT or Apache-2.0 |
| nom | MIT |
| num-bigint, num-integer, num-traits | MIT or Apache-2.0 |
| pem | MIT |
| rcgen | MIT or Apache-2.0 |
| thiserror | MIT or Apache-2.0 |
| yasna | MIT or Apache-2.0 |

Used only while building, not linked: asn1-rs-derive, autocfg,
displaydoc, thiserror-impl, time-macros (MIT or Apache-2.0), asn1-rs-impl
(MIT or Apache-2.0; published without its license files, which
`third_party/licenses/rust/asn1-rs-impl/` keeps from its repository,
<https://github.com/rusticata/asn1-rs>), and synstructure (MIT). bit-vec
(MIT or Apache-2.0) is in the lock file as an optional dependency Armada's
builds do not select.

`proto/gen`, the generator `make proto` runs, is outside the workspace
with a `Cargo.lock` of its own: it writes `proto/src/gen` on a
developer's machine and is never built into anything Armada distributes.
Besides crates under the licenses above, prost-build brings foldhash
(Zlib) into it through petgraph.

## armada-spec

`armada-spec` (`spec/`, Apache-2.0) reads, checks, and writes app and job
specs in Rust (ADR 0055). `armada` and `armadad` link it; besides
serde_json (above), it is built with these crates:

| Crate | License |
| --- | --- |
| jiff, jiff-core | Unlicense or MIT (used under MIT) |
| jiff-tzdb | Unlicense or MIT (used under MIT); the time zone database it embeds is in the public domain |

In the lock file but not built by Armada: jiff-static (Unlicense or MIT),
log (MIT or Apache-2.0), and, for targets without pointer-sized atomics,
portable-atomic and portable-atomic-util (Apache-2.0 or MIT).

It also holds code ported from Go, so specs parse, fail, and print as
Go's code does:

- go-yaml v3 (`go.yaml.in/yaml/v3`, `spec/src/yaml`): its reader,
  scanner, parser, and emitter, ported from libyaml and under the MIT
  license, and its resolver, node composer, and encoder, under the Apache
  License 2.0 with Canonical's notice
  ([text](third_party/licenses/MIT-Apache-2.0-go-yaml.txt)).
- robfig/cron v3 (`spec/src/cron.rs`): its five-field parser and
  schedule, under the MIT license ([text](third_party/licenses/MIT-robfig-cron.txt)).
- The Go standard library (`spec/src/go.rs`, `spec/src/gotime.rs`,
  `spec/src/gotables.rs`): strconv's quoting and its table of printable
  runes, unicode's classes, the time package's durations and dates, and
  net/netip's addresses and prefixes, under the BSD-3-Clause license
  ([text](third_party/licenses/BSD-3-Clause-Go.txt)).

## armada-store

`armada-store` (`store/`, Apache-2.0) keeps the cluster state in etcd in
Rust (ADR 0055): the client of an etcd member, the transactions, every
record, and the election and lock recipes. `armadad` links it; besides armada-proto, armada-spec, armada-pki, armada-secrets, ring,
rustls, rustls-pki-types, serde, serde_json, tokio, tokio-stream, and
tonic (above), it is built with these crates:

| Crate | License |
| --- | --- |
| atomic-waker, equivalent, fnv, hashbrown, indexmap | Apache-2.0 or MIT (used under MIT) |
| futures-channel, futures-task, futures-util | MIT or Apache-2.0 |
| h2, hyper, hyper-util | MIT |
| httparse, smallvec, socket2 | MIT or Apache-2.0 |
| hyper-timeout | MIT or Apache-2.0 |
| mio, slab | MIT |
| tokio-rustls | MIT or Apache-2.0 |
| tower | MIT |
| try-lock, want | MIT |

Used only while building, not linked: tokio-macros (MIT). In the lock
file for other operating systems only: windows-link and windows-sys
0.61 (MIT or Apache-2.0). The test program of the store's replays
(`armada-store-parity`, the `parity` feature) is never built for a
release.

Its election and lock (`store/src/election.rs`) follow the recipes of
etcd's `concurrency` package (`go.etcd.io/etcd/client/v3/concurrency`,
v3.7.4, under the [Apache License 2.0](proto/vendor/etcd/LICENSE)), so Go
and Rust servers campaign in one election. Source:
<https://github.com/etcd-io/etcd/tree/v3.7.4/client/v3/concurrency>.

## armada-server

`armada-server` (`server/`, Apache-2.0) is the control plane in Rust
(ADR 0055): one leadership term's API with access control, joins,
sessions with agents, and assignments. `armadad` links it; besides the crates of armada-store (above) and armada-fsutil, it is
built with tonic's server, which adds this crate:

| Crate | License |
| --- | --- |
| httpdate | MIT or Apache-2.0 |

The test program of the control plane's replays (`armada-server-parity`,
the `parity` feature) is never built for a release.

## armada-client

`armada-client` (`client/`, Apache-2.0) is the `armada` client in Rust
(ADR 0055), a program of its own, which releases ship for Linux (static,
with musl, as above) and macOS (linked with the system's libraries, which
are not distributed). It is built with armada-proto, armada-spec, armada-fsutil, armada-pki (its keys and
certificate requests: ring, rcgen, time, x509-parser, above), libc, and
crates of armada-store (above): hyper-util, rustls, rustls-pki-types,
serde, serde_json, tokio, tokio-rustls, tokio-stream, tonic, and tower,
with what they bring. It adds no crate of its own.

Its command framework (`client/src/cli/`) ports the parts of
github.com/spf13/pflag v1.1.0 (BSD-3-Clause, Copyright (c) 2012 Alex
Ogier and The Go Authors), github.com/spf13/cobra v1.10.2 (Apache-2.0),
and Go's text/tabwriter and encoding/csv's reader of one record (both
BSD-3-Clause, The Go Authors) the client's commands use, so their
parsing, errors, help, and tables read as before; `client/src/term.rs`
ports golang.org/x/term's raw mode (BSD-3-Clause, The Go Authors).
Sources: <https://github.com/spf13/pflag/tree/v1.1.0>,
<https://github.com/spf13/cobra/tree/v1.10.2>,
<https://go.dev/src/text/tabwriter/>, <https://go.dev/src/encoding/csv/>,
and <https://cs.opensource.google/go/x/term>.

The shell completion scripts it prints (`client/src/cli/completion/`) are
the ones github.com/spf13/cobra v1.10.2 generates for armada, under the
[Apache License 2.0](https://github.com/spf13/cobra/blob/v1.10.2/LICENSE.txt),
kept as cobra writes them so completion works as it did. Source:
<https://github.com/spf13/cobra/tree/v1.10.2>.

## armada-agent

`armada-agent` (`agent/`, Apache-2.0) is the node agent's loop in Rust
(ADR 0055): the session with the control plane and the reconcile pass
over a container runtime. `armadad` links it; it uses only
crates named above (those of armada-store and armada-pki, with tonic's
channel). The test program of the agent's replays
(`armada-agent-parity`, the `parity` feature) is never built for a
release.

## armada-daemon

`armada-daemon` (`daemon/`, Apache-2.0) is `armadad` in Rust (ADR 0055),
a program of its own, which releases ship for Linux (static, with musl,
as above). It uses only crates named above (armada-client's command framework, armada-pki, armada-spec,
armada-fsutil, flate2, libc, rustls, rustls-pki-types, serde_json, and
sha2). Its shell completion scripts are armada-client's (above) with
armadad's name, as cobra v1.10.2 writes them for armadad. Built with the
`bundle` feature it carries the runtime pack, whose programs are listed
under "The runtime pack" above.

## Downloaded at run time

Nodes pull the HAProxy image (`haproxy:3.2-alpine`, pinned by digest in
`internal/proxy/haproxy/engine.go`) from its registry and run it as a
separate container. HAProxy is under the GNU General Public License 2.0
and its image holds Alpine Linux packages under their own licenses;
Armada does not distribute, link, or change them, and talks to HAProxy
only through its configuration file and control socket. Source:
<https://github.com/haproxy/haproxy>.
