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

## Downloaded at run time

Nodes pull the HAProxy image (`haproxy:3.2-alpine`, pinned by digest in
`internal/proxy/haproxy/engine.go`) from its registry and run it as a
separate container. HAProxy is under the GNU General Public License 2.0
and its image holds Alpine Linux packages under their own licenses;
Armada does not distribute, link, or change them, and talks to HAProxy
only through its configuration file and control socket. Source:
<https://github.com/haproxy/haproxy>.
