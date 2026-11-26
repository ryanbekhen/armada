# Runtime pack updates

The programs `pack/lock.json` pins, against their projects' latest stable releases and the advisories known for the pinned versions (`armada-pack outdated`).

| Program | Pinned | Latest | Status |
| --- | --- | --- | --- |
| runc | 1.5.2 | 1.5.3 | **3 advisories fixed by the update**, update available |
| crun | 1.31 | 1.31 | current |

## Advisories a newer release fixes

Update these pins (exit code 2).

| Advisory | Severity | Program | Affects | Fixed in | Summary |
| --- | --- | --- | --- | --- | --- |
| [GHSA-g2c3-j8g3-7gpw](https://github.com/opencontainers/runc/security/advisories/GHSA-g2c3-j8g3-7gpw) (CVE-2026-119101) | high | runc | runc 1.5.2 | 1.5.3 | malicious image can bind-mount an arbitrary host directory into a container across checkpoint/restore |
| [GHSA-mjcv-p78q-w5fw](https://osv.dev/vulnerability/GHSA-mjcv-p78q-w5fw) (CVE-2026-61801, GO-2026-6686) | moderate | runc | github.com/moby/sys/user v0.4.0 [github.com/moby/sys/user] | github.com/moby/sys/user 0.4.1 | github.com/moby/sys/user has a possible DoS via unbounded parsing of user and group database files |
| [GO-2026-6859](https://osv.dev/vulnerability/GO-2026-6859) (CVE-2026-97054) | unrated | runc | Go standard library go1.26.8 [net/http] | Go 1.26.11 | HTTP/1 server crash due to MaxBytesReader header race in net/http |

## Advisories in upstream builds, no newer release to take

In the pinned programs, or in the Go modules and the Go release their current upstream build was made with; they wait for upstream. Note whether each reaches Armada.

None known.

GitHub's security advisories of each program's repository are checked for every program; the Go programs (runc, the CNI plugins, etcd) also through OSV, for their own module, every module their build information names, and the Go standard library they were built with. An advisory in a module or in the standard library may not reach code the program runs: read it before acting. A fix in a module or in Go reaches the pack with an upstream release built with it.
