# 0057. The control plane's state in Armada's own store

- Status: Accepted; step 1 (a single-member `armada-kv`) built, Raft and the move to come
- Date: 2026-11-27

## Context

The control plane keeps its state in etcd (ADR 0009, ADR 0010), run on
every server as `armada-etcd.service` from the runtime pack's pinned
`etcd` (ADR 0055). Armada's own code reaches it only through
`armada-store` (`store/src`), and what it uses of etcd is small:

- **KV:** `Range` (a key, a prefix, at a revision, keys only, counts),
  `Put` (with a lease), `DeleteRange`, and `Txn` with compares on a key's
  modification and creation revisions, holding ranges, puts, and range
  deletes (at most 4096 operations).
- **Lease:** `Grant`, `Revoke`, `KeepAlive` (election keys, event TTLs,
  the ACME locks' sessions).
- **Watch:** only the deletion of one key after a revision
  (`wait_delete`, election and locks).
- **Cluster:** member list, add as learner, promote, update peer URLs,
  remove.
- **Maintenance:** `Status` (member ID, learner) and `Snapshot` (backups,
  ADR 0051), restored with `etcdutl snapshot restore`.

Running etcd means a second program on every server: its own process and
memory, its own configuration, its own release cadence, and advisories in
the Go modules it links that Armada can only wait out
(`armada-pack outdated`). How it behaves when the disk is slow, when a
read times out, or when a member falls behind is outside Armada's code.
Every other program on a machine is now Armada's own Rust (ADR 0054,
ADR 0055) or a pinned runtime program the agent runs per container.

A replicated store has to write to disk before it answers, whatever it is
written in: a slow disk makes any of them slow. This decision is about
owning the store's behaviour and removing a program, not about making
disks faster; the control plane must treat a failed or slow read as an
error, never as an empty value, on either store.

## Decision

Armada gets its own replicated store, `armada-kv`, and moves every
cluster onto it in two releases.

### The store

A crate `armada-kv` (`kv/`) in the workspace, run on every server as
`armada-kv.service` (`ExecStart=armadad kv ...`), in place of
`armada-etcd.service`. It is a separate unit, like etcd is today, so a
fault in the control plane's code never takes a member of the quorum
down with it, and restarting `armada-server` keeps the quorum.

- **Consensus:** Raft through `openraft` (MIT OR Apache-2.0): leader
  election, log replication, learners, membership changes in joint
  consensus, snapshots and log compaction, ReadIndex for linearizable
  reads.
- **Storage:** `redb` (MIT OR Apache-2.0), one database file per member
  under `<data dir>/kv/`: the Raft log, its vote and membership, and the
  state machine. Every write is durable (fsync) before it is
  acknowledged; writes arriving together share one commit.
- **The state machine:** a multi-version key space like the one the
  store relies on today: a cluster-wide revision raised by every write,
  each key's creation and modification revision and version, reads at a
  past revision until it is compacted (compaction keeps an hour, as
  `armadad etcd` sets it now), leases with TTLs whose expiry the Raft
  leader proposes through the log, so every member removes the same keys
  at the same revision.
- **The API:** the subset of etcd's v3 gRPC API listed above, with the
  same messages (`proto/vendor/etcd`), so `armada-store`'s client, its
  election and lock recipes, and every transaction stay as they are. A
  request outside the subset is refused with `Unimplemented`. `Snapshot`
  streams the store's own snapshot format (a header with the format
  version and the revision, then the key space; a SHA-256 at the end).
- **Network and TLS:** as etcd's today: client and peer listeners on the
  server's private address only (ports 7445 and 7446, added to the
  reserved ports of internal TCP ingress), TLS 1.3, client certificates
  from the cluster CA with the `etcd:member` identity on both, the member
  certificate read on every handshake. Peer traffic is openraft's RPCs
  over the same mTLS.
- **Limits:** at most 4096 operations per transaction, 1.5 MiB per
  request, and a database quota (8 GiB) past which writes are refused
  with the same error etcd gives, as Armada's store expects.

`armadad kv` works out the member (name, data directory, peers,
whether it starts a cluster or joins one) from the server's flags as
`armadad etcd` does, and refuses to start while another process holds the
member's database. `armadad server join` adds the new server as a learner
and the leader promotes it, as today.

Backups (`armadad backup`, ADR 0051) write the store's snapshot as
`kv.snapshot`; `armadad restore` checks it (format, hash, revision) and
writes a new single-member store from it, as `etcdutl snapshot restore`
does now. Doctor's checks of etcd become checks of `armada-kv`.

### The move, release N

Release N carries both: `etcd` in the pack, and `armada-kv`. Upgrades
into N come from the release before it, as usual.

1. Each server upgraded to N installs `armada-kv.service` next to
   `armada-etcd.service` and keeps serving from etcd. Its agent's
   `Hello` and the server record say it can run `armada-kv`.
2. Once every server of the cluster runs N and is healthy, the leader
   moves the state, unless `armada cluster update --state-move off` holds
   it (the operator may also start it at once with `--state-move now`):
   - It writes `meta/state-move` (step `copying`) in etcd, which makes
     every transaction of every server but the move's own fail with
     `Unavailable` ("the control plane's state is moving"): agents keep
     running what they run, the API answers that error, nothing is lost.
   - It reads the whole key space at one revision and writes it into a
     new `armada-kv` cluster on every server (bootstrapped by the leader
     with every current server as a voter), keys with their versions;
     leases are created again with their remaining TTLs; election keys
     and ACME locks are left out.
   - It compares the two key spaces (every key, value, and version; a
     hash over both) and only then writes `meta/state-move` (step
     `moved`, with the revision) into both stores.
   - Every server, seeing `moved`, ends its term, connects to
     `armada-kv`, and campaigns again there. `armada-etcd.service` is
     stopped and disabled; its data directory is kept, renamed
     `etcd.moved`, for a manual return during release N.
3. A move that fails before `moved` removes the new store's data and
   `meta/state-move`, records `StateMoveFailed` with the reason, and
   retries after 10 minutes, doubling to 2 hours; the cluster keeps
   running on etcd. `armada cluster status` shows the step.

The window where writes are refused lasts as long as reading and writing
the key space (seconds for the keyspaces Armada has run so far). Reads
of the API, agents' sessions, the proxies, and every container keep
working through it.

New clusters made by `armadad init` on release N start on `armada-kv`.

### etcd leaves, release N+1

Release N+1 has no etcd in the pack and no `armadad etcd`. Upgrades into
it come only from N on a cluster whose state has moved: `armadad
upgrade` refuses a server still running `armada-etcd`, and doctor fails
on it, both saying to let the move finish on N first. N+1 removes
`armada-etcd.service`, `etcd.moved`, and the etcd lines of
`THIRD_PARTY_NOTICES.md`, `pack/lock.json`, and the release archives'
licenses.

### Testing

- `store/tests/replay.rs` replays the store's recorded behaviour against
  `armada-kv` as well as etcd during N, and against `armada-kv` alone
  after: the recordings are etcd's behaviour, so any difference is a bug
  in `armada-kv`.
- The server's scenarios run on `armada-kv`.
- Fault tests of the store on its own, in process: a member killed at
  every step of a write, a partitioned leader, a member restarted from
  every point of its log, clock jumps against lease expiry; each checks
  that every acknowledged write survives and no read sees a revision go
  back.
- The end-to-end test on real machines (leader stop and SIGKILL, all
  machines rebooted at once, rolling updates through the new leader) on
  `armada-kv`, and `test/e2e/upgrade.sh` from the release before N
  through the move under load.

## Consequences

- One program less on every server, and no Go program in the control
  plane; etcd's advisories stop reaching Armada after N+1.
- Armada owns the store's correctness: Raft and the multi-version state
  machine are now Armada's code to test and fix. The subset of etcd's API
  keeps the store's client unchanged, and etcd's recorded behaviour is
  the test of it.
- The control plane refuses writes for the length of the move, once per
  cluster.
- Backups taken on N+1 are `kv.snapshot`; N restores both kinds, N+1 only
  its own. A cluster restored from an older etcd backup is restored on N
  and moves there.
- Ports 7445 and 7446 join the reserved ports; 2379 and 2380 stay
  reserved through N+1.

## Risks

- A bug in consensus or in the state machine can lose or fork state. The
  replay of etcd's recorded behaviour, the fault tests, and the
  end-to-end tests must pass before N; `armada-kv` stays behind a flag
  (`armadad init --state kv`, no move) until they do.
- A move interrupted between `copying` and `moved` leaves writes refused
  until the leader cleans up; a new leader reads `meta/state-move` and
  finishes the clean-up before anything else.
- Performance on slow disks is no better than etcd's; batching commits
  and keeping reads off the disk are where the store has to do at least
  as well, measured on the same machines before N.
