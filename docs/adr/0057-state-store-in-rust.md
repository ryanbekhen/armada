# 0057. The control plane's state in Armada's own store

- Status: Accepted; steps 1-4 built (a single-member `armada-kv`, Raft, then the TLS listeners, `armadad kv`, `armada-kv.service`, and `armadad init --state kv`, then the backups of armada-kv and the move from etcd); `armadad init` keeps etcd as its default until the move passed the end-to-end tests on real machines; etcd leaves in the release after
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
- **Any member answers:** clients may call any member, as with etcd.
  A member that does not lead forwards a command, a ReadIndex, a lease
  keep-alive, or a membership change to the leader over the peer service
  and answers the client itself; a forwarded command whose connection
  fails is answered with an error, never sent again, since the leader may
  have applied it. Reads are linearizable unless they ask to be
  serializable: the member waits until it has applied the leader's
  ReadIndex, then reads its own key space; watches read the member's own
  key space. The lease clock and the compaction run on the leader only:
  it gives every lease its whole TTL again when it becomes the leader,
  confirms it still leads before renewing a keep-alive, and proposes
  expiries itself, never through another member. A member added with
  MemberAdd starts by asking the members it is given for the member list
  and takes the ID of the member with its peer URL and the cluster's ID;
  once started it tells the cluster its name and client URLs.
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

Until the move, the choice is recorded per server by its data directory:
a server of a cluster made with `armadad init --state kv` has the member's
directory `kv/` (its CA, `member.crt`/`member.key`, `kv.db`, and, on a
server that joined until it votes, `initial-cluster`) and no `etcd/`.
`armadad server join` learns the cluster's choice from the leader
(`JoinServerResponse.state`, `kv`, with the learner added at the
`kv_peer_port` the joining server sends), so every server of a cluster runs
the same store; a machine too old to send that port is refused.
`armada-kv.service` is installed beside `armada-etcd.service`, and
`armada-server.service` wants both: `armadad etcd` on a kv server, and
`armadad kv` on an etcd one, exit with status 78, which neither unit
restarts and systemd counts as a success.

Backups (`armadad backup`, ADR 0051) of a kv server write the store's
snapshot as `kv.snapshot`, checked in a scratch member opened in
`armadad`'s own process; the archive is format 4 and its manifest names
the state (`"state": "kv"`), so a release that knows only etcd's format 3
refuses it, and etcd's archives stay format 3 as they were. `armadad
restore` checks it (format, hash, revision, then the state opened as
Armada's) and writes a new single-member store from it, laid out as a kv
server's member directory (`kv/kv.db`), as `etcdutl snapshot restore` does
for etcd's. Doctor's checks of etcd become checks of `armada-kv`.

### The move, release N

Release N carries both: `etcd` in the pack, and `armada-kv`. Upgrades
into N come from the release before it, as usual.

1. Each server upgraded to N installs `armada-kv.service` next to
   `armada-etcd.service` and keeps serving from etcd. Its server record
   names the peer URL its `armada-kv` member takes (`KvPeerURL`, the
   private IP and port 7446), which also says it can run `armada-kv`.
2. The leader moves the state once every server's record names a peer
   URL, every server is a voting etcd member that answers, and no other
   etcd member exists, and all of that has held for ten minutes as this
   leader saw it (a new leader waits ten minutes again), unless `armada
   cluster update --state-move off` holds it (stored in
   `meta/state-move-mode`; `--state-move now` starts it at the next pass,
   without the ten minutes and the backoff, and is used up by it):
   - It records `StateMoveStarted`, then writes `meta/state-move` (step
     `copying`) and the key `moving` beside the commit key in one
     transaction. Every write of the store compares that `moving` does not
     exist: the transactions (next to the commit key and the term's
     fence), the events, the placements' pruning, and the ACME storage.
     So every write of every server but the move's own fails with
     `Unavailable` ("the control plane's state is moving"): agents keep
     running what they run, the API answers that error, nothing is lost,
     and reads keep working.
   - It reads the whole key space at that transaction's revision, a page
     at a time (keys with their values, versions, creation and
     modification revisions, and leases; leases with what is left of their
     TTLs, at least ten minutes, so keys about to expire outlive the
     comparison; election keys, ACME locks, `moving`, and the record left
     out), and hands it to the leader's `armadad`, which writes it as
     armada-kv's snapshot into a new store of its own member alone
     (`<data dir>/kv.moving`) and runs that member in its own process.
     A store restored from a snapshot holds a key space no log entry
     made, so before the member serves it builds a Raft snapshot of it and
     purges the log up to it (the database's `base` mark until then, done
     again on the next open when interrupted): every member added later
     then receives the whole key space as an InstallSnapshot instead of
     the log alone. `armadad restore` of an armada-kv backup works the
     same way.
   - It adds every other server's member as a learner at its `KvPeerURL`
     and writes the leader member's peer URL into the record. Every
     server's `armadad server` watches the record on its own etcd member
     (serializable reads, every second, so a member that lost its quorum
     still answers) and, named in it, starts its member in its own process
     in `kv.moving` and joins through that URL; the leader promotes each
     once it caught up, until every server's member votes (at most five
     minutes). Joining as learners reuses the membership changes servers
     already use, and needs no agreement on member IDs before the store
     exists.
   - It reads the new key space back and compares it with the copy (every
     key, value, version, revision, and lease; a SHA-256 over each), on
     every member: each member's own key space, read serializable at the
     revision the leader's member reached once that member applied it; a
     member that lacks it or differs fails the move. Only then it
     writes the step `moved` (with the revision) into etcd, compared on
     the record's whole value so a move given up never moves, then into
     `armada-kv`, where it also rewrites each server record's member ID to
     its armada-kv member's (by name; each server writes its own again when
     it starts there).
   - Every server, seeing `moved` (in etcd, or in its `armada-kv` member,
     which has it only after etcd), ends its term, stops its member, renames
     `kv.moving` to `kv` (from then on its store is armada-kv) and `etcd`
     to `etcd.moved` (kept for a manual return during release N), enables
     and starts `armada-kv.service`, stops and disables
     `armada-etcd.service`, and campaigns again on `armada-kv`, whose
     leader records `StateMoved`. A server that was down rejoins the same
     way from its `kv.moving`.
3. A move that fails before `moved` stops the leader's member, removes
   `meta/state-move` and `moving` (each server's `armadad`, seeing the
   record gone, removes its `kv.moving`), records `StateMoveFailed` with
   the reason (an alert warning), and retries after 10 minutes, doubling to
   2 hours (`meta/state-move-retry`); the cluster keeps running on etcd. A
   new term that finds a move `copying` gives it up the same way before
   anything else. `armada cluster status` shows the store, the step, what
   an automatic move waits for, and the failures; the metrics endpoint
   shows `armada_state_store` and `armada_state_move_failures`.

The window where writes are refused lasts as long as reading and writing
the key space (seconds for the keyspaces Armada has run so far). Reads
of the API, agents' sessions, the proxies, and every container keep
working through it.

New clusters made by `armadad init` on release N start on `armada-kv`
(until the move has passed the end-to-end tests on real machines, `init`
keeps etcd as its default and `--state kv` asks for armada-kv).

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
- The move in process (`server/tests/replay/statemove.rs`): one server
  and three on the pinned etcd moved to armada-kv members in the test's
  process with the key spaces equal, a member that does not join leaving
  the cluster on etcd with writes working, writes refused while copying,
  and a new term giving up a move left half done.
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
