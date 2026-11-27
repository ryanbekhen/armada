//! The key space on its own: versions and revisions, reads at past
//! revisions, compaction, leases, transactions and their compares,
//! snapshots, and what survives closing the database.

use std::path::PathBuf;

use armada_kv::command::{Command, Op};
use armada_kv::mvcc::{Applied, Limits, Response, Store};
use armada_kv::{Error, Result};
use armada_proto::etcd::etcdserverpb as pb;
use armada_proto::etcd::mvccpb::KeyValue;
use pb::compare::{CompareResult, CompareTarget, TargetUnion};
use pb::request_op::Request;
use pb::response_op::Response as OpResponse;

fn dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("kv-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn open(name: &str) -> Store {
    Store::open(&dir(name).join("kv.db"), Limits::default()).unwrap()
}

fn one(s: &Store, op: Op) -> Result<Applied> {
    s.apply(&[Command::new(op)]).unwrap().remove(0)
}

fn put(s: &Store, k: &str, v: &str) -> i64 {
    put_leased(s, k, v, 0).unwrap()
}

fn put_leased(s: &Store, k: &str, v: &str, lease: i64) -> Result<i64> {
    Ok(one(
        s,
        Op::Put(pb::PutRequest {
            key: k.into(),
            value: v.into(),
            lease,
            ..Default::default()
        }),
    )?
    .revision)
}

fn del(s: &Store, k: &str, end: &str) -> i64 {
    match one(
        s,
        Op::DeleteRange(pb::DeleteRangeRequest {
            key: k.into(),
            range_end: end.into(),
            ..Default::default()
        }),
    )
    .unwrap()
    .response
    {
        Response::DeleteRange(d) => d.deleted,
        r => panic!("{r:?}"),
    }
}

fn get(s: &Store, k: &str, rev: i64) -> Result<Option<KeyValue>> {
    Ok(s.range(&pb::RangeRequest {
        key: k.into(),
        revision: rev,
        ..Default::default()
    })?
    .kvs
    .pop())
}

fn prefix(s: &Store, p: &str, rev: i64) -> Result<Vec<(String, String)>> {
    let mut end = p.as_bytes().to_vec();
    *end.last_mut().unwrap() += 1;
    Ok(s.range(&pb::RangeRequest {
        key: p.into(),
        range_end: end,
        revision: rev,
        ..Default::default()
    })?
    .kvs
    .into_iter()
    .map(|kv| {
        (
            String::from_utf8(kv.key).unwrap(),
            String::from_utf8(kv.value).unwrap(),
        )
    })
    .collect())
}

fn grant(s: &Store, id: i64, ttl: i64) -> Result<Applied> {
    one(s, Op::LeaseGrant(pb::LeaseGrantRequest { id, ttl }))
}

#[test]
fn versions_and_revisions() {
    let s = open("versions");
    assert_eq!(
        s.state().unwrap().revision,
        1,
        "a new store is at revision 1"
    );
    assert_eq!(put(&s, "a", "1"), 2);
    assert_eq!(put(&s, "a", "2"), 3);
    let kv = get(&s, "a", 0).unwrap().unwrap();
    assert_eq!((kv.create_revision, kv.mod_revision, kv.version), (2, 3, 2));
    assert_eq!(del(&s, "a", ""), 1);
    assert_eq!(s.state().unwrap().revision, 4);
    assert_eq!(del(&s, "a", ""), 0, "nothing to delete");
    assert_eq!(
        s.state().unwrap().revision,
        4,
        "a delete of nothing keeps the revision"
    );
    assert_eq!(put(&s, "a", "3"), 5);
    let kv = get(&s, "a", 0).unwrap().unwrap();
    assert_eq!((kv.create_revision, kv.version), (5, 1), "created again");

    // Past revisions.
    assert_eq!(get(&s, "a", 2).unwrap().unwrap().value, b"1");
    assert_eq!(get(&s, "a", 3).unwrap().unwrap().value, b"2");
    assert!(get(&s, "a", 4).unwrap().is_none(), "deleted at 4");
    assert!(get(&s, "a", 1).unwrap().is_none());
    assert_eq!(get(&s, "a", 6), Err(Error::FutureRev));

    // Ranges at past revisions skip deleted keys and see later ones.
    put(&s, "p/1", "x"); // 6
    put(&s, "p/2", "y"); // 7
    del(&s, "p/1", ""); // 8
    put(&s, "p/3", "z"); // 9
    let at = |r| prefix(&s, "p/", r).unwrap();
    assert_eq!(
        at(7),
        vec![("p/1".into(), "x".into()), ("p/2".into(), "y".into())]
    );
    assert_eq!(at(8), vec![("p/2".into(), "y".into())]);
    assert_eq!(
        at(0),
        vec![("p/2".into(), "y".into()), ("p/3".into(), "z".into())]
    );

    // Limits, counts, sorting, filters, keys only, every key from one.
    let r = s
        .range(&pb::RangeRequest {
            key: "p/".into(),
            range_end: "p0".into(),
            limit: 1,
            ..Default::default()
        })
        .unwrap();
    assert_eq!((r.kvs.len(), r.more, r.count), (1, true, 2));
    assert_eq!(r.header.unwrap().revision, 9);
    let r = s
        .range(&pb::RangeRequest {
            key: "p/".into(),
            range_end: "p0".into(),
            sort_target: pb::range_request::SortTarget::Create as i32,
            sort_order: pb::range_request::SortOrder::Descend as i32,
            limit: 1,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(r.kvs[0].key, b"p/3");
    let r = s
        .range(&pb::RangeRequest {
            key: "p/".into(),
            range_end: "p0".into(),
            max_create_revision: 8,
            keys_only: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(r.kvs.len(), 1);
    assert!(r.kvs[0].value.is_empty());
    let r = s
        .range(&pb::RangeRequest {
            key: "p/".into(),
            range_end: vec![0],
            count_only: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!((r.kvs.len(), r.count), (0, 2));
    assert_eq!(s.range(&pb::RangeRequest::default()), Err(Error::EmptyKey));
}

#[test]
fn compaction() {
    let s = open("compaction");
    put(&s, "k", "1"); // 2
    put(&s, "k", "2"); // 3
    put(&s, "gone", "x"); // 4
    del(&s, "gone", ""); // 5
    put(&s, "k", "3"); // 6
    let r = one(
        &s,
        Op::Compact(pb::CompactionRequest {
            revision: 5,
            physical: false,
        }),
    )
    .unwrap();
    assert_eq!(r.revision, 6, "compaction keeps the revision");
    assert_eq!(s.state().unwrap().compacted, 5);
    assert_eq!(get(&s, "k", 4), Err(Error::Compacted));
    assert_eq!(get(&s, "k", 5).unwrap().unwrap().value, b"2");
    assert!(get(&s, "gone", 5).unwrap().is_none());
    assert_eq!(get(&s, "k", 6).unwrap().unwrap().value, b"3");
    assert_eq!(get(&s, "k", 0).unwrap().unwrap().version, 3);
    // Compacting again at or below, or above the revision, is refused.
    for (rev, want) in [(5, Error::Compacted), (7, Error::FutureRev)] {
        let e = one(
            &s,
            Op::Compact(pb::CompactionRequest {
                revision: rev,
                physical: false,
            }),
        );
        assert_eq!(e, Err(want));
    }
    // Watches from below the compacted revision see nothing; from it on,
    // the changes.
    let ev = s.events(4, b"k", b"", false).unwrap();
    assert!(ev.events.is_empty());
    assert_eq!(ev.compacted, 5);
    let ev = s.events(5, b"k", b"", true).unwrap();
    assert_eq!(ev.events.len(), 1);
    assert_eq!(ev.events[0].kv.as_ref().unwrap().mod_revision, 6);
    assert_eq!(ev.events[0].prev_kv.as_ref().unwrap().value, b"2");
}

#[test]
fn leases() {
    let s = open("leases");
    let g = grant(&s, 7, 1).unwrap();
    assert_eq!(g.granted, Some((7, 2)), "raised to the shortest TTL");
    assert_eq!(g.revision, 1, "a grant keeps the revision");
    assert_eq!(grant(&s, 7, 10), Err(Error::LeaseExists));
    assert_eq!(
        grant(&s, 8, armada_kv::mvcc::MAX_LEASE_TTL + 1),
        Err(Error::LeaseTtlTooLarge)
    );
    assert_eq!(put_leased(&s, "x", "1", 9), Err(Error::LeaseNotFound));
    put_leased(&s, "l/a", "1", 7).unwrap(); // 2
    put_leased(&s, "l/b", "1", 7).unwrap(); // 3
    put(&s, "l/c", "1"); // 4
    put_leased(&s, "l/c", "2", 7).unwrap(); // 5
    put(&s, "l/b", "2"); // 6: no longer under the lease
    assert_eq!(get(&s, "l/a", 0).unwrap().unwrap().lease, 7);
    let r = one(&s, Op::LeaseRevoke(pb::LeaseRevokeRequest { id: 7 })).unwrap();
    assert_eq!(r.revision, 7, "one revision for every key of the lease");
    assert_eq!(r.revoked, Some(7));
    assert_eq!(
        prefix(&s, "l/", 0).unwrap(),
        vec![("l/b".into(), "2".into())]
    );
    assert!(s.leases().unwrap().is_empty());
    assert_eq!(
        one(&s, Op::LeaseRevoke(pb::LeaseRevokeRequest { id: 7 })),
        Err(Error::LeaseNotFound)
    );
    // An expiry of a lease already gone is not an error.
    let r = one(&s, Op::LeaseExpire(pb::LeaseRevokeRequest { id: 7 })).unwrap();
    assert_eq!(r.revision, 7);
}

fn txn(compare: Vec<pb::Compare>, success: Vec<Request>, failure: Vec<Request>) -> Op {
    let ops = |v: Vec<Request>| {
        v.into_iter()
            .map(|r| pb::RequestOp { request: Some(r) })
            .collect()
    };
    Op::Txn(pb::TxnRequest {
        compare,
        success: ops(success),
        failure: ops(failure),
    })
}

fn cmp(key: &str, target: CompareTarget, u: TargetUnion) -> pb::Compare {
    pb::Compare {
        result: CompareResult::Equal as i32,
        target: target as i32,
        key: key.into(),
        range_end: Vec::new(),
        target_union: Some(u),
    }
}

fn put_op(k: &str, v: &str) -> Request {
    Request::RequestPut(pb::PutRequest {
        key: k.into(),
        value: v.into(),
        ..Default::default()
    })
}

fn get_op(k: &str) -> Request {
    Request::RequestRange(pb::RangeRequest {
        key: k.into(),
        ..Default::default()
    })
}

fn txn_response(a: Applied) -> pb::TxnResponse {
    match a.response {
        Response::Txn(t) => t,
        r => panic!("{r:?}"),
    }
}

#[test]
fn transactions() {
    let s = open("txn");
    // Created only when missing (create revision 0).
    let created = |s: &Store| {
        txn_response(
            one(
                s,
                txn(
                    vec![cmp(
                        "c",
                        CompareTarget::Create,
                        TargetUnion::CreateRevision(0),
                    )],
                    vec![put_op("c", "1"), get_op("c")],
                    vec![get_op("c")],
                ),
            )
            .unwrap(),
        )
    };
    let t = created(&s);
    assert!(t.succeeded);
    assert_eq!(t.header.unwrap().revision, 2);
    match &t.responses[1].response {
        Some(OpResponse::ResponseRange(r)) => {
            assert_eq!(r.kvs[0].value, b"1", "a read sees the transaction's write")
        }
        r => panic!("{r:?}"),
    }
    let t = created(&s);
    assert!(!t.succeeded);
    assert_eq!(
        t.header.unwrap().revision,
        2,
        "a failed branch that reads keeps the revision"
    );
    match &t.responses[0].response {
        Some(OpResponse::ResponseRange(r)) => assert_eq!(r.kvs[0].create_revision, 2),
        r => panic!("{r:?}"),
    }
    // A commit key compared by modification revision.
    let mod_is = |rev| cmp("c", CompareTarget::Mod, TargetUnion::ModRevision(rev));
    assert!(
        !txn_response(one(&s, txn(vec![mod_is(1)], vec![put_op("c", "x")], vec![])).unwrap())
            .succeeded
    );
    let t = txn_response(
        one(
            &s,
            txn(
                vec![mod_is(2)],
                vec![
                    put_op("c", "2"),
                    put_op("d", "1"),
                    Request::RequestDeleteRange(pb::DeleteRangeRequest {
                        key: "e".into(),
                        range_end: "f".into(),
                        ..Default::default()
                    }),
                ],
                vec![],
            ),
        )
        .unwrap(),
    );
    assert!(t.succeeded);
    assert_eq!(
        t.header.unwrap().revision,
        3,
        "one revision for the whole transaction"
    );
    assert_eq!(get(&s, "d", 0).unwrap().unwrap().mod_revision, 3);
    // Compares against the value, the version, and a range of keys.
    let mut v = cmp("c", CompareTarget::Value, TargetUnion::Value(b"2".to_vec()));
    assert!(txn_response(one(&s, txn(vec![v.clone()], vec![], vec![])).unwrap()).succeeded);
    v.result = CompareResult::NotEqual as i32;
    assert!(!txn_response(one(&s, txn(vec![v], vec![], vec![])).unwrap()).succeeded);
    let mut ver = cmp("c", CompareTarget::Version, TargetUnion::Version(1));
    ver.result = CompareResult::Greater as i32;
    ver.range_end = "e".into();
    assert!(
        !txn_response(one(&s, txn(vec![ver.clone()], vec![], vec![])).unwrap()).succeeded,
        "d is at version 1"
    );
    ver.result = CompareResult::Less as i32;
    ver.target_union = Some(TargetUnion::Version(3));
    assert!(txn_response(one(&s, txn(vec![ver], vec![], vec![])).unwrap()).succeeded);

    // What etcd refuses before applying.
    assert_eq!(
        one(
            &s,
            txn(vec![], vec![put_op("a", "1"), put_op("a", "2")], vec![])
        ),
        Err(Error::DuplicateKey)
    );
    assert_eq!(
        one(
            &s,
            txn(
                vec![],
                vec![],
                vec![
                    Request::RequestDeleteRange(pb::DeleteRangeRequest {
                        key: "a".into(),
                        range_end: "b".into(),
                        ..Default::default()
                    }),
                    put_op("a/1", "x"),
                ],
            )
        ),
        Err(Error::DuplicateKey),
        "both branches are checked"
    );
    let many: Vec<Request> = (0..4097).map(|i| put_op(&format!("m/{i}"), "x")).collect();
    assert_eq!(one(&s, txn(vec![], many, vec![])), Err(Error::TooManyOps));
    let full: Vec<Request> = (0..4096).map(|i| put_op(&format!("m/{i}"), "x")).collect();
    assert!(one(&s, txn(vec![], full, vec![])).unwrap().revision > 3);
    assert_eq!(
        one(
            &s,
            txn(
                vec![],
                vec![Request::RequestRange(pb::RangeRequest {
                    key: "c".into(),
                    revision: 99999,
                    ..Default::default()
                })],
                vec![]
            )
        ),
        Err(Error::FutureRev)
    );
    let state = s.state().unwrap();
    assert_eq!(
        one(
            &s,
            txn(
                vec![],
                vec![Request::RequestPut(pb::PutRequest {
                    key: "z".into(),
                    lease: 5,
                    ..Default::default()
                })],
                vec![]
            )
        ),
        Err(Error::LeaseNotFound)
    );
    assert_eq!(
        s.state().unwrap().revision,
        state.revision,
        "a refused transaction changes nothing"
    );

    // A transaction of reads only, without a commit.
    let r = s
        .read_txn(
            &pb::TxnRequest {
                compare: vec![],
                success: vec![
                    pb::RequestOp {
                        request: Some(get_op("c")),
                    },
                    pb::RequestOp {
                        request: Some(get_op("d")),
                    },
                ],
                failure: vec![],
            },
            4096,
        )
        .unwrap();
    assert_eq!(r.responses.len(), 2);
    assert_eq!(s.state().unwrap().applied, state.applied + 1);
}

#[test]
fn a_batch_is_one_commit_of_independent_commands() {
    let s = open("batch");
    let r = s
        .apply(&[
            Command::new(Op::Put(pb::PutRequest {
                key: "a".into(),
                value: "1".into(),
                ..Default::default()
            })),
            Command::new(Op::Put(pb::PutRequest {
                key: "b".into(),
                lease: 3,
                ..Default::default()
            })),
            Command::new(Op::Put(pb::PutRequest {
                key: "a".into(),
                value: "2".into(),
                ..Default::default()
            })),
        ])
        .unwrap();
    assert_eq!(r[0].as_ref().unwrap().revision, 2);
    assert_eq!(r[1], Err(Error::LeaseNotFound));
    assert_eq!(r[2].as_ref().unwrap().revision, 3);
    let st = s.state().unwrap();
    assert_eq!((st.revision, st.applied), (3, 3));
}

#[test]
fn snapshot_round_trip() {
    let s = open("snap");
    grant(&s, 11, 30).unwrap();
    put(&s, "a", "1");
    put(&s, "a", "2");
    put_leased(&s, "b", "x", 11).unwrap();
    put(&s, "c", "gone");
    del(&s, "c", "");
    let b = s.snapshot().unwrap();
    let d = dir("snap-restored");
    let r = Store::restore(&b, &d.join("kv.db"), Limits::default()).unwrap();
    assert_eq!(r.state().unwrap().revision, 6);
    assert_eq!(r.state().unwrap().compacted, 6);
    assert_eq!(r.leases().unwrap(), vec![(11, 30)]);
    for k in ["a", "b", "c"] {
        assert_eq!(get(&r, k, 0).unwrap(), get(&s, k, 0).unwrap(), "{k}");
    }
    assert_ne!(r.ids(), s.ids(), "a restored store is a new member");
    assert_eq!(get(&r, "a", 5), Err(Error::Compacted));
    // It goes on from the snapshot's revision, its leases still delete.
    assert_eq!(put(&r, "a", "3"), 7);
    assert_eq!(get(&r, "a", 0).unwrap().unwrap().version, 3);
    one(&r, Op::LeaseRevoke(pb::LeaseRevokeRequest { id: 11 })).unwrap();
    assert!(get(&r, "b", 0).unwrap().is_none());
    // A snapshot is only restored into a new file.
    assert!(Store::restore(&b, &d.join("kv.db"), Limits::default()).is_err());
    let mut bad = b.clone();
    bad[30] ^= 0xff;
    assert!(matches!(
        Store::restore(&bad, &d.join("other.db"), Limits::default()),
        Err(Error::Snapshot(_))
    ));
}

#[test]
fn database_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let path = dir("mode").join("kv.db");
    let _s = Store::open(&path, Limits::default()).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the state database is created 0600");
}

#[test]
fn durable_across_reopen() {
    let d = dir("reopen");
    let path = d.join("kv.db");
    let (ids, rev) = {
        let s = Store::open(&path, Limits::default()).unwrap();
        grant(&s, 5, 60).unwrap();
        put(&s, "a", "1");
        put_leased(&s, "b", "2", 5).unwrap();
        put(&s, "a", "3");
        assert!(
            Store::open(&path, Limits::default()).is_err(),
            "one holder of the database at a time"
        );
        (s.ids(), s.state().unwrap().revision)
    };
    let s = Store::open(&path, Limits::default()).unwrap();
    assert_eq!(s.ids(), ids);
    let st = s.state().unwrap();
    assert_eq!((st.revision, st.applied), (rev, 4));
    assert_eq!(get(&s, "a", 0).unwrap().unwrap().value, b"3");
    assert_eq!(get(&s, "a", 2).unwrap().unwrap().value, b"1");
    assert_eq!(s.leases().unwrap(), vec![(5, 60)]);
    assert_eq!(get(&s, "b", 0).unwrap().unwrap().lease, 5);
}

#[test]
fn quota() {
    let d = dir("quota");
    let s = Store::open(
        &d.join("kv.db"),
        Limits {
            quota_bytes: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(put_leased(&s, "a", "1", 0), Err(Error::NoSpace));
    assert_eq!(del(&s, "a", ""), 0, "deletes still go through");
}
