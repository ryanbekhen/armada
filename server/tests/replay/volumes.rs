//! Fake agents that answer volume sessions (internal/server/
//! parity_volumes_test.go's volumeAgent.serve and volumeBucket): the
//! contents of the node's volumes, and a bucket the scenario's agents
//! share.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use armada_pki::go_quote;
use armada_proto::armada::v1 as pb;
use pb::volume_request::Op;
use prost::Message;
use tonic::transport::Channel;

use super::grpc::{Item, Stream};

const SESSION: &str = "/armada.v1.AgentService/VolumeSession";

/// A bucket of snapshots and their contents by app/volume.
#[derive(Default)]
pub struct Bucket {
    snaps: HashMap<String, Vec<pb::VolumeSnapshot>>,
    data: HashMap<String, String>,
    seq: i64,
    pub fail_put: bool,
}

/// One node's volumes and what it was asked.
#[derive(Default)]
pub struct Disk {
    pub disk: HashMap<String, String>,
    pub seen: Vec<String>,
}

/// What serves a volume agent's requests.
#[derive(Clone)]
pub struct Handler {
    pub ch: Channel,
    pub disk: Arc<Mutex<Disk>>,
    pub bucket: Arc<Mutex<Bucket>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Handler {
    /// Answers one request as an agent does: the attach message first,
    /// then the operation's messages; the session is held until the
    /// server ends it.
    pub async fn serve(self, req: pb::VolumeRequest) {
        let key = format!("{}/{}", req.app, req.volume);
        let op = Op::try_from(req.op).unwrap_or(Op::Unspecified);
        let mut line = format!("{} {key} stop={}", op.as_str_name(), req.stop);
        if let Some(b) = &req.backup {
            line += &format!(
                " url={} key={} keep={} tz={}",
                b.url,
                b.key.len(),
                b.keep.as_ref().map_or(0, |k| k.last),
                go_quote(&b.time_zone)
            );
        }
        if !req.snapshot.is_empty() {
            line += &format!(" snapshot={}", req.snapshot);
        }
        lock(&self.disk).seen.push(line);
        let mut stream = Stream::open(self.ch.clone(), SESSION);
        let mut first = pb::VolumeData {
            request_id: req.request_id.clone(),
            ..Default::default()
        };
        if op == Op::Remove {
            lock(&self.disk).disk.remove(&key);
            first.done = true;
        }
        stream.send(first.encode_to_vec());
        let send = |stream: &Stream, m: pb::VolumeData| stream.send(m.encode_to_vec());
        let done = || pb::VolumeData {
            done: true,
            ..Default::default()
        };
        let read = |k: &str| lock(&self.disk).disk.get(k).cloned().unwrap_or_default();
        match op {
            Op::Backup => {
                send(
                    &stream,
                    pb::VolumeData {
                        data: read(&key).into_bytes(),
                        ..Default::default()
                    },
                );
                send(&stream, done());
            }
            Op::Restore => {
                let mut got = Vec::new();
                loop {
                    match stream.recv().await {
                        Item::Msg(b) => {
                            let Ok(m) = pb::VolumeData::decode(b.as_slice()) else {
                                return;
                            };
                            got.extend_from_slice(&m.data);
                            if m.done {
                                break;
                            }
                        }
                        _ => return,
                    }
                }
                if got == b"bad" {
                    send(
                        &stream,
                        pb::VolumeData {
                            error: "the archive is not a gzipped tar".into(),
                            ..Default::default()
                        },
                    );
                } else {
                    lock(&self.disk)
                        .disk
                        .insert(key.clone(), String::from_utf8_lossy(&got).into_owned());
                    send(&stream, done());
                }
            }
            Op::Snapshot => {
                let contents = read(&key);
                let res = {
                    let mut b = lock(&self.bucket);
                    if b.fail_put {
                        None
                    } else {
                        b.seq += 1;
                        let s = pb::VolumeSnapshot {
                            id: format!("snap-{}", b.seq),
                            files: 1,
                            bytes: contents.len() as i64,
                            ..Default::default()
                        };
                        let list = b.snaps.entry(key.clone()).or_default();
                        list.push(s.clone());
                        let keep = req
                            .backup
                            .as_ref()
                            .and_then(|t| t.keep.as_ref())
                            .map_or(0, |k| k.last) as usize;
                        if keep > 0 && list.len() > keep {
                            list.drain(..list.len() - keep);
                        }
                        let n = list.len();
                        b.data.insert(s.id.clone(), contents.clone());
                        Some(pb::CreateVolumeSnapshotResponse {
                            snapshot: Some(s),
                            new_bytes: contents.len() as i64,
                            stored_bytes: 10 * n as i64,
                            snapshots: n as i32,
                        })
                    }
                };
                match res {
                    None => send(
                        &stream,
                        pb::VolumeData {
                            error: "bucket: put: AccessDenied (HTTP 403): refused".into(),
                            ..Default::default()
                        },
                    ),
                    Some(r) => send(
                        &stream,
                        pb::VolumeData {
                            done: true,
                            snapshot: Some(r),
                            ..Default::default()
                        },
                    ),
                }
            }
            Op::Snapshots => {
                let list = lock(&self.bucket)
                    .snaps
                    .get(&key)
                    .cloned()
                    .unwrap_or_default();
                send(
                    &stream,
                    pb::VolumeData {
                        done: true,
                        snapshots: list,
                        ..Default::default()
                    },
                );
            }
            Op::RestoreSnapshot => {
                let (found, contents) = {
                    let b = lock(&self.bucket);
                    let mut found = None;
                    for s in b.snaps.get(&key).into_iter().flatten() {
                        if s.id == req.snapshot || req.snapshot == "latest" {
                            found = Some(s.clone());
                        }
                    }
                    let contents = found
                        .as_ref()
                        .and_then(|f| b.data.get(&f.id).cloned())
                        .unwrap_or_default();
                    (found, contents)
                };
                match found {
                    None => send(
                        &stream,
                        pb::VolumeData {
                            error: format!("no backup {} in the bucket", req.snapshot),
                            ..Default::default()
                        },
                    ),
                    Some(f) => {
                        lock(&self.disk).disk.insert(key.clone(), contents);
                        send(
                            &stream,
                            pb::VolumeData {
                                done: true,
                                snapshot: Some(pb::CreateVolumeSnapshotResponse {
                                    snapshot: Some(f),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        );
                    }
                }
            }
            Op::Remove | Op::Unspecified => {}
        }
        // Held until the server is done with the session.
        stream.close_send();
        while let Item::Msg(_) = stream.recv().await {}
    }
}
