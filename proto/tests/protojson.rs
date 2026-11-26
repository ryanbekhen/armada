//! armada-proto reads and writes what Go's protobuf code did. The files in
//! testdata were written by Go before the Go code was removed: each
//! message's deterministic binary encoding and its protojson.

use std::fmt::Debug;
use std::path::PathBuf;

use armada_proto::armada::v1 as pb;
use prost::Message;
use serde::Serialize;
use serde::de::DeserializeOwned;

fn read(file: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/testdata")
        .join(file);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn check<M>(name: &str)
where
    M: Message + Default + PartialEq + Debug + Serialize + DeserializeOwned,
{
    let bin = read(&format!("{name}.binpb"));
    let m = M::decode(bin.as_slice()).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(
        m.encode_to_vec(),
        bin,
        "{name}: the encoding differs from Go's"
    );

    let json = read(&format!("{name}.json"));
    let go: serde_json::Value = serde_json::from_slice(&json).unwrap();
    let ours = serde_json::to_value(&m).unwrap();
    assert_eq!(ours, go, "{name}: the JSON differs from Go's protojson");

    let back: M = serde_json::from_slice(&json).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(back, m, "{name}: protojson's JSON reads as another message");
}

#[test]
fn replica_spec() {
    check::<pb::ReplicaSpec>("replica_spec");
}

#[test]
fn agent_hello() {
    check::<pb::AgentMessage>("agent_hello");
}

#[test]
fn join_token_request() {
    check::<pb::CreateJoinTokenRequest>("join_token_request");
}

#[test]
fn metrics_certificate() {
    check::<pb::IssueMetricsCertificateResponse>("metrics_certificate");
}

#[test]
fn log_entry() {
    check::<pb::LogEntry>("log_entry");
}

#[test]
fn volume_request() {
    check::<pb::VolumeRequest>("volume_request");
}

#[test]
fn empty() {
    check::<pb::StatusRequest>("empty");
}

/// Go's deterministic encoding writes a map entry's empty value (`18 0`),
/// prost leaves it out. Both read either form as the same message, and the
/// JSON agrees; only bytes differ. Nothing hashes such a message today (the
/// replica spec hash, ADR 0055, covers ReplicaSpec, which has no maps), and
/// an encoder that must match Go's bytes writes the value.
#[test]
fn map_empty_value() {
    let bin = read("map_empty_value.binpb");
    let m = pb::LabelNodeRequest::decode(bin.as_slice()).unwrap();
    assert_eq!(m.set.get("empty").map(String::as_str), Some(""));
    let ours = m.encode_to_vec();
    assert_eq!(ours.len() + 2, bin.len(), "the known difference changed");
    assert_eq!(pb::LabelNodeRequest::decode(ours.as_slice()).unwrap(), m);

    let json = read("map_empty_value.json");
    let go: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(serde_json::to_value(&m).unwrap(), go);
    let back: pb::LabelNodeRequest = serde_json::from_slice(&json).unwrap();
    assert_eq!(back, m);
}

/// Unknown fields are refused, as protojson.Unmarshal refuses them.
#[test]
fn unknown_fields_refused() {
    assert!(serde_json::from_str::<pb::Wake>(r#"{"app":"web","nope":1}"#).is_err());
    let w: pb::Wake = serde_json::from_str(r#"{"app":"web"}"#).unwrap();
    assert_eq!(w.app, "web");
}
