//! What only the parity program uses: every record under the prefix read
//! into its type and encoded again, which must give the bytes stored.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::client::op;
use crate::error::Result;
use crate::gojson::{decode, marshal};
use crate::records::*;
use crate::tx::Etcd;

fn again<T: DeserializeOwned + Serialize>(k: &str, b: &[u8]) -> Result<Vec<u8>> {
    let v: T = decode(k, b)?;
    Ok(marshal(&v))
}

/// A record whose encoding differs from what was stored.
pub struct Diff {
    pub key: String,
    pub stored: String,
    pub encoded: String,
}

impl Etcd {
    /// Reads every record under the prefix as its type and encodes it
    /// again, returning those whose bytes differ (and those that do not
    /// decode, as an error).
    pub async fn reencode(&self) -> Result<Vec<Diff>> {
        let r = self.c.range(op::get_prefix(&self.prefix, 0)).await?;
        let mut out = Vec::new();
        for kv in r.kvs {
            let full = String::from_utf8_lossy(&kv.key).into_owned();
            let k = full[self.prefix.len()..].to_string();
            let b = &kv.value;
            let head = k.split_once('/').map_or(k.as_str(), |(h, _)| h);
            let enc = match head {
                "commit" => continue,
                "schema" | "auditseq" => again::<i64>(&k, b)?,
                "meta" if k == "meta/user-cutoff" || k == "meta/metrics-cutoff" => {
                    again::<i64>(&k, b)?
                }
                "meta" => again::<String>(&k, b)?,
                "network" => again::<NetworkRec>(&k, b)?,
                "nodes" => again::<NodeRec>(&k, b)?,
                "nodecerts" => again::<CertRec>(&k, b)?,
                "tokens" => again::<TokenRec>(&k, b)?,
                "servers" => again::<ServerRec>(&k, b)?,
                "apps" => again::<AppRec>(&k, b)?,
                "revs" => {
                    let r: RevRec = decode(&k, b)?;
                    let spec = r.spec.get().to_string();
                    let rev = crate::apps::decode_rev(r.clone())?;
                    let back = rev.spec().to_json();
                    if back != spec {
                        out.push(Diff {
                            key: format!("{k} (spec)"),
                            stored: spec,
                            encoded: back,
                        });
                    }
                    marshal(&r)
                }
                "replicas" => again::<ReplicaRec>(&k, b)?,
                "secrets" => again::<SecretRec>(&k, b)?,
                "secretseq" => again::<i64>(&k, b)?,
                "secretusers" => again::<bool>(&k, b)?,
                "domains" => again::<DomainRec>(&k, b)?,
                "audit" => again::<AuditRec>(&k, b)?,
                "runs" => again::<JobRunRec>(&k, b)?,
                "volumes" => again::<VolumeRec>(&k, b)?,
                "spaces" => again::<SpaceRec>(&k, b)?,
                "users" | "services" => again::<PrincipalRec>(&k, b)?,
                "metrics" => again::<MetricsRec>(&k, b)?,
                "placements" => again::<PlacementRec>(&k, b)?,
                "events" => again::<EventRec>(&k, b)?,
                _ => continue,
            };
            if &enc != b {
                out.push(Diff {
                    key: k,
                    stored: String::from_utf8_lossy(b).into_owned(),
                    encoded: String::from_utf8_lossy(&enc).into_owned(),
                });
            }
        }
        Ok(out)
    }
}
