//! armada.v1.NetworkConfig as protojson reads and writes it: lowerCamelCase
//! names (the proto names accepted too), unknown fields refused, null for a
//! default, uint32 as a number or a string.

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use std::fmt;

pub(crate) fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// A protojson uint32: a number, or a string holding one.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct U32(pub u32);

impl<'de> Deserialize<'de> for U32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = U32;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a uint32")
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<U32, E> {
                u32::try_from(v).map(U32).map_err(E::custom)
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<U32, E> {
                u32::try_from(v).map(U32).map_err(E::custom)
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<U32, E> {
                if v.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&v) {
                    Ok(U32(v as u32))
                } else {
                    Err(E::custom("not a uint32"))
                }
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<U32, E> {
                v.parse().map(U32).map_err(E::custom)
            }
        }
        d.deserialize_any(V)
    }
}

impl Serialize for U32 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(self.0)
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Deserialize, Serialize, Default, Clone, PartialEq, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkConfig {
    #[serde(
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub mode: String,
    #[serde(
        rename = "clusterCidr",
        alias = "cluster_cidr",
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub cluster_cidr: String,
    #[serde(deserialize_with = "nullable", skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<NetworkPeer>,
    #[serde(deserialize_with = "nullable", skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<NetworkEndpoint>,
    #[serde(
        rename = "isolateDefault",
        alias = "isolate_default",
        deserialize_with = "nullable",
        skip_serializing_if = "is_false"
    )]
    pub isolate_default: bool,
    #[serde(
        rename = "tcpPorts",
        alias = "tcp_ports",
        deserialize_with = "nullable",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub tcp_ports: Vec<U32>,
    #[serde(
        rename = "meshCidr",
        alias = "mesh_cidr",
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub mesh_cidr: String,
    #[serde(
        rename = "switchTo",
        alias = "switch_to",
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub switch_to: String,
    #[serde(
        rename = "switchStep",
        alias = "switch_step",
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub switch_step: String,
}

#[derive(Deserialize, Serialize, Default, Clone, PartialEq, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkEndpoint {
    #[serde(
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub address: String,
    #[serde(
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub app: String,
}

#[derive(Deserialize, Serialize, Default, Clone, PartialEq, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkPeer {
    #[serde(
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub node: String,
    #[serde(
        rename = "privateIp",
        alias = "private_ip",
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub private_ip: String,
    #[serde(
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub subnet: String,
    #[serde(
        rename = "publicKey",
        alias = "public_key",
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub public_key: String,
    #[serde(
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub endpoint: String,
    #[serde(
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub site: String,
    #[serde(
        rename = "behindNat",
        alias = "behind_nat",
        deserialize_with = "nullable",
        skip_serializing_if = "is_false"
    )]
    pub behind_nat: bool,
    #[serde(deserialize_with = "nullable", skip_serializing_if = "is_false")]
    pub relay: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_protojson() {
        let c: NetworkConfig = serde_json::from_str(
            r#"{"mode":"plain","cluster_cidr":"10.120.0.0/16","tcpPorts":[5432,"6379"],
            "peers":[{"node":"a","privateIp":"10.0.0.1","behind_nat":true}],"switchTo":null}"#,
        )
        .unwrap();
        assert_eq!(c.cluster_cidr, "10.120.0.0/16");
        assert_eq!(c.tcp_ports, vec![U32(5432), U32(6379)]);
        assert!(c.peers[0].behind_nat);
        assert!(serde_json::from_str::<NetworkConfig>(r#"{"bogus":1}"#).is_err());
        assert!(serde_json::from_str::<NetworkConfig>(r#"{"tcpPorts":[-1]}"#).is_err());
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            r#"{"mode":"plain","clusterCidr":"10.120.0.0/16","peers":[{"node":"a","privateIp":"10.0.0.1","behindNat":true}],"tcpPorts":[5432,6379]}"#
        );
    }
}
