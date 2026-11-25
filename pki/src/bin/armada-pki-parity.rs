//! The program Go's parity tests in internal/pki drive (ARMADA_PKI_BIN):
//! `armada-pki-parity COMMAND` with a JSON request on stdin and a JSON
//! answer on stdout, `{"error": TEXT}` when the call fails. Built only with
//! the `parity` feature; never part of a release.

use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use armada_pki::{
    Ca, Certificate, Error, Identity, IssueRequest, PrivateKey, ca_hash, encoding,
    hash_token_secret, needs_renewal, new_csr, parse_ca_hash, parse_cert_pem, parse_identity,
    parse_join_token, pin_ca, renew_due, token_secret_matches, verify_server,
};
use serde_json::{Value, json};

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("read stdin");
    let req: Value = serde_json::from_str(&input).expect("JSON request");
    let answer = match run(&cmd, &req) {
        Ok(v) => v,
        Err(e) => json!({ "error": e.to_string() }),
    };
    println!("{answer}");
}

fn s<'a>(req: &'a Value, key: &str) -> &'a str {
    req[key].as_str().unwrap_or_default()
}

fn b(req: &Value, key: &str) -> Vec<u8> {
    s(req, key).as_bytes().to_vec()
}

fn secs(req: &Value, key: &str) -> Duration {
    Duration::from_secs(req[key].as_i64().unwrap_or(0).max(0) as u64)
}

fn time_at(req: &Value, key: &str) -> SystemTime {
    match req[key].as_i64() {
        Some(ns) if ns >= 0 => UNIX_EPOCH + Duration::from_nanos(ns as u64),
        Some(ns) => UNIX_EPOCH - Duration::from_nanos(ns.unsigned_abs()),
        None => SystemTime::now(),
    }
}

fn ca(req: &Value) -> Result<Ca, Error> {
    Ca::load(&b(req, "caCert"), &b(req, "caKey"))
}

fn text(v: &[u8]) -> String {
    String::from_utf8_lossy(v).into_owned()
}

fn run(cmd: &str, req: &Value) -> Result<Value, Error> {
    Ok(match cmd {
        "new-ca" => {
            let ca = Ca::new(s(req, "name"))?;
            json!({ "cert": text(&ca.cert_pem), "key": text(ca.key_pem().expose()) })
        }
        "load-ca" => {
            let ca = Ca::load(&b(req, "cert"), &b(req, "key"))?;
            json!({ "fingerprint": ca.cert.fingerprint() })
        }
        "load-ca-dir" => {
            let ca = Ca::load_dir(Path::new(s(req, "dir")))?;
            json!({ "fingerprint": ca.cert.fingerprint() })
        }
        "write-ca-dir" => {
            let ca = Ca::new(s(req, "name"))?;
            ca.write_dir(Path::new(s(req, "dir")))?;
            json!({ "fingerprint": ca.cert.fingerprint() })
        }
        "issue" => {
            let ips = req["ips"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str()?.parse::<IpAddr>().ok())
                        .collect()
                })
                .unwrap_or_default();
            let dns = req["dns"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| Some(v.as_str()?.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let (cert, key) = ca(req)?.issue(&IssueRequest {
                identity: Identity::new(s(req, "kind"), s(req, "name")),
                dns_names: dns,
                ips,
                server: req["server"].as_bool().unwrap_or(false),
                client: req["client"].as_bool().unwrap_or(false),
                validity: secs(req, "validitySeconds"),
            })?;
            json!({ "cert": text(&cert), "key": text(key.expose()) })
        }
        "reissue" => {
            let old = parse_cert_pem(&b(req, "cert"))?;
            let cert = ca(req)?.reissue(&old, secs(req, "validitySeconds"))?;
            json!({ "cert": text(&cert) })
        }
        "sign-csr" => {
            let csr = encoding::base64_decode(s(req, "csr").as_bytes())
                .ok_or_else(|| Error::new("bad base64"))?;
            let ca = ca(req)?;
            let name = s(req, "name");
            let nc = match s(req, "as") {
                "node" => ca.sign_node_csr(&csr, name, secs(req, "validitySeconds"))?,
                "user" => ca.sign_user_csr(&csr, name)?,
                "service" => ca.sign_service_csr(&csr, name)?,
                "metrics" => ca.sign_metrics_csr(&csr, name)?,
                other => return Err(Error::new(format!("unknown signer {other}"))),
            };
            json!({ "cert": text(&nc.pem), "serial": nc.serial, "notBefore": nc.not_before, "notAfter": nc.not_after })
        }
        "new-csr" => {
            let (key, csr) = new_csr(&Identity::new(s(req, "kind"), s(req, "name")))?;
            json!({ "key": text(key.expose()), "csr": encoding::base64_encode(&csr) })
        }
        "read-cert" => {
            let c = parse_cert_pem(&b(req, "cert"))?;
            describe(&c)
        }
        "check-signature" => {
            let c = parse_cert_pem(&b(req, "cert"))?;
            let p = parse_cert_pem(&b(req, "parent"))?;
            c.check_signature_from(&p)?;
            json!({})
        }
        "verify-server" => {
            let ca = parse_cert_pem(&b(req, "ca"))?;
            let c = parse_cert_pem(&b(req, "cert"))?;
            verify_server(&c, &ca, time_at(req, "now"))?;
            json!({})
        }
        "renewal" => {
            let c = parse_cert_pem(&b(req, "cert"))?;
            let now = time_at(req, "now");
            json!({ "renewDue": renew_due(&c, now), "needsRenewal": needs_renewal(&c, now) })
        }
        "pin-ca" => {
            let chain: Vec<Certificate> = req["chain"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|v| parse_cert_pem(v.as_str().unwrap_or_default().as_bytes()))
                })
                .into_iter()
                .flatten()
                .collect::<Result<_, _>>()?;
            let ca = pin_ca(&chain, s(req, "hash"), time_at(req, "now"))?;
            json!({ "fingerprint": ca.fingerprint() })
        }
        "parse-identity" => {
            let id = parse_identity(s(req, "cn"))?;
            json!({ "kind": id.kind, "name": id.name })
        }
        "join-token" => {
            let t = parse_join_token(s(req, "token"))?;
            json!({ "id": t.id, "hash": t.secret_hash(), "shown": t.to_string(), "debug": format!("{t:?}") })
        }
        "token-matches" => {
            json!({ "match": token_secret_matches(s(req, "secret"), s(req, "hash")), "hash": hash_token_secret(s(req, "secret")) })
        }
        "ca-hash" => json!({ "hex": parse_ca_hash(s(req, "hash"))? }),
        "key" => {
            let k = PrivateKey::from_pem(&b(req, "key"))?;
            json!({ "pkcs8": encoding::base64_encode(k.pkcs8().expose()), "public": encoding::base64_encode(k.public_key()) })
        }
        other => return Err(Error::new(format!("unknown command {other}"))),
    })
}

fn describe(c: &Certificate) -> Value {
    let (identity, identity_error) = match c.identity() {
        Ok(id) => (Some(id), None),
        Err(e) => (None, Some(e.to_string())),
    };
    let principal = identity.as_ref().and_then(Identity::principal);
    json!({
        "identity": identity.as_ref().map(ToString::to_string),
        "identityError": identity_error,
        "principal": principal.as_ref().map(ToString::to_string),
        "commonName": c.common_name,
        "organization": c.organization,
        "fingerprint": c.fingerprint(),
        "caHash": ca_hash(c),
        "serial": c.serial_string(),
        "notBefore": c.not_before,
        "notAfter": c.not_after,
        "isCA": c.is_ca,
        "basicConstraintsValid": c.basic_constraints_valid,
        "maxPathLen": c.max_path_len,
        "keyUsage": c.key_usage,
        "extKeyUsage": c.ext_key_usage.iter().map(|u| *u as i32).collect::<Vec<_>>(),
        "dnsNames": c.dns_names,
        "ips": c.ip_addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "subjectKeyId": encoding::hex(&c.subject_key_id),
        "authorityKeyId": encoding::hex(&c.authority_key_id),
        "publicKey": encoding::base64_encode(&c.public_key),
        "rawSubject": encoding::base64_encode(&c.raw_subject),
        "rawIssuer": encoding::base64_encode(&c.raw_issuer),
    })
}
