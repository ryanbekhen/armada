//! The parity cases of Go's internal/pki tests, recorded once from Go
//! before the Go code was removed (ADR 0055, item 20): testdata/parity.json
//! holds
//! the CA, certificates, requests, keys, and tokens Go made and what Go
//! answered about each. With no Go, these tests check that the crate issues
//! and signs from Go's CA what Go issued and signed (compared by shape:
//! every extension in order, the raw names, the algorithms, the lifetime),
//! reads what Go wrote, and refuses what Go refused with Go's texts. The
//! fixture's keys are test keys made for it.

use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use armada_pki::encoding::{base64_decode, base64_encode};
use armada_pki::{
    Ca, Certificate, ExtKeyUsage, Identity, IssueRequest, NodeCert, PrivateKey, SERVER_NAME,
    ca_hash, hash_token_secret, needs_renewal, new_csr, parse_ca_hash, parse_cert_pem,
    parse_identity, parse_join_token, pin_ca, renew_due, token_secret_matches, verify_server,
};
use serde_json::{Value, json};
use x509_parser::prelude::{FromDer, X509Certificate, X509CertificationRequest};

fn fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/parity.json");
    let b = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&b).expect("the fixture is JSON")
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("{k} missing in {v}"))
}

fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array()
        .unwrap_or_else(|| panic!("{k} missing in {v}"))
}

fn b64(v: &Value, k: &str) -> Vec<u8> {
    base64_decode(s(v, k).as_bytes()).expect("base64")
}

fn at(v: &Value, k: &str) -> SystemTime {
    let ns = v[k].as_i64().expect("nanoseconds");
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(ns.unsigned_abs())
    }
}

fn go_ca(f: &Value) -> Ca {
    let ca = &f["ca"];
    Ca::load(s(ca, "cert").as_bytes(), s(ca, "key").as_bytes()).expect("Go's CA loads")
}

fn cert(pem: &[u8]) -> Certificate {
    parse_cert_pem(pem).unwrap_or_else(|e| panic!("parse {}: {e}", String::from_utf8_lossy(pem)))
}

fn expect_err<T>(what: &str, got: Result<T, armada_pki::Error>, want: &str) {
    match got {
        Ok(_) => panic!("{what}: Go refused with {want:?}; Rust did not"),
        Err(e) => assert_eq!(e.to_string(), want, "{what}: Rust's text, then Go's"),
    }
}

/// Go's shape of a certificate (record_test.go's shapeJSON), from its DER.
fn shape(der: &[u8]) -> Value {
    let (_, c) = X509Certificate::from_der(der).expect("DER");
    let tbs = &c.tbs_certificate;
    let mut exts = Vec::new();
    let mut ski = Vec::new();
    for e in tbs.extensions() {
        let id = e.oid.to_id_string();
        let v = if id == "2.5.29.14" {
            ski = e.value.to_vec();
            "ski".to_string()
        } else {
            base64_encode(e.value)
        };
        exts.push(format!("{id} {} {v}", e.critical));
    }
    let sig = match c.signature_algorithm.algorithm.to_id_string().as_str() {
        "1.2.840.10045.4.3.2" => "ECDSA-SHA256".to_string(),
        other => other.to_string(),
    };
    let spki = &tbs.subject_pki;
    let ecdsa = spki.algorithm.algorithm.to_id_string() == "1.2.840.10045.2.1";
    let curve256 = ecdsa
        && spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .is_some_and(|o| o.to_id_string() == "1.2.840.10045.3.1.7");
    let point = spki.subject_public_key.data.as_ref();
    // The identifier's OCTET STRING holds the truncated SHA-256 of the key.
    let sum = ring::digest::digest(&ring::digest::SHA256, point);
    let ski_from_key = ski.len() == 22 && ski[2..] == sum.as_ref()[..20] && curve256;
    let serial = tbs.raw_serial();
    assert!(
        serial.first().is_none_or(|b| b & 0x80 == 0) && serial.len() <= 17,
        "serial outside [0, 2^128)"
    );
    json!({
        "version": (tbs.version.0 + 1).to_string(),
        "sigAlg": sig,
        "pubAlg": if ecdsa { "ECDSA" } else { "other" },
        "curve256": curve256,
        "rawSubject": base64_encode(tbs.subject.as_raw()),
        "rawIssuer": base64_encode(tbs.issuer.as_raw()),
        "extensions": exts,
        "lifeSeconds": tbs.validity.not_after.timestamp() - tbs.validity.not_before.timestamp(),
        "skiFromKey": ski_from_key,
        "hasSKI": !ski.is_empty(),
    })
}

/// Rust's certificate has Go's shape: the lifetime within two seconds of
/// Go's (both count from the moment of issue), unless capped at the CA.
fn same_shape(what: &str, go: &Value, rust_der: &[u8], capped_at: Option<i64>) {
    let mut g = go.clone();
    let mut r = shape(rust_der);
    let (gl, rl) = (
        g["lifeSeconds"].as_i64().unwrap(),
        r["lifeSeconds"].as_i64().unwrap(),
    );
    match capped_at {
        Some(not_after) => {
            let c = Certificate::from_der(rust_der).unwrap();
            assert_eq!(c.not_after, not_after, "{what}: not capped at the CA");
        }
        None => assert!(
            (gl - rl).abs() <= 2,
            "{what}: lifetime Go {gl}s, Rust {rl}s"
        ),
    }
    g["lifeSeconds"] = json!(0);
    r["lifeSeconds"] = json!(0);
    if r != g {
        let differs: Vec<String> = g
            .as_object()
            .unwrap()
            .iter()
            .filter(|(k, v)| r.get(k.as_str()) != Some(v))
            .map(|(k, v)| format!("  {k}:\n    go   {v}\n    rust {}", r[k.as_str()]))
            .collect();
        panic!("{what}: the certificates differ\n{}", differs.join("\n"));
    }
}

fn der_of(pem: &[u8]) -> Vec<u8> {
    cert(pem).raw
}

/// A key Rust wrote is PKCS#8 as Go encodes it: Go's CA key's DER with
/// the private scalar and the public point in the same places.
fn key_like_go(f: &Value, key_pem: &[u8]) {
    let k = PrivateKey::from_pem(key_pem).expect("Rust's key");
    let go = &f["caKeyDER"];
    let (gder, d, point) = (b64(go, "pkcs8"), b64(go, "d"), b64(go, "point"));
    let rder = k.pkcs8().expose().to_vec();
    assert_eq!(rder.len(), gder.len(), "PKCS#8 length");
    let find = |hay: &[u8], needle: &[u8]| {
        hay.windows(needle.len())
            .position(|w| w == needle)
            .expect("in Go's DER")
    };
    let (dp, pp) = (find(&gder, &d), find(&gder, &point));
    let mask = |b: &[u8]| {
        let mut b = b.to_vec();
        b[dp..dp + 32].fill(0);
        b[pp..pp + point.len()].fill(0);
        b
    };
    assert_eq!(
        mask(&rder),
        mask(&gder),
        "Rust's PKCS#8 framing differs from Go's"
    );
    assert_eq!(
        &rder[pp..pp + point.len()],
        k.public_key(),
        "the public point's place"
    );
    let pem = String::from_utf8(key_pem.to_vec()).unwrap();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
}

fn issue_request(r: &Value) -> IssueRequest {
    IssueRequest {
        identity: Identity::new(s(r, "kind"), s(r, "name")),
        dns_names: arr(r, "dns")
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect(),
        ips: arr(r, "ips")
            .iter()
            .map(|v| v.as_str().unwrap().parse::<IpAddr>().unwrap())
            .collect(),
        server: r["server"].as_bool().unwrap(),
        client: r["client"].as_bool().unwrap(),
        validity: Duration::from_secs(r["validitySeconds"].as_u64().unwrap()),
    }
}

#[test]
fn issues_what_go_issues() {
    let f = fixture();
    let ca = go_ca(&f);
    // Go's CA key reads, and encodes again to Go's bytes.
    let key = PrivateKey::from_pem(s(&f["ca"], "key").as_bytes()).unwrap();
    assert_eq!(key.to_pem().expose(), s(&f["ca"], "key").as_bytes());
    assert_eq!(key.pkcs8().expose(), b64(&f["caKeyDER"], "pkcs8"));
    assert_eq!(ca.cert.fingerprint(), s(&f["ca"], "fingerprint"));
    let cases = arr(&f, "issue");
    assert_eq!(cases.len(), 9);
    for c in cases {
        let name = s(c, "case");
        let req = issue_request(&c["req"]);
        let before = SystemTime::now();
        let (pem, key) = ca
            .issue(&req)
            .unwrap_or_else(|e| panic!("{name}: Go issued it; Rust: {e}"));
        let capped = (name == "capped").then_some(ca.cert.not_after);
        same_shape(name, &c["shape"], &der_of(&pem), capped);
        key_like_go(&f, key.expose());
        let rc = cert(&pem);
        let k = PrivateKey::from_pem(key.expose()).unwrap();
        assert_eq!(
            rc.public_key,
            k.public_key(),
            "{name}: key and certificate pair"
        );
        rc.check_signature_from(&ca.cert)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(rc.identity().unwrap().to_string(), s(c, "identity"));
        let usage = if req.server {
            ExtKeyUsage::ServerAuth
        } else {
            ExtKeyUsage::ClientAuth
        };
        rc.verify(&ca.cert, None, usage, SystemTime::now())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        if req.server && req.dns_names.iter().any(|n| n == SERVER_NAME) {
            verify_server(&rc, &ca.cert, SystemTime::now())
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        // Backdated by the clock skew.
        let skew = f["clockSkewSeconds"].as_i64().unwrap();
        let issued = before.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        assert!(
            (rc.not_before - (issued - skew)).abs() <= 2,
            "{name}: NotBefore not backdated by the clock skew"
        );
    }
    for c in arr(&f, "issueRefused") {
        let req = issue_request(&c["req"]);
        expect_err(&format!("{:?}", c["req"]), ca.issue(&req), s(c, "error"));
    }
}

#[test]
fn new_ca_and_load_refusals() {
    let f = fixture();
    let go = &f["newCA"];
    let ca = Ca::new(s(go, "name")).unwrap();
    same_shape("CA", &go["shape"], &ca.cert.raw, None);
    assert_eq!(shape(&ca.cert.raw)["skiFromKey"], json!(true));
    key_like_go(&f, ca.key_pem().expose());
    ca.cert.check_signature_from(&ca.cert).unwrap();
    for c in arr(&f, "loadRefused") {
        expect_err(
            s(c, "case"),
            Ca::load(s(c, "cert").as_bytes(), s(c, "key").as_bytes()),
            s(c, "error"),
        );
    }
}

fn sign(
    ca: &Ca,
    as_: &str,
    csr: &[u8],
    name: &str,
    validity: u64,
) -> Result<NodeCert, armada_pki::Error> {
    match as_ {
        "node" => ca.sign_node_csr(csr, name, Duration::from_secs(validity)),
        "user" => ca.sign_user_csr(csr, name),
        "service" => ca.sign_service_csr(csr, name),
        "metrics" => ca.sign_metrics_csr(csr, name),
        other => panic!("unknown signer {other}"),
    }
}

#[test]
fn signs_csrs_as_go_does() {
    let f = fixture();
    let ca = go_ca(&f);
    let csr = b64(&f, "csr");
    let cases = arr(&f, "signed");
    assert_eq!(cases.len(), 12);
    for c in cases {
        let as_ = s(c, "as");
        let v = c["validitySeconds"].as_u64().unwrap();
        let nc = sign(&ca, as_, &csr, "n-1", v).unwrap_or_else(|e| panic!("{as_}: {e}"));
        let what = format!("{as_} for {v}s");
        same_shape(&what, &c["shape"], &der_of(&nc.pem), None);
        let rc = cert(&nc.pem);
        assert_eq!(nc.serial, rc.serial_string(), "{what}: serial");
        assert_eq!(nc.not_before, rc.not_before, "{what}: notBefore");
        assert_eq!(nc.not_after, rc.not_after, "{what}: notAfter");
        assert_eq!(
            rc.identity().unwrap().to_string(),
            s(c, "identity"),
            "{what}"
        );
    }

    // Rust's request looks like Go's own, and Go's CA (here Rust, with
    // Go's key) signs it.
    let go = &f["nodeCSR"];
    let (key, rust_csr) = new_csr(&Identity::new("node", "web-1")).unwrap();
    key_like_go(&f, key.expose());
    let go_csr = b64(go, "csr");
    let (_, gr) = X509CertificationRequest::from_der(&go_csr).unwrap();
    let (_, rr) = X509CertificationRequest::from_der(&rust_csr).unwrap();
    let ginfo = &gr.certification_request_info;
    let rinfo = &rr.certification_request_info;
    assert_eq!(base64_encode(ginfo.subject.as_raw()), s(go, "rawSubject"));
    assert_eq!(rinfo.subject.as_raw(), ginfo.subject.as_raw(), "subject");
    assert_eq!(
        rinfo.raw.len() as u64,
        go["tbsLength"].as_u64().unwrap(),
        "request length"
    );
    assert_eq!(
        rr.signature_algorithm.algorithm.to_id_string(),
        "1.2.840.10045.4.3.2",
        "{}",
        s(go, "sigAlg")
    );
    assert_eq!(rinfo.version.0 as u64, go["version"].as_u64().unwrap());
    assert!(rinfo.attributes().is_empty(), "no extensions");
    let nc = ca
        .sign_node_csr(&rust_csr, "web-1", Duration::ZERO)
        .unwrap();
    let k = PrivateKey::from_pem(key.expose()).unwrap();
    assert_eq!(cert(&nc.pem).public_key, k.public_key());
    let bad = &f["newCSRRefused"];
    expect_err(
        "new-csr",
        new_csr(&Identity::new(s(bad, "kind"), s(bad, "name"))),
        s(bad, "error"),
    );

    // Refusals: Go's text where it is Armada's own, and the prefix where
    // it is a parser's.
    for c in arr(&f, "signRefused") {
        let what = format!("{}/{}", s(c, "case"), s(c, "as"));
        let got = sign(&ca, s(c, "as"), &b64(c, "csr"), s(c, "name"), 0);
        let want = s(c, "error");
        match got {
            Ok(_) => panic!("{what}: Go refused with {want:?}; Rust signed it"),
            Err(e) if c["prefixOnly"].as_bool().unwrap() => {
                assert!(want.starts_with("parse CSR: "), "{what}: Go {want:?}");
                assert!(e.to_string().starts_with("parse CSR: "), "{what}: Rust {e}");
            }
            Err(e) => assert_eq!(e.to_string(), want, "{what}: Rust's text, then Go's"),
        }
    }
}

#[test]
fn reissues_as_go_does() {
    let f = fixture();
    let ca = go_ca(&f);
    let r = &f["reissue"];
    let old = cert(s(r, "cert").as_bytes());
    let key = PrivateKey::from_pem(s(r, "key").as_bytes()).unwrap();
    for c in arr(r, "cases") {
        let v = c["validitySeconds"].as_u64().unwrap();
        let pem = ca.reissue(&old, Duration::from_secs(v)).unwrap();
        same_shape(
            &format!("reissue for {v}s"),
            &c["shape"],
            &der_of(&pem),
            None,
        );
        let rc = cert(&pem);
        assert_eq!(rc.public_key, key.public_key(), "the old key");
        assert_ne!(rc.serial, old.serial, "a new serial");
    }
    for c in arr(&f, "reissueRefused") {
        let got = ca.reissue(&cert(s(c, "cert").as_bytes()), Duration::ZERO);
        expect_err(s(c, "case"), got, s(c, "error"));
    }
}

#[test]
fn reads_identities_as_go_does() {
    let f = fixture();
    for c in arr(&f, "identities") {
        let cn = s(c, "cn");
        match (parse_identity(cn), c.get("error").and_then(Value::as_str)) {
            (Err(e), Some(want)) => assert_eq!(e.to_string(), want, "{cn:?}"),
            (Ok(id), None) => {
                assert_eq!(
                    (id.kind.as_str(), id.name.as_str()),
                    (s(c, "kind"), s(c, "name")),
                    "{cn:?}"
                )
            }
            (got, want) => panic!("{cn:?}: Go {want:?}, Rust {got:?}"),
        }
    }
    for c in arr(&f, "readCert") {
        let rc = cert(s(c, "cert").as_bytes());
        assert_eq!(rc.fingerprint(), s(c, "fingerprint"));
        if let Some(want) = c["identityError"].as_str() {
            expect_err("identity", rc.identity(), want);
            continue;
        }
        let id = rc.identity().unwrap();
        assert_eq!(id.to_string(), s(c, "identity"));
        let principal = id.principal().map(|p| p.to_string()).unwrap_or_default();
        assert_eq!(principal, s(c, "principal"), "{id}");
        assert_eq!(rc.serial_string(), s(c, "serial"), "{id}");
        assert_eq!(ca_hash(&rc), s(c, "caHash"), "{id}");
    }
    expect_err("junk", parse_cert_pem(b"junk"), s(&f, "junkCert"));
}

#[test]
fn renewal_as_go_decides() {
    let f = fixture();
    for c in arr(&f, "renewal") {
        let rc = cert(s(c, "cert").as_bytes());
        for a in arr(c, "at") {
            let now = at(a, "now");
            let what = format!("{}s certificate at {now:?}", rc.not_after - rc.not_before);
            assert_eq!(
                renew_due(&rc, now),
                a["renewDue"].as_bool().unwrap(),
                "{what}: renewDue"
            );
            assert_eq!(
                needs_renewal(&rc, now),
                a["needsRenewal"].as_bool().unwrap(),
                "{what}: needsRenewal"
            );
        }
    }
}

#[test]
fn verifies_servers_as_go_does() {
    let f = fixture();
    let ca = go_ca(&f);
    for c in arr(&f, "verifyServer") {
        let got = verify_server(&cert(s(c, "cert").as_bytes()), &ca.cert, at(c, "now"));
        let want = s(c, "error");
        match got {
            Ok(()) => assert_eq!(want, "", "{}: Go refused it", s(c, "case")),
            Err(e) => assert_eq!(e.to_string(), want, "{}", s(c, "case")),
        }
    }
}

#[test]
fn pins_cas_as_go_does() {
    let f = fixture();
    for c in arr(&f, "pinCA") {
        let chain: Vec<Certificate> = arr(c, "chain")
            .iter()
            .map(|p| cert(p.as_str().unwrap().as_bytes()))
            .collect();
        let got = pin_ca(&chain, s(c, "hash"), at(c, "now"));
        match (got, c.get("error").and_then(Value::as_str)) {
            (Err(e), Some(want)) => assert_eq!(e.to_string(), want, "{}", s(c, "case")),
            (Ok(ca), None) => assert_eq!(ca.fingerprint(), s(c, "fingerprint"), "{}", s(c, "case")),
            (got, want) => panic!("{}: Go {want:?}, Rust {got:?}", s(c, "case")),
        }
    }
}

#[test]
fn join_tokens_as_go_reads_them() {
    let f = fixture();
    let j = &f["joinToken"];
    let t = parse_join_token(s(j, "token")).unwrap();
    assert_eq!(t.id, s(j, "id"));
    assert_eq!(t.secret_hash(), s(j, "hash"));
    assert_eq!(t.to_string(), s(j, "shown"));
    assert_eq!(format!("{t:?}"), s(j, "debug"));
    for c in arr(&f, "joinTokens") {
        let got = parse_join_token(s(c, "token"));
        match (got, c["error"].as_str()) {
            (Err(e), Some(want)) => assert_eq!(e.to_string(), want, "{:?}", s(c, "token")),
            (Ok(_), None) => {}
            (got, want) => panic!("{:?}: Go {want:?}, Rust {got:?}", s(c, "token")),
        }
    }
    for c in arr(&f, "tokenMatches") {
        assert_eq!(
            token_secret_matches(s(c, "secret"), s(c, "hash")),
            c["match"].as_bool().unwrap(),
            "{c}"
        );
        assert_eq!(hash_token_secret(s(c, "secret")), s(c, "secretHash"));
    }
    for c in arr(&f, "caHashes") {
        match (
            parse_ca_hash(s(c, "hash")),
            c.get("error").and_then(Value::as_str),
        ) {
            (Err(e), Some(want)) => assert_eq!(e.to_string(), want, "{:?}", s(c, "hash")),
            (Ok(h), None) => assert_eq!(h, s(c, "hex")),
            (got, want) => panic!("{:?}: Go {want:?}, Rust {got:?}", s(c, "hash")),
        }
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let d =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("pki-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

#[test]
fn ca_files_as_go_reads_them() {
    let f = fixture();
    let dir = temp_dir("files");
    let dir_text = dir.to_str().unwrap().to_string();
    let write = |name: &str, content: &str, mode: u32| {
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    write("ca.crt", s(&f["ca"], "cert"), 0o600);
    write("ca.key", s(&f["ca"], "key"), 0o600);
    let ca = Ca::load_dir(&dir).expect("Go's CA files");
    assert_eq!(ca.cert.fingerprint(), s(&f["ca"], "fingerprint"));
    let files = &f["caFiles"];
    for c in arr(files, "modes") {
        write(
            "ca.key",
            s(&f["ca"], "key"),
            c["mode"].as_u64().unwrap() as u32,
        );
        expect_err(
            "mode",
            Ca::load_dir(&dir),
            &s(c, "error").replace("{dir}", &dir_text),
        );
    }
    expect_err(
        "missing",
        Ca::load_dir(&dir.join("none")),
        &s(files, "missing").replace("{dir}", &dir_text),
    );
    // Rust writes the CA as init does: both files 0600, read back.
    let rdir = dir.join("rust");
    std::fs::create_dir(&rdir).unwrap();
    let rca = Ca::new("c").unwrap();
    rca.write_dir(&rdir).unwrap();
    for name in ["ca.crt", "ca.key"] {
        let mode = std::fs::metadata(rdir.join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }
    assert_eq!(Ca::load_dir(&rdir).unwrap().cert, rca.cert);
    let _ = std::fs::remove_dir_all(&dir);
}
