use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use super::*;

fn now() -> SystemTime {
    SystemTime::now()
}

fn server_req(name: &str) -> IssueRequest {
    IssueRequest {
        identity: Identity::new(KIND_SERVER, name),
        dns_names: vec![SERVER_NAME.to_string()],
        ips: vec!["10.0.0.2".parse::<IpAddr>().unwrap()],
        server: true,
        ..Default::default()
    }
}

#[test]
fn ca_round_trip() {
    let ca = Ca::new("c").unwrap();
    assert!(ca.cert.is_ca && ca.cert.basic_constraints_valid);
    assert_eq!(ca.cert.max_path_len, 0);
    assert_eq!(ca.cert.key_usage, KEY_USAGE_CERT_SIGN | KEY_USAGE_CRL_SIGN);
    assert_eq!(ca.cert.common_name, "armada-ca:c");
    assert_eq!(ca.cert.organization, vec!["armada".to_string()]);
    assert_eq!(ca.cert.subject_key_id.len(), 20);
    assert!(ca.cert.authority_key_id.is_empty());
    let life = ca.cert.not_after - ca.cert.not_before;
    assert_eq!(life, (CA_VALIDITY + CLOCK_SKEW).as_secs() as i64);
    let again = Ca::load(&ca.cert_pem, ca.key_pem().expose()).unwrap();
    assert_eq!(again.cert, ca.cert);
    // A key in its own file reads back the same.
    assert_eq!(
        PrivateKey::from_pem(ca.key_pem().expose()).unwrap().pkcs8(),
        ca.key.pkcs8()
    );
    assert_eq!(
        ca.key.pkcs8().expose().len(),
        138,
        "the PKCS#8 size of a P-256 key"
    );
}

#[test]
fn load_refusals() {
    let ca = Ca::new("c").unwrap();
    let other = Ca::new("o").unwrap();
    let (leaf, leaf_key) = ca.issue(&server_req("s")).unwrap();
    let cases: Vec<(&str, Vec<u8>, Vec<u8>, &str)> = vec![
        (
            "no cert",
            b"x".to_vec(),
            ca.key_pem().expose().to_vec(),
            "no PEM certificate found",
        ),
        (
            "not a CA",
            leaf.clone(),
            leaf_key.expose().to_vec(),
            "certificate is not a CA",
        ),
        (
            "no key",
            ca.cert_pem.clone(),
            b"x".to_vec(),
            "no PEM private key found",
        ),
        (
            "key as cert",
            ca.cert_pem.clone(),
            ca.cert_pem.clone(),
            "no PEM private key found",
        ),
        (
            "other key",
            ca.cert_pem.clone(),
            other.key_pem().expose().to_vec(),
            "CA key does not match certificate",
        ),
    ];
    for (what, cert, key, text) in cases {
        assert_eq!(
            Ca::load(&cert, &key).unwrap_err().to_string(),
            text,
            "{what}"
        );
    }
}

#[test]
fn issue() {
    let ca = Ca::new("c").unwrap();
    let (pem, key) = ca.issue(&server_req("cp-1")).unwrap();
    let c = parse_cert_pem(&pem).unwrap();
    assert_eq!(c.identity().unwrap(), Identity::new(KIND_SERVER, "cp-1"));
    assert_eq!(c.ext_key_usage, vec![ExtKeyUsage::ServerAuth]);
    assert_eq!(c.key_usage, KEY_USAGE_DIGITAL_SIGNATURE);
    assert!(!c.is_ca && c.basic_constraints_valid);
    assert_eq!(c.dns_names, vec![SERVER_NAME.to_string()]);
    assert_eq!(c.ip_addresses, vec!["10.0.0.2".parse::<IpAddr>().unwrap()]);
    assert_eq!(c.authority_key_id, ca.cert.subject_key_id);
    assert!(c.subject_key_id.is_empty());
    assert_eq!(
        PrivateKey::from_pem(key.expose()).unwrap().public_key(),
        c.public_key.as_slice()
    );
    c.check_signature_from(&ca.cert).unwrap();
    verify_server(&c, &ca.cert, now()).unwrap();
    assert_eq!(
        c.not_after - c.not_before,
        (LEAF_VALIDITY + CLOCK_SKEW).as_secs() as i64
    );

    let (both, _) = ca
        .issue(&IssueRequest {
            identity: etcd_member(),
            ips: vec!["10.0.0.2".parse().unwrap(), "fd00::1".parse().unwrap()],
            server: true,
            client: true,
            validity: Duration::from_secs(3600),
            ..Default::default()
        })
        .unwrap();
    let c = parse_cert_pem(&both).unwrap();
    assert_eq!(
        c.ext_key_usage,
        vec![ExtKeyUsage::ServerAuth, ExtKeyUsage::ClientAuth]
    );
    assert_eq!(c.ip_addresses.len(), 2);
    assert_eq!(
        c.not_after - c.not_before,
        3600 + CLOCK_SKEW.as_secs() as i64
    );

    for (req, text) in [
        (
            IssueRequest {
                identity: Identity::new("root", "x"),
                client: true,
                ..Default::default()
            },
            "unknown identity kind \"root\"",
        ),
        (
            IssueRequest {
                identity: Identity::new(KIND_USER, "../x"),
                client: true,
                ..Default::default()
            },
            "invalid identity name \"../x\"",
        ),
        (
            IssueRequest {
                identity: Identity::new(KIND_USER, "x"),
                ..Default::default()
            },
            "certificate needs server or client usage",
        ),
    ] {
        assert_eq!(ca.issue(&req).unwrap_err().to_string(), text);
    }
}

#[test]
fn validity_capped_at_the_ca() {
    let ca = Ca::new("c").unwrap();
    let (pem, _) = ca
        .issue(&IssueRequest {
            identity: Identity::new(KIND_USER, "u"),
            client: true,
            validity: Duration::from_secs(20 * 365 * DAY),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(parse_cert_pem(&pem).unwrap().not_after, ca.cert.not_after);
}

#[test]
fn verification_refusals() {
    let ca = Ca::new("c").unwrap();
    let other = Ca::new("other").unwrap();
    let (pem, _) = other.issue(&server_req("s")).unwrap();
    let foreign = parse_cert_pem(&pem).unwrap();
    let err = verify_server(&foreign, &ca.cert, now())
        .unwrap_err()
        .to_string();
    assert_eq!(
        err,
        "server certificate: x509: certificate signed by unknown authority"
    );

    let (pem, _) = ca
        .issue(&IssueRequest {
            identity: Identity::new(KIND_SERVER, "s"),
            dns_names: vec!["elsewhere".into()],
            server: true,
            ..Default::default()
        })
        .unwrap();
    let wrong_name = parse_cert_pem(&pem).unwrap();
    assert_eq!(
        verify_server(&wrong_name, &ca.cert, now())
            .unwrap_err()
            .to_string(),
        "server certificate: x509: certificate is valid for elsewhere, not armada-server"
    );
    let (pem, _) = ca
        .issue(&IssueRequest {
            identity: Identity::new(KIND_USER, "u"),
            client: true,
            ..Default::default()
        })
        .unwrap();
    let client = parse_cert_pem(&pem).unwrap();
    assert_eq!(
        client
            .verify(&ca.cert, None, ExtKeyUsage::ServerAuth, now())
            .unwrap_err()
            .to_string(),
        "x509: certificate specifies an incompatible key usage"
    );
    client
        .verify(&ca.cert, None, ExtKeyUsage::ClientAuth, now())
        .unwrap();

    let (pem, _) = ca.issue(&server_req("s")).unwrap();
    let ok = parse_cert_pem(&pem).unwrap();
    let later = SystemTime::UNIX_EPOCH + Duration::from_secs((ok.not_after + 1) as u64);
    let err = verify_server(&ok, &ca.cert, later).unwrap_err().to_string();
    assert!(
        err.starts_with(
            "server certificate: x509: certificate has expired or is not yet valid: current time "
        ),
        "{err}"
    );
}

#[test]
fn reissue_keeps_key_names_and_usages() {
    let ca = Ca::new("c").unwrap();
    let mut req = server_req("cp-1");
    req.validity = Duration::from_secs(3600);
    let (pem, key) = ca.issue(&req).unwrap();
    let old = parse_cert_pem(&pem).unwrap();
    let new = parse_cert_pem(&ca.reissue(&old, Duration::ZERO).unwrap()).unwrap();
    assert_eq!(new.public_key, old.public_key);
    assert_eq!(
        PrivateKey::from_pem(key.expose()).unwrap().public_key(),
        new.public_key.as_slice()
    );
    assert_eq!(
        (&new.common_name, &new.dns_names, &new.ip_addresses),
        (&old.common_name, &old.dns_names, &old.ip_addresses)
    );
    assert_eq!(new.ext_key_usage, old.ext_key_usage);
    assert_ne!(new.serial, old.serial);
    assert!(new.not_after - new.not_before > 300 * DAY as i64);
    new.check_signature_from(&ca.cert).unwrap();

    let other = Ca::new("other").unwrap();
    let (pem, _) = other
        .issue(&IssueRequest {
            identity: Identity::new(KIND_ADMIN, "eve"),
            client: true,
            ..Default::default()
        })
        .unwrap();
    let foreign = parse_cert_pem(&pem).unwrap();
    assert_eq!(
        ca.reissue(&foreign, Duration::ZERO)
            .unwrap_err()
            .to_string(),
        "certificate is not signed by this CA: x509: ECDSA verification failure"
    );
    // A CA's own certificate cannot sign: its key usage holds.
    assert!(ca.reissue(&ca.cert, Duration::ZERO).is_err());
}

#[test]
fn csr_signing() {
    let ca = Ca::new("c").unwrap();
    let (key, csr) = new_node_csr("node-2").unwrap();
    let nc = ca.sign_node_csr(&csr, "node-2", Duration::ZERO).unwrap();
    let c = parse_cert_pem(&nc.pem).unwrap();
    assert_eq!(c.identity().unwrap(), Identity::new(KIND_NODE, "node-2"));
    assert_eq!(c.serial_string(), nc.serial);
    assert_eq!((c.not_before, c.not_after), (nc.not_before, nc.not_after));
    assert_eq!(c.ext_key_usage, vec![ExtKeyUsage::ClientAuth]);
    assert!(c.dns_names.is_empty() && c.ip_addresses.is_empty() && !c.has_san);
    assert_eq!(
        c.not_after - c.not_before,
        (NODE_VALIDITY + CLOCK_SKEW).as_secs() as i64
    );
    assert_eq!(
        PrivateKey::from_pem(key.expose()).unwrap().public_key(),
        c.public_key.as_slice()
    );
    let capped = ca
        .sign_node_csr(&csr, "node-2", Duration::from_secs(400 * DAY))
        .unwrap();
    assert_eq!(
        capped.not_after - capped.not_before,
        (NODE_VALIDITY + CLOCK_SKEW).as_secs() as i64
    );

    // The CSR's name is ignored: the CA decides the identity.
    let (_, csr_other) = new_csr(&Identity::new(KIND_SERVER, "asks-for-more")).unwrap();
    for (signed, cn, life) in [
        (
            ca.sign_user_csr(&csr_other, "root").unwrap(),
            "user:root",
            LEAF_VALIDITY,
        ),
        (
            ca.sign_service_csr(&csr_other, "ci").unwrap(),
            "service:ci",
            SERVICE_VALIDITY,
        ),
        (
            ca.sign_metrics_csr(&csr_other, "prom").unwrap(),
            "metrics:prom",
            LEAF_VALIDITY,
        ),
    ] {
        let c = parse_cert_pem(&signed.pem).unwrap();
        assert_eq!(c.common_name, cn);
        assert_eq!(c.ext_key_usage, vec![ExtKeyUsage::ClientAuth]);
        assert_eq!(
            c.not_after - c.not_before,
            (life + CLOCK_SKEW).as_secs() as i64
        );
    }

    let mut tampered = csr.clone();
    let n = tampered.len();
    tampered[n - 5] ^= 0xff;
    let mut trailing = csr.clone();
    trailing.push(0);
    for (what, der, node, text) in [
        ("garbage", b"not a csr".to_vec(), "node-2", None),
        (
            "bad signature",
            tampered,
            "node-2",
            Some("CSR signature: x509: ECDSA verification failure"),
        ),
        (
            "trailing",
            trailing,
            "node-2",
            Some("parse CSR: x509: trailing data"),
        ),
        (
            "bad name",
            csr.clone(),
            "../x",
            Some("invalid identity name \"../x\""),
        ),
        (
            "empty name",
            csr.clone(),
            "",
            Some("invalid identity name \"\""),
        ),
    ] {
        let err = ca
            .sign_node_csr(&der, node, Duration::ZERO)
            .unwrap_err()
            .to_string();
        if let Some(text) = text {
            assert_eq!(err, text, "{what}");
        } else {
            assert!(err.starts_with("parse CSR: "), "{what}: {err}");
        }
    }
    assert!(new_csr(&Identity::new("root", "x")).is_err());
}

fn fake(not_before: i64, not_after: i64) -> Certificate {
    let ca = Ca::new("c").unwrap();
    Certificate {
        not_before,
        not_after,
        ..ca.cert
    }
}

#[test]
fn renewal_rules() {
    let now = SystemTime::now();
    let t = cert::unix(now).0;
    let skew = CLOCK_SKEW.as_secs() as i64;
    let cert = |age: i64, life: i64| fake(t - age - skew, t - age + life);
    let day = DAY as i64;
    let node = NODE_VALIDITY.as_secs() as i64;
    for (name, c, want) in [
        ("fresh", cert(3600, node), false),
        ("two thirds", cert(19 * day, node), false),
        ("last third", cert(21 * day, node), true),
        ("expired", cert(31 * day, node), true),
        (
            "legacy 1 year",
            cert(3600, LEAF_VALIDITY.as_secs() as i64),
            true,
        ),
        ("short", cert(10, 30), false),
        ("short and late", cert(25, 30), true),
    ] {
        assert_eq!(needs_renewal(&c, now), want, "{name}");
    }
    let c = cert(0, 30 * day);
    assert!(!renew_due(&c, now));
    assert!(!renew_due(&c, now + Duration::from_secs(19 * DAY)));
    assert!(renew_due(&c, now + Duration::from_secs(21 * DAY)));
    assert!(renew_due(&c, now + Duration::from_secs(40 * DAY)));
}

#[test]
fn join_tokens() {
    let tok = new_join_token().unwrap();
    let got = parse_join_token(&format!(" {}\n", tok.reveal())).unwrap();
    assert_eq!(got, tok);
    for s in [format!("{tok}"), format!("{tok:?}"), format!("{tok:#?}")] {
        assert!(!s.contains(tok.secret()), "{s}");
    }
    assert!(token_secret_matches(tok.secret(), &tok.secret_hash()));
    let other = new_join_token().unwrap();
    assert!(!token_secret_matches(other.secret(), &tok.secret_hash()));
    assert!(!token_secret_matches("", &tok.secret_hash()));
    let r = tok.reveal();
    for bad in [
        String::new(),
        tok.id.clone(),
        format!("{}.", tok.id),
        format!(".{}", tok.secret()),
        format!("{}.{}", tok.id, &tok.secret()[..63]),
        format!("{r}0"),
        r.to_uppercase(),
        format!("{}:{}", tok.id, tok.secret()),
        format!("{r}.x"),
    ] {
        assert_eq!(
            parse_join_token(&bad).unwrap_err().to_string(),
            "malformed join token (want <12 hex>.<64 hex>)",
            "{bad}"
        );
    }
}

#[test]
fn ca_pins() {
    let ca = Ca::new("c").unwrap();
    let h = parse_ca_hash(&ca_hash(&ca.cert)).unwrap();
    assert_eq!(h, ca.cert.fingerprint());
    for bad in [
        String::new(),
        ca.cert.fingerprint(),
        format!("sha1:{}", ca.cert.fingerprint()),
        format!("sha256:{}", &ca.cert.fingerprint()[..10]),
    ] {
        assert!(parse_ca_hash(&bad).is_err(), "{bad}");
    }

    let (pem, _) = ca.issue(&server_req("s")).unwrap();
    let leaf = parse_cert_pem(&pem).unwrap();
    let chain = vec![leaf.clone(), ca.cert.clone()];
    assert_eq!(pin_ca(&chain, &h, now()).unwrap(), ca.cert);

    let other = Ca::new("c").unwrap();
    let (pem, _) = other.issue(&server_req("s")).unwrap();
    let mitm = parse_cert_pem(&pem).unwrap();
    let cases: Vec<(&str, Vec<Certificate>, String, &str)> = vec![
        (
            "leaf only",
            vec![leaf.clone()],
            h.clone(),
            "server did not present its CA certificate",
        ),
        (
            "other CA",
            vec![mitm.clone(), other.cert.clone()],
            h.clone(),
            "the server's CA does not match the CA hash in the join command; refusing to join (possible man-in-the-middle)",
        ),
        (
            "leaf pinned",
            vec![leaf.clone(), leaf.clone()],
            leaf.fingerprint(),
            "pinned certificate is not a CA",
        ),
    ];
    for (what, chain, pin, text) in cases {
        assert_eq!(
            pin_ca(&chain, &pin, now()).unwrap_err().to_string(),
            text,
            "{what}"
        );
    }
    // The pinned CA's own certificate, its leaf swapped for one of another
    // CA with the same name.
    let err = pin_ca(&[mitm, ca.cert.clone()], &h, now())
        .unwrap_err()
        .to_string();
    assert_eq!(
        err,
        "server certificate is not valid for the pinned CA: x509: certificate signed by unknown authority (possibly because of \"x509: ECDSA verification failure\" while trying to verify candidate authority certificate \"armada-ca:c\")"
    );
}

#[test]
fn files() {
    let dir = std::env::temp_dir().join(format!(
        "armada-pki-{}-{:?}",
        std::process::id(),
        SystemTime::now()
    ));
    armada_fsutil::mkdir_private(&dir).unwrap();
    let ca = Ca::new("c").unwrap();
    ca.write_dir(&dir).unwrap();
    use std::os::unix::fs::PermissionsExt;
    for f in [FILE_CA_CERT, FILE_CA_KEY] {
        let mode = std::fs::metadata(dir.join(f)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{f}");
    }
    assert_eq!(Ca::load_dir(&dir).unwrap().cert, ca.cert);
    std::fs::set_permissions(
        dir.join(FILE_CA_KEY),
        std::fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    assert!(
        Ca::load_dir(&dir)
            .unwrap_err()
            .to_string()
            .ends_with("insecure permissions")
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn keys_redact_themselves() {
    let ca = Ca::new("c").unwrap();
    let pem = ca.key_pem();
    let body = String::from_utf8(pem.expose().to_vec()).unwrap();
    let line = body.lines().nth(1).unwrap().to_string();
    for s in [
        format!("{pem:?}"),
        format!("{pem}"),
        format!("{ca:?}"),
        format!("{:?}", ca.key),
    ] {
        assert!(!s.contains(&line), "{s}");
    }
}

#[test]
fn key_refusals() {
    assert_eq!(
        PrivateKey::from_pem(b"").unwrap_err().to_string(),
        "no PEM private key found"
    );
    // An Ed25519 key in PKCS#8.
    let ed = encoding::seq(&[
        vec![0x02, 0x01, 0x00],
        encoding::seq(&[encoding::tlv(0x06, encoding::oid::ED25519)]),
        encoding::tlv(0x04, &encoding::tlv(0x04, &[1; 32])),
    ]);
    assert_eq!(
        PrivateKey::from_pkcs8(&ed).unwrap_err().to_string(),
        "private key is not ECDSA"
    );
    assert!(PrivateKey::from_pkcs8(b"\x30\x00").is_err());
}
