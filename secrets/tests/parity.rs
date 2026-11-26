//! The parity cases of Go's internal/secrets tests, recorded once from Go
//! before the Go code was removed (ADR 0055, item 20): testdata/parity.json
//! holds
//! what Go sealed, refused, and wrote; these tests check the crate
//! opens, refuses, and writes the same with no Go.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use armada_secrets::{
    Error, Keyring, Sealed, Value, generate_key_file, load_key_file, write_key_file,
};
use serde_json::Value as Json;

fn fixture() -> Json {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/parity.json");
    let b = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&b).expect("the fixture is JSON")
}

fn s<'a>(v: &'a Json, k: &str) -> &'a str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("{k} missing in {v}"))
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sealed(v: &Json) -> Sealed {
    Sealed {
        key_id: s(v, "keyId").to_string(),
        wrapped_key: unhex(s(v, "wrappedKey")),
        ciphertext: unhex(s(v, "ciphertext")),
    }
}

/// Checks Rust refused as Go did: the same text (the directory written as
/// {dir}) and whether it is ErrWrongKey.
fn same_error<T>(what: &str, got: Result<T, Error>, want: &Json, dir: &str) {
    let text = s(want, "error").replace("{dir}", dir);
    match got {
        Ok(_) => panic!("{what}: Go refused with {text:?}; Rust did not"),
        Err(e) => {
            assert_eq!(e.to_string(), text, "{what}: Rust's text, then Go's");
            assert_eq!(
                e == Error::WrongKey,
                want["wrongKey"].as_bool().unwrap_or(false),
                "{what}: the wrong key or not"
            );
        }
    }
}

fn version(v: &Json) -> i64 {
    v["version"].as_i64().expect("version")
}

#[test]
fn opens_what_go_sealed() {
    let f = fixture();
    let k = Keyring::new(&unhex(s(&f, "key"))).expect("the key");
    assert_eq!(k.id(), s(&f, "keyId"));
    assert_eq!(k.to_string(), s(&f, "shown"));
    let cases = f["sealed"].as_array().expect("sealed");
    assert_eq!(cases.len(), 5);
    for c in cases {
        let what = format!("{:?}/{:?}", s(c, "scope"), s(c, "name"));
        let go = sealed(&c["sealed"]);
        let v = k
            .open(&go, s(c, "scope"), s(c, "name"), version(c))
            .unwrap_or_else(|e| panic!("{what}: Rust does not open Go's: {e}"));
        assert_eq!(hex(v.bytes()), s(c, "value"), "{what}");
        assert_eq!(format!("{v} {v:?}"), s(c, "shown"), "{what}: shown");
        // Rust seals the same value: Go's key ID and lengths, a fresh
        // nonce, and it opens again.
        let r = k
            .seal(s(c, "scope"), s(c, "name"), version(c), &v)
            .expect("seal");
        assert_eq!(r.key_id, go.key_id, "{what}");
        assert_eq!(r.wrapped_key.len(), go.wrapped_key.len(), "{what}");
        assert_eq!(r.ciphertext.len(), go.ciphertext.len(), "{what}");
        assert_ne!(r.ciphertext, go.ciphertext, "{what}: a fresh nonce");
        let again = k
            .open(&r, s(c, "scope"), s(c, "name"), version(c))
            .expect("open");
        assert_eq!(again.bytes(), v.bytes(), "{what}");
    }
}

#[test]
fn refuses_what_go_refused() {
    let f = fixture();
    let cases = f["refused"].as_array().expect("refused");
    assert_eq!(cases.len(), 12);
    for c in cases {
        let k = Keyring::new(&unhex(s(c, "key"))).expect("the key");
        let got = k.open(
            &sealed(&c["sealed"]),
            s(c, "scope"),
            s(c, "name"),
            version(c),
        );
        same_error(s(c, "case"), got, &c["want"], "");
    }
    let k = Keyring::new(&unhex(s(&f, "key"))).expect("the key");
    let big = Value::new(&vec![0u8; armada_secrets::MAX_SIZE + 1]);
    same_error("too large", k.seal("s", "n", 1, &big), &f["tooBig"], "");
    for c in f["keySizes"].as_array().expect("keySizes") {
        let n = c["size"].as_u64().expect("size") as usize;
        same_error(
            &format!("{n}-byte key"),
            Keyring::new(&vec![0u8; n]),
            &c["want"],
            "",
        );
    }
}

fn write(path: &Path, content: &[u8], mode: u32) {
    std::fs::write(path, content).expect("write");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn temp_dir(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("secrets-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

#[test]
fn key_files_as_go_reads_and_writes_them() {
    let f = fixture();
    let dir = temp_dir("files");
    let dir_text = dir.to_str().expect("a UTF-8 path").to_string();

    // Go's key file reads as Go read it.
    let kf = &f["keyFile"];
    let go_path = dir.join("go.key");
    write(&go_path, s(kf, "content").as_bytes(), 0o600);
    let k = load_key_file(&go_path).expect("Go's key file");
    assert_eq!(k.id(), s(kf, "id"));
    assert_eq!(hex(k.export().bytes()), s(kf, "export"));
    assert_eq!(format!("{k} {k:?}"), s(kf, "shown"));

    // Rust writes one as Go does: 0600, 64 hex digits and a newline.
    let rust_path = dir.join("rust.key");
    generate_key_file(&rust_path).expect("generate");
    let meta = std::fs::metadata(&rust_path).expect("stat");
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let b = std::fs::read(&rust_path).expect("read");
    assert_eq!(b.len(), 65);
    assert_eq!(b[64], b'\n');
    assert!(
        b[..64]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
    );
    load_key_file(&rust_path).expect("Rust's key file");

    // An exported key written again reads as the same key.
    let exported = dir.join("exported.key");
    write_key_file(&exported, &Value::new(&unhex(s(kf, "export")))).expect("write");
    assert_eq!(load_key_file(&exported).expect("load").id(), s(kf, "id"));

    // Go's refusals, with its texts.
    for c in f["loadKeyFile"].as_array().expect("loadKeyFile") {
        let path = dir.join(s(c, "file"));
        if c["dir"].as_bool() == Some(true) {
            std::fs::create_dir(&path).expect("mkdir");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        } else if c["missing"].as_bool() != Some(true) {
            write(
                &path,
                s(c, "content").as_bytes(),
                c["mode"].as_u64().expect("mode") as u32,
            );
        }
        let got = load_key_file(&path);
        if c.get("want").is_some_and(|w| !w.is_null()) {
            same_error(s(c, "case"), got, &c["want"], &dir_text);
        } else {
            let k = got.unwrap_or_else(|e| panic!("{}: Go read it; Rust: {e}", s(c, "case")));
            assert_eq!(k.id(), s(c, "id"), "{}", s(c, "case"));
        }
    }
    for c in f["writeKeyFile"].as_array().expect("writeKeyFile") {
        let got = write_key_file(&dir.join(s(c, "file")), &Value::new(&unhex(s(c, "value"))));
        same_error(s(c, "case"), got, &c["want"], &dir_text);
    }
    same_error(
        "generate over an existing file",
        generate_key_file(&go_path),
        &f["generateExisting"],
        &dir_text,
    );
    let _ = std::fs::remove_dir_all(&dir);
}
