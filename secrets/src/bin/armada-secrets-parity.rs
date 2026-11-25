//! The program Go's parity tests in internal/secrets drive
//! (ARMADA_SECRETS_BIN): `armada-secrets-parity COMMAND` with a JSON
//! request on stdin and a JSON answer on stdout, `{"error": TEXT}` when the
//! call fails. Bytes travel as hex. Built only with the `parity` feature;
//! never part of a release.

use std::io::Read;
use std::path::Path;

use armada_secrets::{
    Error, Keyring, Sealed, Value, generate_key_file, load_key_file, write_key_file,
};
use serde_json::{Value as Json, json};

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("read stdin");
    let req: Json = serde_json::from_str(&input).expect("JSON request");
    let answer = match run(&cmd, &req) {
        Ok(v) => v,
        Err(e) => json!({ "error": e.to_string(), "wrongKey": e == Error::WrongKey }),
    };
    println!("{answer}");
}

fn s<'a>(req: &'a Json, key: &str) -> &'a str {
    req[key].as_str().unwrap_or_default()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, Error> {
    if !s.len().is_multiple_of(2) {
        return Err(Error::Other("bad hex".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| Error::Other("bad hex".into())))
        .collect()
}

fn keyring(req: &Json) -> Result<Keyring, Error> {
    if let Some(path) = req["keyFile"].as_str() {
        return load_key_file(Path::new(path));
    }
    Keyring::new(&unhex(s(req, "key"))?)
}

fn run(cmd: &str, req: &Json) -> Result<Json, Error> {
    let version = req["version"].as_i64().unwrap_or(0);
    Ok(match cmd {
        "seal" => {
            let k = keyring(req)?;
            let v = Value::from(unhex(s(req, "value"))?);
            let sealed = k.seal(s(req, "scope"), s(req, "name"), version, &v)?;
            json!({ "keyId": sealed.key_id, "wrappedKey": hex(&sealed.wrapped_key), "ciphertext": hex(&sealed.ciphertext) })
        }
        "open" => {
            let k = keyring(req)?;
            let sealed = Sealed {
                key_id: s(req, "keyId").to_string(),
                wrapped_key: unhex(s(req, "wrappedKey"))?,
                ciphertext: unhex(s(req, "ciphertext"))?,
            };
            let v = k.open(&sealed, s(req, "scope"), s(req, "name"), version)?;
            json!({ "value": hex(v.bytes()), "shown": format!("{v} {v:?}") })
        }
        "generate-key-file" => {
            generate_key_file(Path::new(s(req, "path")))?;
            json!({})
        }
        "load-key-file" => {
            let k = load_key_file(Path::new(s(req, "path")))?;
            json!({ "id": k.id(), "export": hex(k.export().bytes()), "shown": format!("{k} {k:?}") })
        }
        "write-key-file" => {
            write_key_file(
                Path::new(s(req, "path")),
                &Value::from(unhex(s(req, "value"))?),
            )?;
            json!({})
        }
        other => return Err(Error::Other(format!("unknown command {other}"))),
    })
}
