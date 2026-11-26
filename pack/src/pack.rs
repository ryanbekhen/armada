//! The pack: a gzipped tar, MANIFEST.json first, then every file by name
//! in byte order, as Go's `embedded.Pack` writes it; its tar is the same
//! bytes, header for header (USTAR, mode 0644 for the manifest and 0755
//! for programs, owner 0, time 0). The gzip stream is flate2's at the
//! default level: a valid stream of the same tar, not Go's compressor's
//! bytes, which change with Go's releases anyway.

use std::collections::BTreeMap;
use std::io::{self, Write};

use flate2::Compression;
use flate2::GzBuilder;
use serde::Serialize;

use crate::fetch::sum_hex;

/// manifestName: the first entry of a pack.
pub const MANIFEST_NAME: &str = "MANIFEST.json";
/// The pack's limits, as the readers check them (bundle.go, daemon's
/// pack.rs).
pub const MAX_PACK_FILES: usize = 32;
pub const MAX_FILE_SIZE: u64 = 256 << 20;

const BLOCK: usize = 512;

/// Manifest describes a pack (field order as Go's struct).
#[derive(Debug, Serialize)]
pub struct Manifest {
    pub arch: String,
    pub versions: BTreeMap<String, String>,
    pub files: BTreeMap<String, String>,
}

/// manifest_json: json.MarshalIndent(m, "", "  "), Go's HTML escaping
/// included.
pub fn manifest_json(m: &Manifest) -> Vec<u8> {
    let s = serde_json::to_string_pretty(m).expect("manifest");
    s.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
        .into_bytes()
}

/// pack builds a pack from files, which maps names in the pack to their
/// contents.
pub fn pack(
    arch: &str,
    versions: &BTreeMap<String, String>,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let mut m = Manifest {
        arch: arch.to_string(),
        versions: versions.clone(),
        files: BTreeMap::new(),
    };
    for (n, b) in files {
        check_name(n)?;
        m.files.insert(n.clone(), sum_hex(b));
    }
    let mut z = GzBuilder::new().write(Vec::new(), Compression::default());
    write_tar(&mut z, &manifest_json(&m), files).map_err(|e| e.to_string())?;
    z.finish().map_err(|e| e.to_string())
}

/// write_tar writes the pack's tar: the manifest, then files in byte
/// order of their names, then two zero blocks.
pub fn write_tar(
    w: &mut impl Write,
    manifest: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
) -> io::Result<()> {
    add(w, MANIFEST_NAME, 0o644, manifest)?;
    for (n, b) in files {
        add(w, n, 0o755, b)?;
    }
    w.write_all(&[0u8; 2 * BLOCK])
}

fn add(w: &mut impl Write, name: &str, mode: i64, b: &[u8]) -> io::Result<()> {
    w.write_all(&ustar_header(name, mode, b.len() as i64)?)?;
    w.write_all(b)?;
    let pad = (BLOCK - b.len() % BLOCK) % BLOCK;
    w.write_all(&vec![0u8; pad])
}

/// ustar_header: archive/tar's writeUSTARHeader for a header with Name,
/// Mode, Size, and Typeflag TypeReg (templateV7Plus, setFormat).
fn ustar_header(name: &str, mode: i64, size: i64) -> io::Result<[u8; BLOCK]> {
    if name.len() > 100 {
        return Err(io::Error::other(format!("{name}: name too long")));
    }
    let mut b = [0u8; BLOCK];
    b[156] = b'0';
    fmt_str(&mut b[0..100], name);
    fmt_octal(&mut b[100..108], mode);
    fmt_octal(&mut b[108..116], 0);
    fmt_octal(&mut b[116..124], 0);
    fmt_octal(&mut b[124..136], size);
    fmt_octal(&mut b[136..148], 0);
    fmt_octal(&mut b[329..337], 0);
    fmt_octal(&mut b[337..345], 0);
    b[257..263].copy_from_slice(b"ustar\0");
    b[263..265].copy_from_slice(b"00");
    let sum: i64 = b
        .iter()
        .enumerate()
        .map(|(i, &c)| if (148..156).contains(&i) { b' ' } else { c } as i64)
        .sum();
    fmt_octal(&mut b[148..155], sum);
    b[155] = b' ';
    Ok(b)
}

fn fmt_str(b: &mut [u8], s: &str) {
    b[..s.len()].copy_from_slice(s.as_bytes());
    if s.len() < b.len() {
        b[s.len()] = 0;
    }
}

fn fmt_octal(b: &mut [u8], x: i64) {
    let mut s = format!("{x:o}");
    if b.len() > s.len() + 1 {
        s = "0".repeat(b.len() - s.len() - 1) + &s;
    }
    fmt_str(b, &s);
}

/// checkName accepts only plain relative names such as "runc" or
/// "cni/bridge".
pub fn check_name(n: &str) -> Result<(), String> {
    if n.is_empty()
        || n == MANIFEST_NAME
        || clean(n) != n
        || n.starts_with('/')
        || n.starts_with("../")
        || n == ".."
        || n.contains(['\\', '\0'])
    {
        return Err(format!("bundle: invalid file name {n:?}"));
    }
    Ok(())
}

/// clean: Go's path.Clean.
pub fn clean(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let rooted = p.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|l| *l != "..") {
                    out.pop();
                } else if !rooted {
                    out.push("..");
                }
            }
            s => out.push(s),
        }
    }
    let joined = out.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".into(),
        (false, false) => joined,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["runc", "cni/bridge", "."] {
            assert!(check_name(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "/runc",
            "../x",
            "..",
            "a//b",
            "a/./b",
            "a/",
            "a\\b",
            "a\0",
            "MANIFEST.json",
            "a/../b",
        ] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn clean_is_gos() {
        for (p, want) in [
            ("", "."),
            ("a/b/../c", "a/c"),
            ("/../a", "/a"),
            ("../../a", "../../a"),
            ("a/", "a"),
            ("//a//b/", "/a/b"),
        ] {
            assert_eq!(clean(p), want, "{p}");
        }
    }

    #[test]
    fn manifest_is_marshal_indent() {
        let m = Manifest {
            arch: "amd64".into(),
            versions: [("runc".to_string(), "1.5.2".to_string())].into(),
            files: [("runc".to_string(), "ab".to_string())].into(),
        };
        assert_eq!(
            String::from_utf8(manifest_json(&m)).unwrap(),
            "{\n  \"arch\": \"amd64\",\n  \"versions\": {\n    \"runc\": \"1.5.2\"\n  },\n  \"files\": {\n    \"runc\": \"ab\"\n  }\n}"
        );
    }

    /// testdata/pack.tar is the tar inside the pack Go's embedded.Pack
    /// built for these inputs (written once, before Go's code left): the
    /// pack's tar is the same bytes, manifest included.
    #[test]
    fn tar_is_gos() {
        let files: BTreeMap<String, Vec<u8>> = [
            ("runc".to_string(), vec![b'r'; 1000]),
            ("cni/bridge".to_string(), b"bridge\n".to_vec()),
            ("empty".to_string(), Vec::new()),
            ("armada-log".to_string(), [0u8, 1, 2].repeat(600)),
        ]
        .into();
        let versions: BTreeMap<String, String> = [
            ("runc", "1.5.2"),
            ("cni-plugins", "1.9.1"),
            ("armada-log", "source"),
            ("odd", "<&>"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .into();
        let p = pack("arm64", &versions, &files).unwrap();
        let mut tar = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&p[..]), &mut tar).unwrap();
        let want = include_bytes!("../testdata/pack.tar");
        assert!(tar == want, "the pack's tar differs from Go's");
        // The gzip header Go writes: no name, time 0, unknown OS.
        assert_eq!(&p[..10], b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff");
    }

    #[test]
    fn header_bytes() {
        // A header archive/tar writes for {Name: "runc", Mode: 0755, Size:
        // 5, Typeflag: TypeReg}.
        let h = ustar_header("runc", 0o755, 5).unwrap();
        assert_eq!(&h[0..5], b"runc\0");
        assert_eq!(&h[100..108], b"0000755\0");
        assert_eq!(&h[124..136], b"00000000005\0");
        assert_eq!(&h[136..148], b"00000000000\0");
        assert_eq!(&h[257..265], b"ustar\x0000");
        assert_eq!(&h[329..345], b"0000000\x000000000\0");
        assert_eq!(h[155], b' ');
        assert_eq!(h[154], 0);
    }
}
