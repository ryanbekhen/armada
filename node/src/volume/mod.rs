//! Volume archives (ADR 0023) as the Go agent writes, restores, and
//! measures them (internal/agent/volume.go, internal/volbackup/walk.go;
//! ADR 0054 step 5, second part). The agent keeps the volume session, the
//! pause and resume of the app, and the 64 KiB messages; it runs these with
//! the archive's bytes on standard streams, and does a call itself when
//! armada-node fails before the stream is touched.
//!
//!   armada-node volume archive DIR
//!       stdout: DIR as a gzipped tar (writeArchive: "." first, then every
//!       entry depth first in byte order, links stored, sockets, devices,
//!       and pipes left out, the tar headers Go's archive/tar writes);
//!       descriptor 3, once the archive ends: {} or {"error": TEXT,
//!       "changed": BOOL} (changed: volbackup.ErrChanged). A failure to
//!       write stdout ends the program with no answer.
//!   armada-node volume restore DIR
//!       descriptor 3: "ready" and a newline before stdin is read, then {}
//!       or {"error": TEXT}; stdin: a gzipped tar (restoreArchive: into a
//!       new directory next to DIR, swapped in only when every entry was
//!       restored); descriptor 4, read when stdin ends: empty for the
//!       archive's end, or the agent's error reading the session as a JSON
//!       string, which the restore fails with where Go's reader would.
//!   armada-node volume size DIR...
//!       stdout: {"sizes": [N]}, the regular files of each DIR added up
//!       (volumeSize; 0 for a DIR that cannot be opened)
//!
//! Every lookup in a volume is made beneath the volume's directory
//! (openat2 RESOLVE_BENEATH), as Go's os.Root makes it, and every entry is
//! opened without blocking and refused unless it is the entry just looked
//! up. A kernel without openat2 fails the call before any output, so the
//! agent does it.
//!
//! Two variables are test hooks, set only by Go's parity tests and read only
//! by builds with test hooks (src/hooks.rs; nativevolume_test.go):
//! ARMADA_NODE_TEST_VOLUME_HOOK=ENTRY:fifo|truncate
//! replaces or empties the regular file ENTRY of the volume being archived
//! between its lookup and its open (archiveHook), and
//! ARMADA_NODE_TEST_VOLUME_SPACE=BYTES,TOTAL,INODES,TOTAL|unknown is the
//! free space a restore sees (restoreSpace).

pub mod archive;
pub(crate) mod errno;
pub mod gzip;
pub mod restore;
pub mod walk;

use std::fs::File;
use std::io::Write;
use std::os::fd::FromRawFd;

pub fn command(args: &[&str]) -> Result<(), String> {
    match args {
        ["archive", dir] => archive::command(dir),
        ["restore", dir] => restore::command(dir),
        ["size", dirs @ ..] if !dirs.is_empty() => size_command(dirs),
        [
            op @ ("snapshot" | "snapshots" | "restore-snapshot" | "prune" | "target"),
            rest @ ..,
        ] => crate::volbackup::command(op, rest),
        _ => Err(format!(
            "unknown volume command {args:?}; try: volume archive DIR, volume restore DIR, volume size DIR..., volume snapshot|snapshots|restore-snapshot|prune [--extra-ca FILE], volume target"
        )),
    }
}

fn size_command(dirs: &[&str]) -> Result<(), String> {
    let mut sizes = Vec::with_capacity(dirs.len());
    for d in dirs {
        sizes.push(walk::size(d.as_bytes())?);
    }
    println!("{}", serde_json::json!({ "sizes": sizes }));
    Ok(())
}

/// The descriptor a call answers on (3), or stderr when it was not given
/// one (run by hand).
pub(crate) fn answer_file(fd: i32) -> Option<File> {
    // SAFETY: fcntl only reads the descriptor's flags.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return None;
    }
    // SAFETY: the descriptor is open and handed to this program for it.
    Some(unsafe { File::from_raw_fd(fd) })
}

pub(crate) fn send_answer(f: &mut Option<File>, v: &serde_json::Value) -> Result<(), String> {
    let line = format!("{v}\n");
    match f {
        Some(f) => f
            .write_all(line.as_bytes())
            .map_err(|e| format!("answer: {e}")),
        None => {
            eprint!("{line}");
            Ok(())
        }
    }
}

/// Go's strconv.Quote of bytes, which `%q` writes: ASCII as Go escapes it,
/// bytes that are not UTF-8 as \x, and other characters kept unless they
/// are not printable.
pub(crate) fn quote(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() + 2);
    out.push('"');
    for chunk in b.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\u{7}' => out.push_str("\\a"),
                '\u{8}' => out.push_str("\\b"),
                '\u{c}' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{b}' => out.push_str("\\v"),
                ' '..='~' => out.push(c),
                c if (c as u32) < 0x80 => out.push_str(&format!("\\x{:02x}", c as u32)),
                c if !printable(c) => {
                    if (c as u32) < 0x10000 {
                        out.push_str(&format!("\\u{:04x}", c as u32));
                    } else {
                        out.push_str(&format!("\\U{:08x}", c as u32));
                    }
                }
                c => out.push(c),
            }
        }
        for x in chunk.invalid() {
            out.push_str(&format!("\\x{x:02x}"));
        }
    }
    out.push('"');
    out
}

/// unicode.IsPrint for the characters names hold: control, format, and
/// space characters other than U+0020, and private use, are not.
fn printable(c: char) -> bool {
    let u = c as u32;
    !(c.is_control()
        || matches!(u, 0xa0 | 0xad | 0x1680 | 0x180e | 0x3000 | 0xfeff)
        || (0x2000..=0x200f).contains(&u)
        || (0x2028..=0x202f).contains(&u)
        || (0x205f..=0x206f).contains(&u)
        || (0xfff9..=0xfffb).contains(&u)
        || (0xe000..=0xf8ff).contains(&u)
        || u >= 0xf0000)
}

/// A path in an os.PathError's text: as it is when it is UTF-8, else
/// quoted as `%q` quotes it. Go prints the bytes as they are, which makes
/// a text the agent cannot send (protobuf strings are UTF-8); this keeps
/// every byte readable instead.
pub(crate) fn show(p: &[u8]) -> String {
    match std::str::from_utf8(p) {
        Ok(s) => s.to_string(),
        Err(_) => quote(p),
    }
}

/// An os.PathError's text.
pub(crate) fn path_err(op: &str, p: &[u8], e: i32) -> String {
    format!("{op} {}: {}", show(p), errno::text(e))
}

pub(crate) fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

pub(crate) fn cstr(b: &[u8]) -> Result<std::ffi::CString, i32> {
    std::ffi::CString::new(b).map_err(|_| libc::EINVAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_as_go() {
        assert_eq!(quote(b"a b"), "\"a b\"");
        assert_eq!(quote(b"f\x1b]0;t\x07"), "\"f\\x1b]0;t\\a\"");
        assert_eq!(quote(b"\xff\"\\"), "\"\\xff\\\"\\\\\"");
        assert_eq!(quote("é\u{200b}".as_bytes()), "\"é\\u200b\"");
        assert_eq!(quote(b"\x7f"), "\"\\x7f\"");
    }

    #[test]
    fn words_errors_as_go() {
        assert_eq!(
            errno::text(libc::ELOOP),
            "too many levels of symbolic links"
        );
        assert_eq!(errno::text(libc::EXDEV), "invalid cross-device link");
        assert_eq!(errno::text(9999), "errno 9999");
    }
}
