//! Sensitive files with strict permissions. Errors read `OP PATH: TEXT`
//! with the system's error texts (`open PATH: file
//! exists`, `PATH has mode 0644, want no group/other access (chmod go-rwx):
//! insecure permissions`), since the machine commands print them.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// The text of an insecure permissions error.
pub const INSECURE_PERMISSIONS: &str = "insecure permissions";

/// What kind of failure an [`Error`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The file or directory is open to group or others.
    InsecurePermissions,
    /// The path does not exist.
    NotFound,
    /// The file exists where it must not.
    AlreadyExists,
    /// Anything else.
    Other,
}

/// An error worded `OP PATH: TEXT`, or as one of fsutil's own texts.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    text: String,
}

impl Error {
    /// The kind of failure.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Whether the file had group or other permissions.
    pub fn is_insecure(&self) -> bool {
        self.kind == ErrorKind::InsecurePermissions
    }

    /// A path error's text: `OP PATH: ERRNO TEXT`.
    pub fn path(op: &str, path: &Path, err: &io::Error) -> Self {
        let kind = match err.kind() {
            io::ErrorKind::NotFound => ErrorKind::NotFound,
            io::ErrorKind::AlreadyExists => ErrorKind::AlreadyExists,
            _ => ErrorKind::Other,
        };
        Error {
            kind,
            text: format!("{op} {}: {}", path.display(), errno_text(err)),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::error::Error for Error {}

/// The short lowercase text of the common errors, else the
/// system's own text without Rust's `(os error N)`.
pub fn errno_text(err: &io::Error) -> String {
    let text = match err.raw_os_error() {
        Some(1) => "operation not permitted",
        Some(2) => "no such file or directory",
        Some(5) => "input/output error",
        Some(13) => "permission denied",
        Some(17) => "file exists",
        Some(20) => "not a directory",
        Some(21) => "is a directory",
        Some(22) => "invalid argument",
        Some(28) => "no space left on device",
        Some(30) => "read-only file system",
        Some(36) => "file name too long",
        Some(40) => "too many levels of symbolic links",
        _ => {
            let s = err.to_string();
            return match s.find(" (os error") {
                Some(i) => s[..i].to_lowercase(),
                None => s,
            };
        }
    };
    text.to_string()
}

/// Verifies that `path` exists and has no group or other permissions
/// (symbolic links are followed).
pub fn check_private(path: &Path) -> Result<(), Error> {
    let meta = fs::metadata(path).map_err(|e| Error::path("stat", path, &e))?;
    let perm = meta.permissions().mode() & 0o777;
    if perm & 0o077 != 0 {
        return Err(Error {
            kind: ErrorKind::InsecurePermissions,
            text: format!(
                "{} has mode {perm:04o}, want no group/other access (chmod go-rwx): {INSECURE_PERMISSIONS}",
                path.display()
            ),
        });
    }
    Ok(())
}

/// Reads a file only if it is not accessible by group or others.
pub fn read_private_file(path: &Path) -> Result<Vec<u8>, Error> {
    check_private(path)?;
    // A directory opens and fails at the read, worded as one.
    fs::read(path).map_err(|e| {
        let op = if e.raw_os_error() == Some(21) {
            "read"
        } else {
            "open"
        };
        Error::path(op, path, &e)
    })
}

/// Creates `dir` with mode 0700 if missing and verifies the mode of an
/// existing directory.
pub fn mkdir_private(dir: &Path) -> Result<(), Error> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| Error::path("mkdir", dir, &e))?;
    check_private(dir)
}

/// Creates `path` with `perm` and writes `data`, failing if the file
/// already exists. For keys that must never be
/// overwritten.
pub fn write_file_exclusive(path: &Path, data: &[u8], perm: u32) -> Result<(), Error> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(perm)
        .open(path)
        .map_err(|e| Error::path("open", path, &e))?;
    let written = (|| -> io::Result<()> {
        // Not subject to the umask.
        f.set_permissions(fs::Permissions::from_mode(perm))?;
        f.write_all(data)?;
        f.sync_all()
    })();
    if let Err(e) = written {
        drop(f);
        let _ = fs::remove_file(path);
        return Err(Error::path("write", path, &e));
    }
    Ok(())
}

/// Writes `data` to `path` through a temporary file in the same directory
/// and an atomic rename, so readers never see a partial file.
pub fn write_file_atomic(path: &Path, data: &[u8], perm: u32) -> Result<(), Error> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let base = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (tmp, mut f) = create_temp(&dir, &base)?;
    let written = (|| -> io::Result<()> {
        f.set_permissions(fs::Permissions::from_mode(perm))?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(Error::path("write", path, &e));
    }
    Ok(())
}

/// Opens a new file `.<base>.tmp-<random>` in `dir`, created exclusively.
fn create_temp(dir: &Path, base: &str) -> Result<(PathBuf, File), Error> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut last = None;
    for _ in 0..10_000 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let seed =
            nanos ^ (u64::from(std::process::id()) << 32) ^ n.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let name = dir.join(format!(".{base}.tmp-{}", seed % 10_000_000_000));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&name)
        {
            Ok(f) => return Ok((name, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(Error::path("open", &name, &e)),
        }
    }
    let e = last.unwrap_or_else(|| io::Error::from(io::ErrorKind::AlreadyExists));
    Err(Error::path("open", dir, &e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "armada-fsutil-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    #[test]
    fn atomic_write_replaces_and_leaves_nothing() {
        let dir = temp_dir("atomic");
        let path = dir.join("secret.pem");
        write_file_atomic(&path, b"one", 0o600).unwrap();
        write_file_atomic(&path, b"two", 0o600).unwrap();
        assert_eq!(read_private_file(&path).unwrap(), b"two");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        assert!(write_file_atomic(&dir.join("nope/f"), b"", 0o600).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn private_reads_refuse_loose_modes() {
        let dir = temp_dir("loose");
        let path = dir.join("key");
        fs::write(&path, b"k").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = read_private_file(&path).unwrap_err();
        assert!(err.is_insecure());
        assert_eq!(
            err.to_string(),
            format!(
                "{} has mode 0644, want no group/other access (chmod go-rwx): insecure permissions",
                path.display()
            )
        );
        let missing = dir.join("missing");
        let err = read_private_file(&missing).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
        assert_eq!(
            err.to_string(),
            format!("stat {}: no such file or directory", missing.display())
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn exclusive_write_never_overwrites() {
        let dir = temp_dir("excl");
        let path = dir.join("master.key");
        write_file_exclusive(&path, b"a", 0o600).unwrap();
        let err = write_file_exclusive(&path, b"b", 0o600).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::AlreadyExists);
        assert_eq!(
            err.to_string(),
            format!("open {}: file exists", path.display())
        );
        assert_eq!(fs::read(&path).unwrap(), b"a");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn private_directories() {
        let dir = temp_dir("mkdir");
        let data = dir.join("data");
        mkdir_private(&data).unwrap();
        mkdir_private(&data).unwrap();
        let loose = dir.join("loose");
        fs::create_dir(&loose).unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(mkdir_private(&loose).unwrap_err().is_insecure());
        fs::remove_dir_all(dir).unwrap();
    }
}
