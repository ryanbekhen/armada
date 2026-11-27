//! imagecheck: a layer blob is used only once it decompresses to the diff
//! ID its image's config names. Unpacked layers are shared by chain ID,
//! which comes from the config's diff IDs alone, so without this an image
//! could name another image's layers and get them while serving blobs of
//! its own. Blobs are told apart as containerd's DecompressStream does:
//! gzip and zstd by their magic numbers, anything else as a plain tar.

use super::digest::Digest;
use std::io::{self, BufRead, BufReader, Read};

const GZIP_MAGIC: [u8; 3] = [0x1f, 0x8b, 0x08];
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
const ZSTD_SKIPPABLE_START: u32 = 0x184d_2a50;
const ZSTD_SKIPPABLE_MASK: u32 = 0xffff_fff0;
/// The largest zstd window accepted (512 MiB), which bounds the memory a
/// layer can make us take.
const ZSTD_MAX_WINDOW: u64 = 1 << 29;

#[derive(PartialEq, Eq, Debug)]
enum Compression {
    None,
    Gzip,
    Zstd,
}

fn detect(head: &[u8]) -> Compression {
    if head.starts_with(&GZIP_MAGIC) {
        return Compression::Gzip;
    }
    if head.starts_with(&ZSTD_MAGIC) {
        return Compression::Zstd;
    }
    if head.len() >= 8 {
        let m = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
        if m & ZSTD_SKIPPABLE_MASK == ZSTD_SKIPPABLE_START {
            return Compression::Zstd;
        }
    }
    Compression::None
}

/// The digest, in diff_id's algorithm, of what r decompresses to.
pub fn uncompressed(r: impl Read, diff_id: &Digest) -> Result<Digest, String> {
    let mut r = BufReader::with_capacity(64 << 10, r);
    let head = r.fill_buf().map_err(|e| e.to_string())?.to_vec();
    let mut h = diff_id.algorithm().hasher();
    match detect(&head[..head.len().min(10)]) {
        Compression::None => {
            io::copy(&mut r, &mut h).map_err(|e| e.to_string())?;
        }
        Compression::Gzip => {
            let mut d = flate2::bufread::MultiGzDecoder::new(r);
            io::copy(&mut d, &mut h).map_err(|e| format!("gzip: {e}"))?;
        }
        Compression::Zstd => zstd(&mut r, &mut h)?,
    }
    Ok(h.finish())
}

/// Every frame of a zstd stream, skippable frames skipped.
fn zstd<R: BufRead>(r: &mut R, out: &mut impl io::Write) -> Result<(), String> {
    use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
    loop {
        if r.fill_buf().map_err(|e| e.to_string())?.is_empty() {
            return Ok(());
        }
        let head = r.fill_buf().map_err(|e| e.to_string())?;
        if let Some(w) = window_size(head)
            && w > ZSTD_MAX_WINDOW
        {
            return Err(format!(
                "zstd: window size {w} exceeded the limit {ZSTD_MAX_WINDOW}"
            ));
        }
        match ruzstd::decoding::StreamingDecoder::new(&mut *r) {
            Ok(mut d) => {
                io::copy(&mut d, out).map_err(|e| format!("zstd: {e}"))?;
                let f = &d.decoder;
                if !f.is_finished() {
                    return Err("zstd: unexpected end of frame".into());
                }
                if let (Some(want), Some(got)) =
                    (f.get_checksum_from_data(), f.get_calculated_checksum())
                    && want != got
                {
                    return Err("zstd: frame checksum mismatch".into());
                }
            }
            Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame {
                length,
                ..
            })) => {
                let n = io::copy(&mut r.take(u64::from(length)), &mut io::sink())
                    .map_err(|e| e.to_string())?;
                if n != u64::from(length) {
                    return Err("zstd: skippable frame ended early".into());
                }
            }
            Err(e) => return Err(format!("zstd: {e}")),
        }
    }
}

/// The window a zstd frame header asks for, when the bytes at hand show
/// it (RFC 8878 3.1.1.1).
pub(crate) fn window_size(h: &[u8]) -> Option<u64> {
    if h.len() < 6 || h[..4] != ZSTD_MAGIC {
        return None;
    }
    let fhd = h[4];
    let single_segment = fhd & 0x20 != 0;
    if !single_segment {
        let wd = h[5];
        let exponent = u64::from(wd >> 3);
        let mantissa = u64::from(wd & 7);
        let base = 1u64 << (10 + exponent);
        return Some(base + (base / 8) * mantissa);
    }
    // A single segment's window is its content size.
    let dict_len = [0usize, 1, 2, 4][usize::from(fhd & 3)];
    let fcs_len = [1usize, 2, 4, 8][usize::from(fhd >> 6)];
    let at = 5 + dict_len;
    let b = h.get(at..at + fcs_len)?;
    let mut v = 0u64;
    for (i, x) in b.iter().enumerate() {
        v |= u64::from(*x) << (8 * i);
    }
    Some(if fcs_len == 2 { v + 256 } else { v })
}

/// A layer blob read for unpacking: its media type must be a layer's
/// (images.DiffCompression), and its magic numbers alone decide whether
/// and how it is decompressed (DecompressStream), as `uncompressed` reads
/// it to check its diff ID. containerd lets the media type decide, so a
/// compressed blob under an uncompressed type was checked as one tar and
/// unpacked as another; here both read the same bytes.
pub fn layer_reader<'a, R: Read + 'a>(
    r: R,
    media_type: &str,
) -> Result<Box<dyn Read + 'a>, String> {
    diff_compressed(media_type)?;
    let mut r = BufReader::with_capacity(64 << 10, r);
    let head = r.fill_buf().map_err(|e| e.to_string())?.to_vec();
    Ok(match detect(&head[..head.len().min(10)]) {
        Compression::None => Box::new(r),
        Compression::Gzip => Box::new(flate2::bufread::MultiGzDecoder::new(r)),
        Compression::Zstd => Box::new(ZstdReader {
            src: Shared(std::rc::Rc::new(std::cell::RefCell::new(r))),
            frame: None,
            done: false,
        }),
    })
}

/// images.DiffCompression: whether the applier decompresses a layer of
/// this media type; an error for one it has no processor for.
fn diff_compressed(mt: &str) -> Result<bool, String> {
    let (base, mut ext): (&str, Vec<&str>) = match mt.split_once('+') {
        Some((b, e)) => (b, e.splitn(50, '+').collect()),
        None => (mt, Vec::new()),
    };
    ext.sort_unstable();
    match base {
        "application/vnd.docker.image.rootfs.diff.tar"
        | "application/vnd.docker.image.rootfs.foreign.diff.tar"
        | "application/vnd.docker.image.rootfs.diff.tar.gzip"
        | "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
        | "application/vnd.docker.image.rootfs.diff.tar.zstd" => Ok(ext.is_empty()),
        "application/vnd.oci.image.layer.v1.tar"
        | "application/vnd.oci.image.layer.nondistributable.v1.tar" => {
            Ok(matches!(ext.last(), Some(&"gzip") | Some(&"zstd")))
        }
        _ => Err(format!(
            "failed to get stream processor for {mt}: no processor for media-type"
        )),
    }
}

/// A BufRead shared between the zstd reader and the frame it decodes.
struct Shared<R>(std::rc::Rc<std::cell::RefCell<R>>);

impl<R> Clone for Shared<R> {
    fn clone(&self) -> Self {
        Shared(self.0.clone())
    }
}

impl<R: BufRead> Read for Shared<R> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.0.borrow_mut().read(b)
    }
}

type Frame<R> = ruzstd::decoding::StreamingDecoder<Shared<R>, ruzstd::decoding::FrameDecoder>;

/// Every frame of a zstd stream as one reader, as zstd() reads it.
struct ZstdReader<R: BufRead> {
    src: Shared<R>,
    frame: Option<Frame<R>>,
    done: bool,
}

fn zerr(m: String) -> io::Error {
    io::Error::other(m)
}

impl<R: BufRead> Read for ZstdReader<R> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
        loop {
            if self.done || b.is_empty() {
                return Ok(0);
            }
            if let Some(f) = &mut self.frame {
                let n = f.read(b).map_err(|e| zerr(format!("zstd: {e}")))?;
                if n > 0 {
                    return Ok(n);
                }
                let d = &f.decoder;
                if !d.is_finished() {
                    return Err(zerr("zstd: unexpected end of frame".into()));
                }
                if let (Some(want), Some(got)) =
                    (d.get_checksum_from_data(), d.get_calculated_checksum())
                    && want != got
                {
                    return Err(zerr("zstd: frame checksum mismatch".into()));
                }
                self.frame = None;
                continue;
            }
            {
                let mut src = self.src.0.borrow_mut();
                let head = src.fill_buf()?;
                if head.is_empty() {
                    self.done = true;
                    return Ok(0);
                }
                if let Some(w) = window_size(head)
                    && w > ZSTD_MAX_WINDOW
                {
                    return Err(zerr(format!(
                        "zstd: window size {w} exceeded the limit {ZSTD_MAX_WINDOW}"
                    )));
                }
            }
            match ruzstd::decoding::StreamingDecoder::new(self.src.clone()) {
                Ok(d) => self.frame = Some(d),
                Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame {
                    length,
                    ..
                })) => {
                    let n = io::copy(
                        &mut self.src.clone().take(u64::from(length)),
                        &mut io::sink(),
                    )?;
                    if n != u64::from(length) {
                        return Err(zerr("zstd: skippable frame ended early".into()));
                    }
                }
                Err(e) => return Err(zerr(format!("zstd: {e}"))),
            }
        }
    }
}

/// imagecheck.Layer for a blob read from r.
pub fn layer(r: impl Read, blob: &Digest, diff_id: &Digest) -> Result<(), String> {
    let got = uncompressed(r, diff_id).map_err(|e| format!("layer {blob}: {e}"))?;
    if &got != diff_id {
        return Err(format!(
            "layer {blob} does not match its diff ID {diff_id} in the image config"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gz(b: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn checks_every_form() {
        let tar = b"my layer tar".to_vec();
        let id = Digest::sha256(&tar);
        let blob = Digest::sha256(b"x");
        layer(&tar[..], &blob, &id).unwrap();
        layer(&gz(&tar)[..], &blob, &id).unwrap();
        // Two gzip members read as one stream.
        let mut two = gz(b"my layer");
        two.extend(gz(b" tar"));
        layer(&two[..], &blob, &id).unwrap();
        let mut z = Vec::new();
        ruzstd::encoding::compress(
            &tar[..],
            &mut z,
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        layer(&z[..], &blob, &id).unwrap();
        // A skippable frame first.
        let mut skip = vec![0x50, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 1, 2, 3];
        skip.extend(&z);
        layer(&skip[..], &blob, &id).unwrap();
        assert!(layer(&gz(&tar)[..], &blob, &Digest::sha256(b"another layer")).is_err());
        let mut bad = gz(&tar);
        let n = bad.len();
        bad[n - 6] ^= 0xff;
        assert!(layer(&bad[..], &blob, &id).is_err());
    }

    #[test]
    fn reads_layers_as_the_applier() {
        let tar = b"my layer tar".to_vec();
        let mut z = Vec::new();
        ruzstd::encoding::compress(
            &tar[..],
            &mut z,
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        let mut two = vec![0x50, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 1, 2, 3];
        two.extend(&z);
        two.extend(&z);
        let read = |b: &[u8], mt: &str| {
            let mut out = Vec::new();
            layer_reader(b, mt).unwrap().read_to_end(&mut out).unwrap();
            out
        };
        let oci = "application/vnd.oci.image.layer.v1.tar";
        assert_eq!(
            read(&two, &format!("{oci}+zstd")),
            [&tar[..], &tar[..]].concat()
        );
        assert_eq!(read(&gz(&tar), &format!("{oci}+gzip")), tar);
        // The bytes decide, whatever the layer type says (as the diff ID
        // check reads them).
        assert_eq!(read(&gz(&tar), oci), tar);
        assert_eq!(read(&tar, oci), tar);
        assert_eq!(
            read(&tar, "application/vnd.docker.image.rootfs.diff.tar.gzip"),
            tar
        );
        assert_eq!(
            read(&gz(&tar), "application/vnd.docker.image.rootfs.diff.tar"),
            tar
        );
        assert!(layer_reader(&tar[..], "text/plain").is_err());
        let mut bad = z.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xff;
        let mut out = Vec::new();
        assert!(
            layer_reader(&bad[..], &format!("{oci}+zstd"))
                .unwrap()
                .read_to_end(&mut out)
                .is_err()
        );
    }

    #[test]
    fn refuses_huge_windows() {
        // Window descriptor exponent 31: a 2 TiB window.
        let h = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 31 << 3];
        assert!(window_size(&h).unwrap() > ZSTD_MAX_WINDOW);
        let mut r = BufReader::new(&h[..]);
        assert!(zstd(&mut r, &mut io::sink()).is_err());
    }
}
