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
/// The largest zstd window the Go decoder accepts (MaxWindowSize on
/// 64-bit machines), which bounds the memory a layer can make us take.
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
fn window_size(h: &[u8]) -> Option<u64> {
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
        // Two gzip members read as one stream, as Go's reader does.
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
    fn refuses_huge_windows() {
        // Window descriptor exponent 31: a 2 TiB window.
        let h = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 31 << 3];
        assert!(window_size(&h).unwrap() > ZSTD_MAX_WINDOW);
        let mut r = BufReader::new(&h[..]);
        assert!(zstd(&mut r, &mut io::sink()).is_err());
    }
}
