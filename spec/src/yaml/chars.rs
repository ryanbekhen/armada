//! Character classes of the YAML reader and scanner (go-yaml's
//! yamlprivateh.go, from libyaml). Each takes the buffer and an index, as
//! the Go functions do; a byte past the buffer's end reads as 0, where Go
//! would panic, so a check never crashes.

pub const INPUT_RAW_BUFFER_SIZE: usize = 512;
pub const INPUT_BUFFER_SIZE: usize = INPUT_RAW_BUFFER_SIZE * 3;
pub const INITIAL_STACK_SIZE: usize = 16;
pub const INITIAL_QUEUE_SIZE: usize = 16;

#[inline]
pub fn at(b: &[u8], i: usize) -> u8 {
    b.get(i).copied().unwrap_or(0)
}

pub fn is_alpha(b: &[u8], i: usize) -> bool {
    let c = at(b, i);
    c.is_ascii_digit() || c.is_ascii_uppercase() || c.is_ascii_lowercase() || c == b'_' || c == b'-'
}

pub fn is_digit(b: &[u8], i: usize) -> bool {
    at(b, i).is_ascii_digit()
}

pub fn as_digit(b: &[u8], i: usize) -> i32 {
    at(b, i) as i32 - b'0' as i32
}

pub fn is_hex(b: &[u8], i: usize) -> bool {
    at(b, i).is_ascii_hexdigit()
}

pub fn as_hex(b: &[u8], i: usize) -> i32 {
    let c = at(b, i);
    match c {
        b'A'..=b'F' => c as i32 - b'A' as i32 + 10,
        b'a'..=b'f' => c as i32 - b'a' as i32 + 10,
        _ => c as i32 - b'0' as i32,
    }
}

pub fn is_ascii(b: &[u8], i: usize) -> bool {
    at(b, i) <= 0x7f
}

/// Whether the character at i may appear in a YAML stream.
pub fn is_printable(b: &[u8], i: usize) -> bool {
    let (c0, c1, c2) = (at(b, i), at(b, i + 1), at(b, i + 2));
    c0 == 0x0a
        || (0x20..=0x7e).contains(&c0)
        || (c0 == 0xc2 && c1 >= 0xa0)
        || (c0 > 0xc2 && c0 < 0xed)
        || (c0 == 0xed && c1 < 0xa0)
        || c0 == 0xee
        || (c0 == 0xef
            && !(c1 == 0xbb && c2 == 0xbf)
            && !(c1 == 0xbf && (c2 == 0xbe || c2 == 0xbf)))
}

pub fn is_z(b: &[u8], i: usize) -> bool {
    at(b, i) == 0
}

/// Whether the buffer starts with a UTF-8 BOM (Go's is_bom ignores i).
pub fn is_bom(b: &[u8], _i: usize) -> bool {
    at(b, 0) == 0xef && at(b, 1) == 0xbb && at(b, 2) == 0xbf
}

pub fn is_space(b: &[u8], i: usize) -> bool {
    at(b, i) == b' '
}

pub fn is_tab(b: &[u8], i: usize) -> bool {
    at(b, i) == b'\t'
}

pub fn is_blank(b: &[u8], i: usize) -> bool {
    let c = at(b, i);
    c == b' ' || c == b'\t'
}

pub fn is_break(b: &[u8], i: usize) -> bool {
    let (c0, c1, c2) = (at(b, i), at(b, i + 1), at(b, i + 2));
    c0 == b'\r'
        || c0 == b'\n'
        || (c0 == 0xc2 && c1 == 0x85)
        || (c0 == 0xe2 && c1 == 0x80 && c2 == 0xa8)
        || (c0 == 0xe2 && c1 == 0x80 && c2 == 0xa9)
}

pub fn is_crlf(b: &[u8], i: usize) -> bool {
    at(b, i) == b'\r' && at(b, i + 1) == b'\n'
}

pub fn is_breakz(b: &[u8], i: usize) -> bool {
    is_break(b, i) || at(b, i) == 0
}

pub fn is_spacez(b: &[u8], i: usize) -> bool {
    at(b, i) == b' ' || is_breakz(b, i)
}

pub fn is_blankz(b: &[u8], i: usize) -> bool {
    is_blank(b, i) || is_breakz(b, i)
}

/// The length of the UTF-8 sequence a leading byte starts, 0 if invalid.
pub fn width(b: u8) -> usize {
    if b & 0x80 == 0 {
        1
    } else if b & 0xe0 == 0xc0 {
        2
    } else if b & 0xf0 == 0xe0 {
        3
    } else if b & 0xf8 == 0xf0 {
        4
    } else {
        0
    }
}
