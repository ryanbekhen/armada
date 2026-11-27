//! The input reader (go-yaml's readerc.go): detects the encoding from a
//! BOM, decodes UTF-8 or UTF-16 into the UTF-8 working buffer, and refuses
//! characters YAML does not allow. It reads the input in chunks of 512
//! bytes, as go-yaml does, so errors surface at the same point of the scan.

use super::chars::{INPUT_BUFFER_SIZE, INPUT_RAW_BUFFER_SIZE};
use super::parser::Parser;
use super::types::{Encoding, ErrorType};

impl Parser {
    fn set_reader_error(&mut self, problem: &str, offset: usize, value: i64) -> bool {
        self.error = ErrorType::Reader;
        self.problem = problem.to_string();
        self.problem_offset = offset;
        self.problem_value = value;
        false
    }

    fn determine_encoding(&mut self) -> bool {
        while !self.eof && self.raw_buffer.len() - self.raw_buffer_pos < 3 {
            if !self.update_raw_buffer() {
                return false;
            }
        }
        let buf = &self.raw_buffer;
        let pos = self.raw_buffer_pos;
        let avail = buf.len() - pos;
        if avail >= 2 && buf[pos] == 0xff && buf[pos + 1] == 0xfe {
            self.encoding = Encoding::Utf16Le;
            self.raw_buffer_pos += 2;
            self.offset += 2;
        } else if avail >= 2 && buf[pos] == 0xfe && buf[pos + 1] == 0xff {
            self.encoding = Encoding::Utf16Be;
            self.raw_buffer_pos += 2;
            self.offset += 2;
        } else if avail >= 3 && buf[pos] == 0xef && buf[pos + 1] == 0xbb && buf[pos + 2] == 0xbf {
            self.encoding = Encoding::Utf8;
            self.raw_buffer_pos += 3;
            self.offset += 3;
        } else {
            self.encoding = Encoding::Utf8;
        }
        true
    }

    /// Fills the raw buffer from the input, up to 512 bytes; the input's
    /// end sets eof (a read of nothing is the end).
    fn update_raw_buffer(&mut self) -> bool {
        if self.raw_buffer_pos == 0 && self.raw_buffer.len() == INPUT_RAW_BUFFER_SIZE {
            return true;
        }
        if self.eof {
            return true;
        }
        self.raw_buffer.drain(..self.raw_buffer_pos);
        self.raw_buffer_pos = 0;
        if self.input_pos == self.input.len() {
            self.eof = true;
            return true;
        }
        let room = INPUT_RAW_BUFFER_SIZE - self.raw_buffer.len();
        let n = room.min(self.input.len() - self.input_pos);
        self.raw_buffer
            .extend_from_slice(&self.input[self.input_pos..self.input_pos + n]);
        self.input_pos += n;
        true
    }

    fn put(&mut self, at: usize, b: u8) {
        if at >= self.buffer.len() {
            self.buffer.resize(at + 1, 0);
        }
        self.buffer[at] = b;
    }

    /// Makes at least length characters available in the working buffer.
    pub(super) fn update_buffer(&mut self, length: usize) -> bool {
        if self.unread >= length {
            return true;
        }
        if self.encoding == Encoding::Any && !self.determine_encoding() {
            return false;
        }
        let mut buffer_len = self.buffer_len;
        if self.buffer_pos > 0 && self.buffer_pos < buffer_len {
            self.buffer.copy_within(self.buffer_pos..buffer_len, 0);
            buffer_len -= self.buffer_pos;
            self.buffer_pos = 0;
        } else if self.buffer_pos == buffer_len {
            buffer_len = 0;
            self.buffer_pos = 0;
        }
        // go-yaml reslices the buffer to its capacity here; a decoding error
        // returns with that length, the bytes past the decoded ones being
        // whatever the array held before.
        if self.buffer.len() < INPUT_BUFFER_SIZE {
            self.buffer.resize(INPUT_BUFFER_SIZE, 0);
        }
        let cap = self.buffer.len();
        let mut first = true;
        while self.unread < length {
            if (!first || self.raw_buffer_pos == self.raw_buffer.len()) && !self.update_raw_buffer()
            {
                self.buffer_len = buffer_len;
                return false;
            }
            first = false;
            while self.raw_buffer_pos != self.raw_buffer.len() {
                let raw_unread = self.raw_buffer.len() - self.raw_buffer_pos;
                let pos = self.raw_buffer_pos;
                let mut value: u32;
                let width: usize;
                match self.encoding {
                    Encoding::Utf16Le | Encoding::Utf16Be => {
                        let (low, high) = if self.encoding == Encoding::Utf16Le {
                            (0, 1)
                        } else {
                            (1, 0)
                        };
                        if raw_unread < 2 {
                            if self.eof {
                                self.buffer_len = cap;
                                return self.set_reader_error(
                                    "incomplete UTF-16 character",
                                    self.offset,
                                    -1,
                                );
                            }
                            break;
                        }
                        value = self.raw_buffer[pos + low] as u32
                            + ((self.raw_buffer[pos + high] as u32) << 8);
                        if value & 0xfc00 == 0xdc00 {
                            self.buffer_len = cap;
                            return self.set_reader_error(
                                "unexpected low surrogate area",
                                self.offset,
                                value as i64,
                            );
                        }
                        if value & 0xfc00 == 0xd800 {
                            width = 4;
                            if raw_unread < 4 {
                                if self.eof {
                                    self.buffer_len = cap;
                                    return self.set_reader_error(
                                        "incomplete UTF-16 surrogate pair",
                                        self.offset,
                                        -1,
                                    );
                                }
                                break;
                            }
                            let value2 = self.raw_buffer[pos + low + 2] as u32
                                + ((self.raw_buffer[pos + high + 2] as u32) << 8);
                            if value2 & 0xfc00 != 0xdc00 {
                                self.buffer_len = cap;
                                return self.set_reader_error(
                                    "expected low surrogate area",
                                    self.offset + 2,
                                    value2 as i64,
                                );
                            }
                            value = 0x10000 + ((value & 0x3ff) << 10) + (value2 & 0x3ff);
                        } else {
                            width = 2;
                        }
                    }
                    _ => {
                        let octet = self.raw_buffer[pos];
                        let w = match octet {
                            o if o & 0x80 == 0 => 1,
                            o if o & 0xe0 == 0xc0 => 2,
                            o if o & 0xf0 == 0xe0 => 3,
                            o if o & 0xf8 == 0xf0 => 4,
                            _ => {
                                self.buffer_len = cap;
                                return self.set_reader_error(
                                    "invalid leading UTF-8 octet",
                                    self.offset,
                                    octet as i64,
                                );
                            }
                        };
                        if w > raw_unread {
                            if self.eof {
                                self.buffer_len = cap;
                                return self.set_reader_error(
                                    "incomplete UTF-8 octet sequence",
                                    self.offset,
                                    -1,
                                );
                            }
                            break;
                        }
                        width = w;
                        value = match w {
                            1 => (octet & 0x7f) as u32,
                            2 => (octet & 0x1f) as u32,
                            3 => (octet & 0x0f) as u32,
                            _ => (octet & 0x07) as u32,
                        };
                        for k in 1..w {
                            let o = self.raw_buffer[pos + k];
                            if o & 0xc0 != 0x80 {
                                self.buffer_len = cap;
                                return self.set_reader_error(
                                    "invalid trailing UTF-8 octet",
                                    self.offset + k,
                                    o as i64,
                                );
                            }
                            value = (value << 6) + (o & 0x3f) as u32;
                        }
                        let ok = w == 1
                            || (w == 2 && value >= 0x80)
                            || (w == 3 && value >= 0x800)
                            || (w == 4 && value >= 0x10000);
                        if !ok {
                            self.buffer_len = cap;
                            return self.set_reader_error(
                                "invalid length of a UTF-8 sequence",
                                self.offset,
                                -1,
                            );
                        }
                        if (0xd800..=0xdfff).contains(&value) || value > 0x10ffff {
                            self.buffer_len = cap;
                            return self.set_reader_error(
                                "invalid Unicode character",
                                self.offset,
                                value as i64,
                            );
                        }
                    }
                }
                let allowed = value == 0x09
                    || value == 0x0a
                    || value == 0x0d
                    || (0x20..=0x7e).contains(&value)
                    || value == 0x85
                    || (0xa0..=0xd7ff).contains(&value)
                    || (0xe000..=0xfffd).contains(&value)
                    || (0x10000..=0x10ffff).contains(&value);
                if !allowed {
                    self.buffer_len = cap;
                    return self.set_reader_error(
                        "control characters are not allowed",
                        self.offset,
                        value as i64,
                    );
                }
                self.raw_buffer_pos += width;
                self.offset += width;
                if value <= 0x7f {
                    self.put(buffer_len, value as u8);
                    buffer_len += 1;
                } else if value <= 0x7ff {
                    self.put(buffer_len, (0xc0 + (value >> 6)) as u8);
                    self.put(buffer_len + 1, (0x80 + (value & 0x3f)) as u8);
                    buffer_len += 2;
                } else if value <= 0xffff {
                    self.put(buffer_len, (0xe0 + (value >> 12)) as u8);
                    self.put(buffer_len + 1, (0x80 + ((value >> 6) & 0x3f)) as u8);
                    self.put(buffer_len + 2, (0x80 + (value & 0x3f)) as u8);
                    buffer_len += 3;
                } else {
                    self.put(buffer_len, (0xf0 + (value >> 18)) as u8);
                    self.put(buffer_len + 1, (0x80 + ((value >> 12) & 0x3f)) as u8);
                    self.put(buffer_len + 2, (0x80 + ((value >> 6) & 0x3f)) as u8);
                    self.put(buffer_len + 3, (0x80 + (value & 0x3f)) as u8);
                    buffer_len += 4;
                }
                self.unread += 1;
            }
            if self.eof {
                self.put(buffer_len, 0);
                buffer_len += 1;
                self.unread += 1;
                break;
            }
        }
        while buffer_len < length {
            self.put(buffer_len, 0);
            buffer_len += 1;
        }
        self.buffer_len = buffer_len;
        true
    }
}
