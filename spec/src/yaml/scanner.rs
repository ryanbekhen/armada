//! The scanner (go-yaml's scannerc.go, from libyaml): turns the characters
//! of the working buffer into tokens, with go-yaml's simple key rules,
//! indentation, comment collection, and error texts. Marks keep Go's
//! arithmetic: an index or column one before 0 wraps, and is compared as
//! the signed number Go has.

use super::chars::{
    as_digit, as_hex, at, is_alpha, is_blank, is_blankz, is_bom, is_break, is_breakz, is_crlf,
    is_digit, is_hex, is_space, is_tab, is_z, width,
};
use super::parser::Parser;
use super::types::{Encoding, ErrorType, Mark, ScalarStyle};

/// Token types (yaml_token_type_t).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TokenType {
    #[default]
    NoToken,
    StreamStart,
    StreamEnd,
    VersionDirective,
    TagDirective,
    DocumentStart,
    DocumentEnd,
    BlockSequenceStart,
    BlockMappingStart,
    BlockEnd,
    FlowSequenceStart,
    FlowSequenceEnd,
    FlowMappingStart,
    FlowMappingEnd,
    BlockEntry,
    FlowEntry,
    Key,
    Value,
    Alias,
    Anchor,
    Tag,
    Scalar,
}

/// A token (yaml_token_t).
#[derive(Clone, Debug, Default)]
pub struct Token {
    pub typ: TokenType,
    pub start_mark: Mark,
    pub end_mark: Mark,
    pub encoding: Encoding,
    pub value: Vec<u8>,
    pub suffix: Vec<u8>,
    pub prefix: Vec<u8>,
    pub style: ScalarStyle,
    pub major: i8,
    pub minor: i8,
}

/// A possible simple key (yaml_simple_key_t).
#[derive(Clone, Copy, Debug, Default)]
pub struct SimpleKey {
    pub possible: bool,
    pub required: bool,
    pub token_number: usize,
    pub mark: Mark,
}

/// A comment the scanner collected (yaml_comment_t).
#[derive(Clone, Debug, Default)]
pub struct Comment {
    pub scan_mark: Mark,
    pub token_mark: Mark,
    pub start_mark: Mark,
    pub end_mark: Mark,
    pub head: Vec<u8>,
    pub line: Vec<u8>,
    pub foot: Vec<u8>,
}

const MAX_FLOW_LEVEL: i64 = 10000;
const MAX_INDENTS: usize = 10000;

/// The size of a yaml_token_t on 64-bit Go, for the capacity of the queue.
const TOKEN_SIZE: usize = 144;

const SIZE_CLASSES: [usize; 67] = [
    8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256, 288, 320, 352,
    384, 416, 448, 480, 512, 576, 640, 704, 768, 896, 1024, 1152, 1280, 1408, 1536, 1792, 2048,
    2304, 2688, 3072, 3200, 3456, 4096, 4864, 5376, 6144, 6528, 6784, 6912, 8192, 9472, 9728,
    10240, 10880, 12288, 13568, 14336, 16384, 18432, 19072, 20480, 21760, 24576, 27264, 28672,
    32768,
];

/// Go's roundupsize for objects with pointers (runtime/msize.go).
fn roundupsize(size: usize) -> usize {
    if size <= 32768 - 8 {
        let mut req = size;
        if req > 512 {
            req += 8; // the malloc header
        }
        let class = SIZE_CLASSES
            .iter()
            .copied()
            .find(|&c| c >= req)
            .unwrap_or(32768);
        return class - (req - size);
    }
    (size + 8191) & !8191
}

/// The capacity append gives a slice of tokens growing past old_cap.
fn grow_cap(old_cap: usize, new_len: usize) -> usize {
    let double = old_cap * 2;
    let newcap = if new_len > double {
        new_len
    } else if old_cap < 256 {
        double
    } else {
        let mut c = old_cap;
        while c < new_len {
            c += (c + 3 * 256) >> 2;
        }
        c
    };
    roundupsize(newcap * TOKEN_SIZE) / TOKEN_SIZE
}

impl Parser {
    fn buf(&self) -> &[u8] {
        &self.buffer[..self.buffer_len]
    }

    /// The byte k bytes ahead of the current position.
    fn b(&self, k: usize) -> u8 {
        at(self.buf(), self.buffer_pos + k)
    }

    fn cache(&mut self, length: usize) -> bool {
        self.unread >= length || self.update_buffer(length)
    }

    fn skip(&mut self) {
        if !is_blank(self.buf(), self.buffer_pos) {
            self.newlines = 0;
        }
        self.mark.index = self.mark.index.wrapping_add(1);
        self.mark.column = self.mark.column.wrapping_add(1);
        self.unread = self.unread.wrapping_sub(1);
        self.buffer_pos += width(self.b(0));
    }

    fn skip_line(&mut self) {
        if is_crlf(self.buf(), self.buffer_pos) {
            self.mark.index = self.mark.index.wrapping_add(2);
            self.mark.column = 0;
            self.mark.line += 1;
            self.unread = self.unread.wrapping_sub(2);
            self.buffer_pos += 2;
            self.newlines += 1;
        } else if is_break(self.buf(), self.buffer_pos) {
            self.mark.index = self.mark.index.wrapping_add(1);
            self.mark.column = 0;
            self.mark.line += 1;
            self.unread = self.unread.wrapping_sub(1);
            self.buffer_pos += width(self.b(0));
            self.newlines += 1;
        }
    }

    /// Copies the current character to s.
    fn read(&mut self, s: &mut Vec<u8>) {
        if !is_blank(self.buf(), self.buffer_pos) {
            self.newlines = 0;
        }
        // Go slices the buffer up to its capacity here.
        let w = width(self.b(0)).max(1);
        let end = (self.buffer_pos + w).min(self.buffer.len());
        s.extend_from_slice(&self.buffer[self.buffer_pos..end]);
        self.buffer_pos += w;
        self.mark.index = self.mark.index.wrapping_add(1);
        self.mark.column = self.mark.column.wrapping_add(1);
        self.unread = self.unread.wrapping_sub(1);
    }

    /// Copies a line break to s as '\n' (or LS/PS as they are).
    fn read_line(&mut self, s: &mut Vec<u8>) {
        let (c0, c1, c2) = (self.b(0), self.b(1), self.b(2));
        if c0 == b'\r' && c1 == b'\n' {
            s.push(b'\n');
            self.buffer_pos += 2;
            self.mark.index = self.mark.index.wrapping_add(1);
            self.unread = self.unread.wrapping_sub(1);
        } else if c0 == b'\r' || c0 == b'\n' {
            s.push(b'\n');
            self.buffer_pos += 1;
        } else if c0 == 0xc2 && c1 == 0x85 {
            s.push(b'\n');
            self.buffer_pos += 2;
        } else if c0 == 0xe2 && c1 == 0x80 && (c2 == 0xa8 || c2 == 0xa9) {
            s.extend_from_slice(&[c0, c1, c2]);
            self.buffer_pos += 3;
        } else {
            return;
        }
        self.mark.index = self.mark.index.wrapping_add(1);
        self.mark.column = 0;
        self.mark.line += 1;
        self.unread = self.unread.wrapping_sub(1);
        self.newlines += 1;
    }

    fn insert_token(&mut self, pos: i64, token: Token) {
        // Move the queue to the start of its array when the array is full.
        if self.tokens_head > 0 && self.tokens.len() == self.tokens_cap {
            self.tokens.drain(..self.tokens_head);
            self.tokens_head = 0;
        }
        if self.tokens.len() == self.tokens_cap {
            self.tokens_cap = grow_cap(self.tokens_cap, self.tokens.len() + 1);
        }
        if pos < 0 {
            self.tokens.push(token);
        } else {
            self.tokens.insert(self.tokens_head + pos as usize, token);
        }
    }

    fn set_scanner_error(&mut self, context: &str, context_mark: Mark, problem: &str) -> bool {
        self.error = ErrorType::Scanner;
        self.context = context.to_string();
        self.context_mark = context_mark;
        self.problem = problem.to_string();
        self.problem_mark = self.mark;
        false
    }

    fn set_scanner_tag_error(
        &mut self,
        directive: bool,
        context_mark: Mark,
        problem: &str,
    ) -> bool {
        let context = if directive {
            "while parsing a %TAG directive"
        } else {
            "while parsing a tag"
        };
        self.set_scanner_error(context, context_mark, problem)
    }

    /// Fetches tokens until the head one can be handed out.
    pub(super) fn fetch_more_tokens(&mut self) -> bool {
        loop {
            if (self.tokens_head as i64) < self.tokens.len() as i64 - 2 {
                // If a potential simple key is at the head position, we
                // need to fetch the next token to disambiguate it.
                let Some(&idx) = self.simple_keys_by_tok.get(&self.tokens_parsed) else {
                    break;
                };
                let (valid, ok) = self.simple_key_is_valid(idx);
                if !ok {
                    return false;
                }
                if !valid {
                    break;
                }
            }
            if !self.fetch_next_token() {
                return false;
            }
        }
        self.token_available = true;
        true
    }

    fn fetch_next_token(&mut self) -> bool {
        if !self.cache(1) {
            return false;
        }
        if !self.stream_start_produced {
            return self.fetch_stream_start();
        }
        let scan_mark = self.mark;
        if !self.scan_to_next_token() {
            return false;
        }
        if !self.unroll_indent(self.mark.column as i64, scan_mark) {
            return false;
        }
        if !self.cache(4) {
            return false;
        }
        if is_z(self.buf(), self.buffer_pos) {
            return self.fetch_stream_end();
        }
        if self.mark.column == 0 && self.b(0) == b'%' {
            return self.fetch_directive();
        }
        let (c0, c1, c2) = (self.b(0), self.b(1), self.b(2));
        if self.mark.column == 0
            && c0 == b'-'
            && c1 == b'-'
            && c2 == b'-'
            && is_blankz(self.buf(), self.buffer_pos + 3)
        {
            return self.fetch_document_indicator(TokenType::DocumentStart);
        }
        if self.mark.column == 0
            && c0 == b'.'
            && c1 == b'.'
            && c2 == b'.'
            && is_blankz(self.buf(), self.buffer_pos + 3)
        {
            return self.fetch_document_indicator(TokenType::DocumentEnd);
        }
        let mut comment_mark = self.mark;
        if !self.tokens.is_empty()
            && ((self.flow_level == 0 && c0 == b':') || (self.flow_level > 0 && c0 == b','))
        {
            // Associate any following comments with the prior token.
            comment_mark = self.tokens[self.tokens.len() - 1].start_mark;
        }
        if !self.fetch_token_proper() {
            return false;
        }
        // Go runs this in a deferred function once the token is fetched.
        if !self.tokens.is_empty()
            && self.tokens[self.tokens.len() - 1].typ == TokenType::BlockEntry
        {
            // Sequence indicators alone have no line comments. It becomes
            // a head comment for whatever follows.
            return true;
        }
        self.scan_line_comment(comment_mark)
    }

    fn fetch_token_proper(&mut self) -> bool {
        let c = self.b(0);
        match c {
            b'[' => return self.fetch_flow_collection_start(TokenType::FlowSequenceStart),
            b'{' => return self.fetch_flow_collection_start(TokenType::FlowMappingStart),
            b']' => return self.fetch_flow_collection_end(TokenType::FlowSequenceEnd),
            b'}' => return self.fetch_flow_collection_end(TokenType::FlowMappingEnd),
            b',' => return self.fetch_flow_entry(),
            _ => {}
        }
        let next_blankz = is_blankz(self.buf(), self.buffer_pos + 1);
        if c == b'-' && next_blankz {
            return self.fetch_block_entry();
        }
        if c == b'?' && (self.flow_level > 0 || next_blankz) {
            return self.fetch_key();
        }
        if c == b':' && (self.flow_level > 0 || next_blankz) {
            return self.fetch_value();
        }
        match c {
            b'*' => return self.fetch_anchor(TokenType::Alias),
            b'&' => return self.fetch_anchor(TokenType::Anchor),
            b'!' => return self.fetch_tag(),
            b'|' if self.flow_level == 0 => return self.fetch_block_scalar(true),
            b'>' if self.flow_level == 0 => return self.fetch_block_scalar(false),
            b'\'' => return self.fetch_flow_scalar(true),
            b'"' => return self.fetch_flow_scalar(false),
            _ => {}
        }
        let indicator = matches!(
            c,
            b'-' | b'?'
                | b':'
                | b','
                | b'['
                | b']'
                | b'{'
                | b'}'
                | b'#'
                | b'&'
                | b'*'
                | b'!'
                | b'|'
                | b'>'
                | b'\''
                | b'"'
                | b'%'
                | b'@'
                | b'`'
        );
        if !(is_blankz(self.buf(), self.buffer_pos) || indicator)
            || (c == b'-' && !is_blank(self.buf(), self.buffer_pos + 1))
            || (self.flow_level == 0 && (c == b'?' || c == b':') && !next_blankz)
        {
            return self.fetch_plain_scalar();
        }
        let mark = self.mark;
        self.set_scanner_error(
            "while scanning for the next token",
            mark,
            "found character that cannot start any token",
        )
    }

    /// Whether the simple key at idx is still possible; ok is false on an
    /// error.
    fn simple_key_is_valid(&mut self, idx: usize) -> (bool, bool) {
        let key = self.simple_keys[idx];
        if !key.possible {
            return (false, true);
        }
        // The 1.2 specification says:
        //
        //     "If the ? indicator is omitted, parsing needs to see past the
        //     implicit key to recognize it as such. To limit the amount of
        //     lookahead required, the “:” indicator must appear at most 1024
        //     Unicode characters beyond the start of the key. In addition, the key
        //     is restricted to a single line."
        if key.mark.line < self.mark.line || key.mark.index.wrapping_add(1024) < self.mark.index {
            // Check if the potential simple key to be removed is required.
            if key.required {
                return (
                    false,
                    self.set_scanner_error(
                        "while scanning a simple key",
                        key.mark,
                        "could not find expected ':'",
                    ),
                );
            }
            self.simple_keys[idx].possible = false;
            return (false, true);
        }
        (true, true)
    }

    fn save_simple_key(&mut self) -> bool {
        // A simple key is required at the current position if the scanner
        // is in the block context and the current column coincides with
        // the indentation level.
        let required = self.flow_level == 0 && self.indent == self.mark.column as i64;
        if self.simple_key_allowed {
            let key = SimpleKey {
                possible: true,
                required,
                token_number: self.tokens_parsed + (self.tokens.len() - self.tokens_head),
                mark: self.mark,
            };
            if !self.remove_simple_key() {
                return false;
            }
            let last = self.simple_keys.len() - 1;
            self.simple_keys[last] = key;
            self.simple_keys_by_tok.insert(key.token_number, last);
        }
        true
    }

    fn remove_simple_key(&mut self) -> bool {
        let i = self.simple_keys.len() - 1;
        if self.simple_keys[i].possible {
            if self.simple_keys[i].required {
                let mark = self.simple_keys[i].mark;
                return self.set_scanner_error(
                    "while scanning a simple key",
                    mark,
                    "could not find expected ':'",
                );
            }
            self.simple_keys[i].possible = false;
            let n = self.simple_keys[i].token_number;
            self.simple_keys_by_tok.remove(&n);
        }
        true
    }

    fn increase_flow_level(&mut self) -> bool {
        self.simple_keys.push(SimpleKey {
            possible: false,
            required: false,
            token_number: self.tokens_parsed + (self.tokens.len() - self.tokens_head),
            mark: self.mark,
        });
        self.flow_level += 1;
        if self.flow_level > MAX_FLOW_LEVEL {
            let mark = self.simple_keys[self.simple_keys.len() - 1].mark;
            return self.set_scanner_error(
                "while increasing flow level",
                mark,
                &format!("exceeded max depth of {MAX_FLOW_LEVEL}"),
            );
        }
        true
    }

    fn decrease_flow_level(&mut self) -> bool {
        if self.flow_level > 0 {
            self.flow_level -= 1;
            let last = self.simple_keys.len() - 1;
            let n = self.simple_keys[last].token_number;
            self.simple_keys_by_tok.remove(&n);
            self.simple_keys.pop();
        }
        true
    }

    fn roll_indent(&mut self, column: i64, number: i64, typ: TokenType, mark: Mark) -> bool {
        if self.flow_level > 0 {
            return true;
        }
        if self.indent < column {
            self.indents.push(self.indent);
            self.indent = column;
            if self.indents.len() > MAX_INDENTS {
                let m = self.simple_keys[self.simple_keys.len() - 1].mark;
                return self.set_scanner_error(
                    "while increasing indent level",
                    m,
                    &format!("exceeded max depth of {MAX_INDENTS}"),
                );
            }
            let token = Token {
                typ,
                start_mark: mark,
                end_mark: mark,
                ..Token::default()
            };
            let mut number = number;
            if number > -1 {
                number -= self.tokens_parsed as i64;
            }
            self.insert_token(number, token);
        }
        true
    }

    fn unroll_indent(&mut self, column: i64, scan_mark: Mark) -> bool {
        if self.flow_level > 0 {
            return true;
        }
        let mut block_mark = scan_mark;
        block_mark.index = block_mark.index.wrapping_sub(1);
        while self.indent > column {
            // Indentation is closed at the start of the comments that
            // belong to the block, if any.
            let mut stop_index = block_mark.index as i64;
            for i in (0..self.comments.len()).rev() {
                let comment = &self.comments[i];
                if (comment.end_mark.index as i64) < stop_index {
                    // Don't go back beyond the start of the comment/whitespace scan, unless column < 0.
                    // If requested indent column is < 0, then the document is over and everything else
                    // is a foot anyway.
                    break;
                }
                if comment.start_mark.column as i64 == self.indent + 1 {
                    // This is a good match. But maybe there's a former comment
                    // at that same indent level, so keep searching.
                    block_mark = comment.start_mark;
                }
                // While the end of the former comment matches with
                // the start of the following one, we know there's
                // nothing in between and scanning is still safe.
                stop_index = comment.scan_mark.index as i64;
            }
            let token = Token {
                typ: TokenType::BlockEnd,
                start_mark: block_mark,
                end_mark: block_mark,
                ..Token::default()
            };
            self.insert_token(-1, token);
            self.indent = self.indents.pop().unwrap_or(-1);
        }
        true
    }

    fn fetch_stream_start(&mut self) -> bool {
        self.indent = -1;
        self.simple_keys.push(SimpleKey::default());
        self.simple_keys_by_tok.clear();
        self.simple_key_allowed = true;
        self.stream_start_produced = true;
        let token = Token {
            typ: TokenType::StreamStart,
            start_mark: self.mark,
            end_mark: self.mark,
            encoding: self.encoding,
            ..Token::default()
        };
        self.insert_token(-1, token);
        true
    }

    fn fetch_stream_end(&mut self) -> bool {
        // Force new line.
        if self.mark.column != 0 {
            self.mark.column = 0;
            self.mark.line += 1;
        }
        if !self.unroll_indent(-1, self.mark) {
            return false;
        }
        if !self.remove_simple_key() {
            return false;
        }
        self.simple_key_allowed = false;
        let token = Token {
            typ: TokenType::StreamEnd,
            start_mark: self.mark,
            end_mark: self.mark,
            ..Token::default()
        };
        self.insert_token(-1, token);
        true
    }

    fn fetch_directive(&mut self) -> bool {
        if !self.unroll_indent(-1, self.mark) {
            return false;
        }
        if !self.remove_simple_key() {
            return false;
        }
        self.simple_key_allowed = false;
        let mut token = Token::default();
        if !self.scan_directive(&mut token) {
            return false;
        }
        self.insert_token(-1, token);
        true
    }

    fn fetch_document_indicator(&mut self, typ: TokenType) -> bool {
        if !self.unroll_indent(-1, self.mark) {
            return false;
        }
        if !self.remove_simple_key() {
            return false;
        }
        self.simple_key_allowed = false;
        let start_mark = self.mark;
        self.skip();
        self.skip();
        self.skip();
        let end_mark = self.mark;
        self.insert_token(
            -1,
            Token {
                typ,
                start_mark,
                end_mark,
                ..Token::default()
            },
        );
        true
    }

    fn fetch_flow_collection_start(&mut self, typ: TokenType) -> bool {
        if !self.save_simple_key() {
            return false;
        }
        if !self.increase_flow_level() {
            return false;
        }
        self.simple_key_allowed = true;
        let start_mark = self.mark;
        self.skip();
        let end_mark = self.mark;
        self.insert_token(
            -1,
            Token {
                typ,
                start_mark,
                end_mark,
                ..Token::default()
            },
        );
        true
    }

    fn fetch_flow_collection_end(&mut self, typ: TokenType) -> bool {
        if !self.remove_simple_key() {
            return false;
        }
        if !self.decrease_flow_level() {
            return false;
        }
        self.simple_key_allowed = false;
        let start_mark = self.mark;
        self.skip();
        let end_mark = self.mark;
        self.insert_token(
            -1,
            Token {
                typ,
                start_mark,
                end_mark,
                ..Token::default()
            },
        );
        true
    }

    fn fetch_flow_entry(&mut self) -> bool {
        if !self.remove_simple_key() {
            return false;
        }
        self.simple_key_allowed = true;
        let start_mark = self.mark;
        self.skip();
        let end_mark = self.mark;
        self.insert_token(
            -1,
            Token {
                typ: TokenType::FlowEntry,
                start_mark,
                end_mark,
                ..Token::default()
            },
        );
        true
    }

    fn fetch_block_entry(&mut self) -> bool {
        if self.flow_level == 0 {
            if !self.simple_key_allowed {
                let mark = self.mark;
                return self.set_scanner_error(
                    "",
                    mark,
                    "block sequence entries are not allowed in this context",
                );
            }
            if !self.roll_indent(
                self.mark.column as i64,
                -1,
                TokenType::BlockSequenceStart,
                self.mark,
            ) {
                return false;
            }
        }
        if !self.remove_simple_key() {
            return false;
        }
        self.simple_key_allowed = true;
        let start_mark = self.mark;
        self.skip();
        let end_mark = self.mark;
        self.insert_token(
            -1,
            Token {
                typ: TokenType::BlockEntry,
                start_mark,
                end_mark,
                ..Token::default()
            },
        );
        true
    }

    fn fetch_key(&mut self) -> bool {
        if self.flow_level == 0 {
            if !self.simple_key_allowed {
                let mark = self.mark;
                return self.set_scanner_error(
                    "",
                    mark,
                    "mapping keys are not allowed in this context",
                );
            }
            if !self.roll_indent(
                self.mark.column as i64,
                -1,
                TokenType::BlockMappingStart,
                self.mark,
            ) {
                return false;
            }
        }
        if !self.remove_simple_key() {
            return false;
        }
        self.simple_key_allowed = self.flow_level == 0;
        let start_mark = self.mark;
        self.skip();
        let end_mark = self.mark;
        self.insert_token(
            -1,
            Token {
                typ: TokenType::Key,
                start_mark,
                end_mark,
                ..Token::default()
            },
        );
        true
    }

    fn fetch_value(&mut self) -> bool {
        let idx = self.simple_keys.len() - 1;
        let (valid, ok) = self.simple_key_is_valid(idx);
        if !ok {
            return false;
        }
        if valid {
            let key = self.simple_keys[idx];
            // Create the KEY token and insert it into the queue.
            let token = Token {
                typ: TokenType::Key,
                start_mark: key.mark,
                end_mark: key.mark,
                ..Token::default()
            };
            self.insert_token(key.token_number as i64 - self.tokens_parsed as i64, token);
            // In the block context, we may need to add the BLOCK-MAPPING-START token.
            if !self.roll_indent(
                key.mark.column as i64,
                key.token_number as i64,
                TokenType::BlockMappingStart,
                key.mark,
            ) {
                return false;
            }
            self.simple_keys[idx].possible = false;
            self.simple_keys_by_tok.remove(&key.token_number);
            self.simple_key_allowed = false;
        } else {
            // The ':' indicator follows a complex key.
            if self.flow_level == 0 {
                if !self.simple_key_allowed {
                    let mark = self.mark;
                    return self.set_scanner_error(
                        "",
                        mark,
                        "mapping values are not allowed in this context",
                    );
                }
                if !self.roll_indent(
                    self.mark.column as i64,
                    -1,
                    TokenType::BlockMappingStart,
                    self.mark,
                ) {
                    return false;
                }
            }
            self.simple_key_allowed = self.flow_level == 0;
        }
        let start_mark = self.mark;
        self.skip();
        let end_mark = self.mark;
        self.insert_token(
            -1,
            Token {
                typ: TokenType::Value,
                start_mark,
                end_mark,
                ..Token::default()
            },
        );
        true
    }

    fn fetch_anchor(&mut self, typ: TokenType) -> bool {
        if !self.save_simple_key() {
            return false;
        }
        self.simple_key_allowed = false;
        let mut token = Token::default();
        if !self.scan_anchor(&mut token, typ) {
            return false;
        }
        self.insert_token(-1, token);
        true
    }

    fn fetch_tag(&mut self) -> bool {
        if !self.save_simple_key() {
            return false;
        }
        self.simple_key_allowed = false;
        let mut token = Token::default();
        if !self.scan_tag(&mut token) {
            return false;
        }
        self.insert_token(-1, token);
        true
    }

    fn fetch_block_scalar(&mut self, literal: bool) -> bool {
        if !self.remove_simple_key() {
            return false;
        }
        self.simple_key_allowed = true;
        let mut token = Token::default();
        if !self.scan_block_scalar(&mut token, literal) {
            return false;
        }
        self.insert_token(-1, token);
        true
    }

    fn fetch_flow_scalar(&mut self, single: bool) -> bool {
        if !self.save_simple_key() {
            return false;
        }
        self.simple_key_allowed = false;
        let mut token = Token::default();
        if !self.scan_flow_scalar(&mut token, single) {
            return false;
        }
        self.insert_token(-1, token);
        true
    }

    fn fetch_plain_scalar(&mut self) -> bool {
        if !self.save_simple_key() {
            return false;
        }
        self.simple_key_allowed = false;
        let mut token = Token::default();
        if !self.scan_plain_scalar(&mut token) {
            return false;
        }
        self.insert_token(-1, token);
        true
    }

    /// Skips spaces, comments, and line breaks up to the next token.
    fn scan_to_next_token(&mut self) -> bool {
        let scan_mark = self.mark;
        loop {
            if !self.cache(1) {
                return false;
            }
            // Allow the BOM.
            if self.mark.column == 0 && is_bom(self.buf(), self.buffer_pos) {
                self.skip();
            }
            if !self.cache(1) {
                return false;
            }
            // Eat whitespaces. Tabs are allowed in the flow context, and in
            // the block context after a simple key is impossible.
            while self.b(0) == b' '
                || ((self.flow_level > 0 || !self.simple_key_allowed) && self.b(0) == b'\t')
            {
                self.skip();
                if !self.cache(1) {
                    return false;
                }
            }
            // Check if we just had a line comment under a sequence entry
            // that looks more like a header to the following content.
            if !self.comments.is_empty() && self.tokens.len() > 1 {
                let a = self.tokens[self.tokens.len() - 2].typ;
                let b = self.tokens[self.tokens.len() - 1].typ;
                let breaks = is_break(self.buf(), self.buffer_pos);
                let mark = self.mark;
                let last = self.comments.len() - 1;
                let comment = &mut self.comments[last];
                if a == TokenType::BlockSequenceStart
                    && b == TokenType::BlockEntry
                    && !comment.line.is_empty()
                    && !breaks
                {
                    comment.head = std::mem::take(&mut comment.line);
                    if comment.start_mark.line as i64 == mark.line as i64 - 1 {
                        comment.token_mark = mark;
                    }
                }
            }
            // Eat a comment until a line break.
            if self.b(0) == b'#' && !self.scan_comments(scan_mark) {
                return false;
            }
            // If it is a line break, eat it.
            if is_break(self.buf(), self.buffer_pos) {
                if !self.cache(2) {
                    return false;
                }
                self.skip_line();
                // In the block context, a new line may start a simple key.
                if self.flow_level == 0 {
                    self.simple_key_allowed = true;
                }
            } else {
                break; // We have found a token.
            }
        }
        true
    }

    fn scan_directive(&mut self, token: &mut Token) -> bool {
        let start_mark = self.mark;
        self.skip();
        let mut name = Vec::new();
        if !self.scan_directive_name(start_mark, &mut name) {
            return false;
        }
        if name == b"YAML" {
            let (mut major, mut minor) = (0i8, 0i8);
            if !self.scan_version_directive_value(start_mark, &mut major, &mut minor) {
                return false;
            }
            *token = Token {
                typ: TokenType::VersionDirective,
                start_mark,
                end_mark: self.mark,
                major,
                minor,
                ..Token::default()
            };
        } else if name == b"TAG" {
            let (mut handle, mut prefix) = (Vec::new(), Vec::new());
            if !self.scan_tag_directive_value(start_mark, &mut handle, &mut prefix) {
                return false;
            }
            *token = Token {
                typ: TokenType::TagDirective,
                start_mark,
                end_mark: self.mark,
                value: handle,
                prefix,
                ..Token::default()
            };
        } else {
            self.set_scanner_error(
                "while scanning a directive",
                start_mark,
                "found unknown directive name",
            );
            return false;
        }
        if !self.cache(1) {
            return false;
        }
        while is_blank(self.buf(), self.buffer_pos) {
            self.skip();
            if !self.cache(1) {
                return false;
            }
        }
        if self.b(0) == b'#' {
            // [Go] Discard this inline comment for the time being.
            while !is_breakz(self.buf(), self.buffer_pos) {
                self.skip();
                if !self.cache(1) {
                    return false;
                }
            }
        }
        if !is_breakz(self.buf(), self.buffer_pos) {
            self.set_scanner_error(
                "while scanning a directive",
                start_mark,
                "did not find expected comment or line break",
            );
            return false;
        }
        if is_break(self.buf(), self.buffer_pos) {
            if !self.cache(2) {
                return false;
            }
            self.skip_line();
        }
        true
    }

    fn scan_directive_name(&mut self, start_mark: Mark, name: &mut Vec<u8>) -> bool {
        if !self.cache(1) {
            return false;
        }
        let mut s = Vec::new();
        while is_alpha(self.buf(), self.buffer_pos) {
            self.read(&mut s);
            if !self.cache(1) {
                return false;
            }
        }
        if s.is_empty() {
            self.set_scanner_error(
                "while scanning a directive",
                start_mark,
                "could not find expected directive name",
            );
            return false;
        }
        if !is_blankz(self.buf(), self.buffer_pos) {
            self.set_scanner_error(
                "while scanning a directive",
                start_mark,
                "found unexpected non-alphabetical character",
            );
            return false;
        }
        *name = s;
        true
    }

    fn scan_version_directive_value(
        &mut self,
        start_mark: Mark,
        major: &mut i8,
        minor: &mut i8,
    ) -> bool {
        if !self.cache(1) {
            return false;
        }
        while is_blank(self.buf(), self.buffer_pos) {
            self.skip();
            if !self.cache(1) {
                return false;
            }
        }
        if !self.scan_version_directive_number(start_mark, major) {
            return false;
        }
        if self.b(0) != b'.' {
            return self.set_scanner_error(
                "while scanning a %YAML directive",
                start_mark,
                "did not find expected digit or '.' character",
            );
        }
        self.skip();
        self.scan_version_directive_number(start_mark, minor)
    }

    fn scan_version_directive_number(&mut self, start_mark: Mark, number: &mut i8) -> bool {
        if !self.cache(1) {
            return false;
        }
        let (mut value, mut length) = (0i8, 0i8);
        while is_digit(self.buf(), self.buffer_pos) {
            length += 1;
            if length > 2 {
                return self.set_scanner_error(
                    "while scanning a %YAML directive",
                    start_mark,
                    "found extremely long version number",
                );
            }
            value = value
                .wrapping_mul(10)
                .wrapping_add(as_digit(self.buf(), self.buffer_pos) as i8);
            self.skip();
            if !self.cache(1) {
                return false;
            }
        }
        if length == 0 {
            return self.set_scanner_error(
                "while scanning a %YAML directive",
                start_mark,
                "did not find expected version number",
            );
        }
        *number = value;
        true
    }

    fn scan_tag_directive_value(
        &mut self,
        start_mark: Mark,
        handle: &mut Vec<u8>,
        prefix: &mut Vec<u8>,
    ) -> bool {
        let (mut handle_value, mut prefix_value) = (Vec::new(), Vec::new());
        if !self.cache(1) {
            return false;
        }
        while is_blank(self.buf(), self.buffer_pos) {
            self.skip();
            if !self.cache(1) {
                return false;
            }
        }
        if !self.scan_tag_handle(true, start_mark, &mut handle_value) {
            return false;
        }
        if !self.cache(1) {
            return false;
        }
        if !is_blank(self.buf(), self.buffer_pos) {
            self.set_scanner_error(
                "while scanning a %TAG directive",
                start_mark,
                "did not find expected whitespace",
            );
            return false;
        }
        while is_blank(self.buf(), self.buffer_pos) {
            self.skip();
            if !self.cache(1) {
                return false;
            }
        }
        if !self.scan_tag_uri(true, &[], start_mark, &mut prefix_value) {
            return false;
        }
        if !self.cache(1) {
            return false;
        }
        if !is_blankz(self.buf(), self.buffer_pos) {
            self.set_scanner_error(
                "while scanning a %TAG directive",
                start_mark,
                "did not find expected whitespace or line break",
            );
            return false;
        }
        *handle = handle_value;
        *prefix = prefix_value;
        true
    }

    fn scan_anchor(&mut self, token: &mut Token, typ: TokenType) -> bool {
        let mut s = Vec::new();
        let start_mark = self.mark;
        self.skip();
        if !self.cache(1) {
            return false;
        }
        while is_alpha(self.buf(), self.buffer_pos) {
            self.read(&mut s);
            if !self.cache(1) {
                return false;
            }
        }
        let end_mark = self.mark;
        // Check if length of the anchor is greater than 0 and it is
        // followed by a whitespace character or one of the indicators:
        // '?', ':', ',', ']', '}', '%', '@', '`'.
        let c = self.b(0);
        if s.is_empty()
            || !(is_blankz(self.buf(), self.buffer_pos)
                || matches!(c, b'?' | b':' | b',' | b']' | b'}' | b'%' | b'@' | b'`'))
        {
            let context = if typ == TokenType::Anchor {
                "while scanning an anchor"
            } else {
                "while scanning an alias"
            };
            self.set_scanner_error(
                context,
                start_mark,
                "did not find expected alphabetic or numeric character",
            );
            return false;
        }
        *token = Token {
            typ,
            start_mark,
            end_mark,
            value: s,
            ..Token::default()
        };
        true
    }

    fn scan_tag(&mut self, token: &mut Token) -> bool {
        let mut handle = Vec::new();
        let mut suffix = Vec::new();
        let start_mark = self.mark;
        // Check if the tag is in the canonical form.
        if !self.cache(2) {
            return false;
        }
        if self.b(1) == b'<' {
            // Keep the handle as ''. Eat '!<'.
            self.skip();
            self.skip();
            if !self.scan_tag_uri(false, &[], start_mark, &mut suffix) {
                return false;
            }
            if self.b(0) != b'>' {
                self.set_scanner_error(
                    "while scanning a tag",
                    start_mark,
                    "did not find the expected '>'",
                );
                return false;
            }
            self.skip();
        } else {
            // The tag has either the '!suffix' or the '!handle!suffix' form.
            if !self.scan_tag_handle(false, start_mark, &mut handle) {
                return false;
            }
            if handle[0] == b'!' && handle.len() > 1 && handle[handle.len() - 1] == b'!' {
                if !self.scan_tag_uri(false, &[], start_mark, &mut suffix) {
                    return false;
                }
            } else {
                let head = handle.clone();
                if !self.scan_tag_uri(false, &head, start_mark, &mut suffix) {
                    return false;
                }
                handle = b"!".to_vec();
                if suffix.is_empty() {
                    std::mem::swap(&mut handle, &mut suffix);
                }
            }
        }
        if !self.cache(1) {
            return false;
        }
        if !is_blankz(self.buf(), self.buffer_pos) {
            self.set_scanner_error(
                "while scanning a tag",
                start_mark,
                "did not find expected whitespace or line break",
            );
            return false;
        }
        *token = Token {
            typ: TokenType::Tag,
            start_mark,
            end_mark: self.mark,
            value: handle,
            suffix,
            ..Token::default()
        };
        true
    }

    fn scan_tag_handle(&mut self, directive: bool, start_mark: Mark, handle: &mut Vec<u8>) -> bool {
        if !self.cache(1) {
            return false;
        }
        if self.b(0) != b'!' {
            self.set_scanner_tag_error(directive, start_mark, "did not find expected '!'");
            return false;
        }
        let mut s = Vec::new();
        self.read(&mut s);
        if !self.cache(1) {
            return false;
        }
        while is_alpha(self.buf(), self.buffer_pos) {
            self.read(&mut s);
            if !self.cache(1) {
                return false;
            }
        }
        if self.b(0) == b'!' {
            self.read(&mut s);
        } else if directive && s != b"!" {
            // It's either the '!' tag or not really a tag handle. If it's
            // a %TAG directive, it's an error. If it's a tag token, it must
            // be a part of URI.
            self.set_scanner_tag_error(directive, start_mark, "did not find expected '!'");
            return false;
        }
        *handle = s;
        true
    }

    fn scan_tag_uri(
        &mut self,
        directive: bool,
        head: &[u8],
        start_mark: Mark,
        uri: &mut Vec<u8>,
    ) -> bool {
        let mut s = Vec::new();
        let mut has_tag = !head.is_empty();
        // Copy the head if needed. Note that we don't copy the leading '!'.
        if head.len() > 1 {
            s.extend_from_slice(&head[1..]);
        }
        if !self.cache(1) {
            return false;
        }
        // The set of characters that may appear in URI is as follows:
        //      '0'-'9', 'A'-'Z', 'a'-'z', '_', '-', ';', '/', '?', ':', '@', '&',
        //      '=', '+', '$', ',', '.', '!', '~', '*', '\'', '(', ')', '[', ']', '%'.
        loop {
            let c = self.b(0);
            let uri_char = is_alpha(self.buf(), self.buffer_pos)
                || matches!(
                    c,
                    b';' | b'/'
                        | b'?'
                        | b':'
                        | b'@'
                        | b'&'
                        | b'='
                        | b'+'
                        | b'$'
                        | b','
                        | b'.'
                        | b'!'
                        | b'~'
                        | b'*'
                        | b'\''
                        | b'('
                        | b')'
                        | b'['
                        | b']'
                        | b'%'
                );
            if !uri_char {
                break;
            }
            if c == b'%' {
                if !self.scan_uri_escapes(directive, start_mark, &mut s) {
                    return false;
                }
            } else {
                self.read(&mut s);
            }
            if !self.cache(1) {
                return false;
            }
            has_tag = true;
        }
        if !has_tag {
            self.set_scanner_tag_error(directive, start_mark, "did not find expected tag URI");
            return false;
        }
        *uri = s;
        true
    }

    fn scan_uri_escapes(&mut self, directive: bool, start_mark: Mark, s: &mut Vec<u8>) -> bool {
        // Decode the required number of characters.
        let mut w: i64 = 1024;
        while w > 0 {
            // Check for a URI escaped octet.
            if !self.cache(3) {
                return false;
            }
            if !(self.b(0) == b'%'
                && is_hex(self.buf(), self.buffer_pos + 1)
                && is_hex(self.buf(), self.buffer_pos + 2))
            {
                return self.set_scanner_tag_error(
                    directive,
                    start_mark,
                    "did not find URI escaped octet",
                );
            }
            let octet = ((as_hex(self.buf(), self.buffer_pos + 1) << 4)
                + as_hex(self.buf(), self.buffer_pos + 2)) as u8;
            if w == 1024 {
                w = width(octet) as i64;
                if w == 0 {
                    return self.set_scanner_tag_error(
                        directive,
                        start_mark,
                        "found an incorrect leading UTF-8 octet",
                    );
                }
            } else if octet & 0xc0 != 0x80 {
                return self.set_scanner_tag_error(
                    directive,
                    start_mark,
                    "found an incorrect trailing UTF-8 octet",
                );
            }
            s.push(octet);
            self.skip();
            self.skip();
            self.skip();
            w -= 1;
        }
        true
    }

    fn scan_block_scalar(&mut self, token: &mut Token, literal: bool) -> bool {
        let start_mark = self.mark;
        self.skip();
        if !self.cache(1) {
            return false;
        }
        let mut chomping = 0;
        let mut increment: i64 = 0;
        let c = self.b(0);
        if c == b'+' || c == b'-' {
            chomping = if c == b'+' { 1 } else { -1 };
            self.skip();
            if !self.cache(1) {
                return false;
            }
            if is_digit(self.buf(), self.buffer_pos) {
                if self.b(0) == b'0' {
                    self.set_scanner_error(
                        "while scanning a block scalar",
                        start_mark,
                        "found an indentation indicator equal to 0",
                    );
                    return false;
                }
                increment = as_digit(self.buf(), self.buffer_pos) as i64;
                self.skip();
            }
        } else if is_digit(self.buf(), self.buffer_pos) {
            if c == b'0' {
                self.set_scanner_error(
                    "while scanning a block scalar",
                    start_mark,
                    "found an indentation indicator equal to 0",
                );
                return false;
            }
            increment = as_digit(self.buf(), self.buffer_pos) as i64;
            self.skip();
            if !self.cache(1) {
                return false;
            }
            let c = self.b(0);
            if c == b'+' || c == b'-' {
                chomping = if c == b'+' { 1 } else { -1 };
                self.skip();
            }
        }
        // Eat whitespaces and comments to the end of the line.
        if !self.cache(1) {
            return false;
        }
        while is_blank(self.buf(), self.buffer_pos) {
            self.skip();
            if !self.cache(1) {
                return false;
            }
        }
        if self.b(0) == b'#' {
            if !self.scan_line_comment(start_mark) {
                return false;
            }
            while !is_breakz(self.buf(), self.buffer_pos) {
                self.skip();
                if !self.cache(1) {
                    return false;
                }
            }
        }
        if !is_breakz(self.buf(), self.buffer_pos) {
            self.set_scanner_error(
                "while scanning a block scalar",
                start_mark,
                "did not find expected comment or line break",
            );
            return false;
        }
        if is_break(self.buf(), self.buffer_pos) {
            if !self.cache(2) {
                return false;
            }
            self.skip_line();
        }
        let mut end_mark = self.mark;
        // Set the indentation level if it was specified.
        let mut indent: i64 = 0;
        if increment > 0 {
            indent = if self.indent >= 0 {
                self.indent + increment
            } else {
                increment
            };
        }
        let mut s = Vec::new();
        let mut leading_break = Vec::new();
        let mut trailing_breaks = Vec::new();
        if !self.scan_block_scalar_breaks(
            &mut indent,
            &mut trailing_breaks,
            start_mark,
            &mut end_mark,
        ) {
            return false;
        }
        if !self.cache(1) {
            return false;
        }
        let mut leading_blank = false;
        while self.mark.column as i64 == indent && !is_z(self.buf(), self.buffer_pos) {
            // We are at the beginning of a non-empty line.
            let trailing_blank = is_blank(self.buf(), self.buffer_pos);
            // Check if we need to fold the leading line break.
            if !literal
                && !leading_blank
                && !trailing_blank
                && !leading_break.is_empty()
                && leading_break[0] == b'\n'
            {
                // Do we need to join the lines by space?
                if trailing_breaks.is_empty() {
                    s.push(b' ');
                }
            } else {
                s.extend_from_slice(&leading_break);
            }
            leading_break.clear();
            s.extend_from_slice(&trailing_breaks);
            trailing_breaks.clear();
            leading_blank = is_blank(self.buf(), self.buffer_pos);
            while !is_breakz(self.buf(), self.buffer_pos) {
                self.read(&mut s);
                if !self.cache(1) {
                    return false;
                }
            }
            if !self.cache(2) {
                return false;
            }
            self.read_line(&mut leading_break);
            if !self.scan_block_scalar_breaks(
                &mut indent,
                &mut trailing_breaks,
                start_mark,
                &mut end_mark,
            ) {
                return false;
            }
        }
        // Chomp the tail.
        if chomping != -1 {
            s.extend_from_slice(&leading_break);
        }
        if chomping == 1 {
            s.extend_from_slice(&trailing_breaks);
        }
        *token = Token {
            typ: TokenType::Scalar,
            start_mark,
            end_mark,
            value: s,
            style: if literal {
                ScalarStyle::Literal
            } else {
                ScalarStyle::Folded
            },
            ..Token::default()
        };
        true
    }

    fn scan_block_scalar_breaks(
        &mut self,
        indent: &mut i64,
        breaks: &mut Vec<u8>,
        start_mark: Mark,
        end_mark: &mut Mark,
    ) -> bool {
        *end_mark = self.mark;
        let mut max_indent: i64 = 0;
        loop {
            if !self.cache(1) {
                return false;
            }
            while (*indent == 0 || (self.mark.column as i64) < *indent)
                && is_space(self.buf(), self.buffer_pos)
            {
                self.skip();
                if !self.cache(1) {
                    return false;
                }
            }
            if self.mark.column as i64 > max_indent {
                max_indent = self.mark.column as i64;
            }
            if (*indent == 0 || (self.mark.column as i64) < *indent)
                && is_tab(self.buf(), self.buffer_pos)
            {
                return self.set_scanner_error(
                    "while scanning a block scalar",
                    start_mark,
                    "found a tab character where an indentation space is expected",
                );
            }
            if !is_break(self.buf(), self.buffer_pos) {
                break;
            }
            if !self.cache(2) {
                return false;
            }
            self.read_line(breaks);
            *end_mark = self.mark;
        }
        if *indent == 0 {
            *indent = max_indent;
            if *indent < self.indent + 1 {
                *indent = self.indent + 1;
            }
            if *indent < 1 {
                *indent = 1;
            }
        }
        true
    }

    fn scan_flow_scalar(&mut self, token: &mut Token, single: bool) -> bool {
        let start_mark = self.mark;
        self.skip();
        let mut s = Vec::new();
        let mut leading_break = Vec::new();
        let mut trailing_breaks = Vec::new();
        let mut whitespaces = Vec::new();
        loop {
            if !self.cache(4) {
                return false;
            }
            let (c0, c1, c2) = (self.b(0), self.b(1), self.b(2));
            if self.mark.column == 0
                && ((c0 == b'-' && c1 == b'-' && c2 == b'-')
                    || (c0 == b'.' && c1 == b'.' && c2 == b'.'))
                && is_blankz(self.buf(), self.buffer_pos + 3)
            {
                self.set_scanner_error(
                    "while scanning a quoted scalar",
                    start_mark,
                    "found unexpected document indicator",
                );
                return false;
            }
            if is_z(self.buf(), self.buffer_pos) {
                self.set_scanner_error(
                    "while scanning a quoted scalar",
                    start_mark,
                    "found unexpected end of stream",
                );
                return false;
            }
            // Consume non-blank characters.
            let mut leading_blanks = false;
            while !is_blankz(self.buf(), self.buffer_pos) {
                let c = self.b(0);
                if single && c == b'\'' && self.b(1) == b'\'' {
                    // Is is an escaped single quote.
                    s.push(b'\'');
                    self.skip();
                    self.skip();
                } else if single && c == b'\'' {
                    // It is a right single quote.
                    break;
                } else if !single && c == b'"' {
                    // It is a right double quote.
                    break;
                } else if !single && c == b'\\' && is_break(self.buf(), self.buffer_pos + 1) {
                    // It is an escaped line break.
                    if !self.cache(3) {
                        return false;
                    }
                    self.skip();
                    self.skip_line();
                    leading_blanks = true;
                    break;
                } else if !single && c == b'\\' {
                    // It is an escape sequence.
                    let mut code_length = 0;
                    match self.b(1) {
                        b'0' => s.push(0),
                        b'a' => s.push(0x07),
                        b'b' => s.push(0x08),
                        b't' | b'\t' => s.push(0x09),
                        b'n' => s.push(0x0a),
                        b'v' => s.push(0x0b),
                        b'f' => s.push(0x0c),
                        b'r' => s.push(0x0d),
                        b'e' => s.push(0x1b),
                        b' ' => s.push(0x20),
                        b'"' => s.push(b'"'),
                        b'\'' => s.push(b'\''),
                        b'\\' => s.push(b'\\'),
                        b'N' => s.extend_from_slice(&[0xc2, 0x85]),
                        b'_' => s.extend_from_slice(&[0xc2, 0xa0]),
                        b'L' => s.extend_from_slice(&[0xe2, 0x80, 0xa8]),
                        b'P' => s.extend_from_slice(&[0xe2, 0x80, 0xa9]),
                        b'x' => code_length = 2,
                        b'u' => code_length = 4,
                        b'U' => code_length = 8,
                        _ => {
                            self.set_scanner_error(
                                "while parsing a quoted scalar",
                                start_mark,
                                "found unknown escape character",
                            );
                            return false;
                        }
                    }
                    self.skip();
                    self.skip();
                    // Consume an arbitrary escape code.
                    if code_length > 0 {
                        let mut value: i64 = 0;
                        if !self.cache(code_length) {
                            return false;
                        }
                        for k in 0..code_length {
                            if !is_hex(self.buf(), self.buffer_pos + k) {
                                self.set_scanner_error(
                                    "while parsing a quoted scalar",
                                    start_mark,
                                    "did not find expected hexdecimal number",
                                );
                                return false;
                            }
                            value = (value << 4) + as_hex(self.buf(), self.buffer_pos + k) as i64;
                        }
                        // Check the value and write the character.
                        if (0xd800..=0xdfff).contains(&value) || value > 0x10ffff {
                            self.set_scanner_error(
                                "while parsing a quoted scalar",
                                start_mark,
                                "found invalid Unicode character escape code",
                            );
                            return false;
                        }
                        if value <= 0x7f {
                            s.push(value as u8);
                        } else if value <= 0x7ff {
                            s.push((0xc0 + (value >> 6)) as u8);
                            s.push((0x80 + (value & 0x3f)) as u8);
                        } else if value <= 0xffff {
                            s.push((0xe0 + (value >> 12)) as u8);
                            s.push((0x80 + ((value >> 6) & 0x3f)) as u8);
                            s.push((0x80 + (value & 0x3f)) as u8);
                        } else {
                            s.push((0xf0 + (value >> 18)) as u8);
                            s.push((0x80 + ((value >> 12) & 0x3f)) as u8);
                            s.push((0x80 + ((value >> 6) & 0x3f)) as u8);
                            s.push((0x80 + (value & 0x3f)) as u8);
                        }
                        // Advance the pointer.
                        for _ in 0..code_length {
                            self.skip();
                        }
                    }
                } else {
                    // It is a non-escaped non-blank character.
                    self.read(&mut s);
                }
                if !self.cache(2) {
                    return false;
                }
            }
            if !self.cache(1) {
                return false;
            }
            // Check if we are at the end of the scalar.
            if single {
                if self.b(0) == b'\'' {
                    break;
                }
            } else if self.b(0) == b'"' {
                break;
            }
            // Consume blank characters.
            while is_blank(self.buf(), self.buffer_pos) || is_break(self.buf(), self.buffer_pos) {
                if is_blank(self.buf(), self.buffer_pos) {
                    // Consume a space or a tab character.
                    if !leading_blanks {
                        self.read(&mut whitespaces);
                    } else {
                        self.skip();
                    }
                } else {
                    if !self.cache(2) {
                        return false;
                    }
                    // Check if it is a first line break.
                    if !leading_blanks {
                        whitespaces.clear();
                        self.read_line(&mut leading_break);
                        leading_blanks = true;
                    } else {
                        self.read_line(&mut trailing_breaks);
                    }
                }
                if !self.cache(1) {
                    return false;
                }
            }
            // Join the whitespaces or fold line breaks.
            if leading_blanks {
                // Do we need to fold line breaks?
                if !leading_break.is_empty() && leading_break[0] == b'\n' {
                    if trailing_breaks.is_empty() {
                        s.push(b' ');
                    } else {
                        s.extend_from_slice(&trailing_breaks);
                    }
                } else {
                    s.extend_from_slice(&leading_break);
                    s.extend_from_slice(&trailing_breaks);
                }
                trailing_breaks.clear();
                leading_break.clear();
            } else {
                s.extend_from_slice(&whitespaces);
                whitespaces.clear();
            }
        }
        // Eat the right quote.
        self.skip();
        *token = Token {
            typ: TokenType::Scalar,
            start_mark,
            end_mark: self.mark,
            value: s,
            style: if single {
                ScalarStyle::SingleQuoted
            } else {
                ScalarStyle::DoubleQuoted
            },
            ..Token::default()
        };
        true
    }

    fn scan_plain_scalar(&mut self, token: &mut Token) -> bool {
        let mut s = Vec::new();
        let mut leading_break = Vec::new();
        let mut trailing_breaks = Vec::new();
        let mut whitespaces = Vec::new();
        let mut leading_blanks = false;
        let indent = self.indent + 1;
        let start_mark = self.mark;
        let mut end_mark = self.mark;
        // Consume the content of the plain scalar.
        loop {
            // Check for a document indicator.
            if !self.cache(4) {
                return false;
            }
            let (c0, c1, c2) = (self.b(0), self.b(1), self.b(2));
            if self.mark.column == 0
                && ((c0 == b'-' && c1 == b'-' && c2 == b'-')
                    || (c0 == b'.' && c1 == b'.' && c2 == b'.'))
                && is_blankz(self.buf(), self.buffer_pos + 3)
            {
                break;
            }
            // Check for a comment.
            if c0 == b'#' {
                break;
            }
            // Consume non-blank characters.
            while !is_blankz(self.buf(), self.buffer_pos) {
                let c = self.b(0);
                // Check for indicators that may end a plain scalar.
                if (c == b':' && is_blankz(self.buf(), self.buffer_pos + 1))
                    || (self.flow_level > 0 && matches!(c, b',' | b'?' | b'[' | b']' | b'{' | b'}'))
                {
                    break;
                }
                // Check if we need to join whitespaces and breaks.
                if leading_blanks || !whitespaces.is_empty() {
                    if leading_blanks {
                        // Do we need to fold line breaks?
                        if at(&leading_break, 0) == b'\n' {
                            if trailing_breaks.is_empty() {
                                s.push(b' ');
                            } else {
                                s.extend_from_slice(&trailing_breaks);
                            }
                        } else {
                            s.extend_from_slice(&leading_break);
                            s.extend_from_slice(&trailing_breaks);
                        }
                        trailing_breaks.clear();
                        leading_break.clear();
                        leading_blanks = false;
                    } else {
                        s.extend_from_slice(&whitespaces);
                        whitespaces.clear();
                    }
                }
                // Copy the character.
                self.read(&mut s);
                end_mark = self.mark;
                if !self.cache(2) {
                    return false;
                }
            }
            // Is it the end?
            if !(is_blank(self.buf(), self.buffer_pos) || is_break(self.buf(), self.buffer_pos)) {
                break;
            }
            // Consume blank characters.
            if !self.cache(1) {
                return false;
            }
            while is_blank(self.buf(), self.buffer_pos) || is_break(self.buf(), self.buffer_pos) {
                if is_blank(self.buf(), self.buffer_pos) {
                    // Check for tab characters that abuse indentation.
                    if leading_blanks
                        && (self.mark.column as i64) < indent
                        && is_tab(self.buf(), self.buffer_pos)
                    {
                        self.set_scanner_error(
                            "while scanning a plain scalar",
                            start_mark,
                            "found a tab character that violates indentation",
                        );
                        return false;
                    }
                    // Consume a space or a tab character.
                    if !leading_blanks {
                        self.read(&mut whitespaces);
                    } else {
                        self.skip();
                    }
                } else {
                    if !self.cache(2) {
                        return false;
                    }
                    // Check if it is a first line break.
                    if !leading_blanks {
                        whitespaces.clear();
                        self.read_line(&mut leading_break);
                        leading_blanks = true;
                    } else {
                        self.read_line(&mut trailing_breaks);
                    }
                }
                if !self.cache(1) {
                    return false;
                }
            }
            // Check indentation level.
            if self.flow_level == 0 && (self.mark.column as i64) < indent {
                break;
            }
        }
        *token = Token {
            typ: TokenType::Scalar,
            start_mark,
            end_mark,
            value: s,
            style: ScalarStyle::Plain,
            ..Token::default()
        };
        // Note that we change the 'simple_key_allowed' flag.
        if leading_blanks {
            self.simple_key_allowed = true;
        }
        true
    }

    fn scan_line_comment(&mut self, token_mark: Mark) -> bool {
        if self.newlines > 0 {
            return true;
        }
        let mut start_mark = Mark::default();
        let mut text = Vec::new();
        let mut peek = 0;
        while peek < 512 {
            if self.unread < peek + 1 && !self.update_buffer(peek + 1) {
                break;
            }
            if is_blank(self.buf(), self.buffer_pos + peek) {
                peek += 1;
                continue;
            }
            if self.b(peek) == b'#' {
                let seen = self.mark.index.wrapping_add(peek);
                loop {
                    if !self.cache(1) {
                        return false;
                    }
                    if is_breakz(self.buf(), self.buffer_pos) {
                        if self.mark.index >= seen {
                            break;
                        }
                        if !self.cache(2) {
                            return false;
                        }
                        self.skip_line();
                    } else if self.mark.index >= seen {
                        if text.is_empty() {
                            start_mark = self.mark;
                        }
                        self.read(&mut text);
                    } else {
                        self.skip();
                    }
                }
            }
            break;
        }
        if !text.is_empty() {
            self.comments.push(super::scanner::Comment {
                token_mark,
                start_mark,
                line: text,
                ..Comment::default()
            });
        }
        true
    }

    fn scan_comments(&mut self, scan_mark: Mark) -> bool {
        let mut scan_mark = scan_mark;
        let mut token = self.tokens[self.tokens.len() - 1].clone();
        if token.typ == TokenType::FlowEntry && self.tokens.len() > 1 {
            // [Go] The next token is the one that follows the flow entry.
            token = self.tokens[self.tokens.len() - 2].clone();
        }
        let mut token_mark = token.start_mark;
        let mut start_mark = Mark::default();
        let mut next_indent = self.indent.max(0);
        let mut recent_empty = false;
        let mut first_empty = self.newlines <= 1;
        let mut line = self.mark.line;
        let mut column = self.mark.column as i64;
        let mut text: Vec<u8> = Vec::new();
        // The foot line is the place where a comment must start to
        // still be considered as a foot of the prior content.
        // If there's some content in the currently parsed line, then
        // the foot is the line below it.
        let mut foot_line: i64 = -1;
        if scan_mark.line > 0 {
            foot_line = self.mark.line as i64 - self.newlines as i64 + 1;
            if self.newlines == 0 && self.mark.column > 1 {
                foot_line += 1;
            }
        }
        let mut peek: usize = 0;
        while peek < 512 {
            if self.unread < peek + 1 && !self.update_buffer(peek + 1) {
                break;
            }
            column += 1;
            if is_blank(self.buf(), self.buffer_pos + peek) {
                peek += 1;
                continue;
            }
            let c = self.b(peek);
            let close_flow = self.flow_level > 0 && (c == b']' || c == b'}');
            if close_flow || is_breakz(self.buf(), self.buffer_pos + peek) {
                // Got line break or terminator.
                if close_flow || !recent_empty {
                    if close_flow
                        || (first_empty
                            && ((start_mark.line as i64 == foot_line
                                && token.typ != TokenType::Value)
                                || (start_mark.column as i64) - 1 < next_indent))
                    {
                        // This is the first empty line and there were no empty lines before,
                        // so this initial part of the comment is a foot of the prior token
                        // instead of being a head for the following one. Split it up.
                        // Alternatively, this might also be the last comment inside a flow
                        // scope, so it must be a footer.
                        if !text.is_empty() {
                            if (start_mark.column as i64) - 1 < next_indent {
                                // If dedented it's unrelated to the prior token.
                                token_mark = start_mark;
                            }
                            let end = Mark {
                                index: self.mark.index.wrapping_add(peek),
                                line,
                                column: column as usize,
                            };
                            self.comments.push(Comment {
                                scan_mark,
                                token_mark,
                                start_mark,
                                end_mark: end,
                                foot: std::mem::take(&mut text),
                                ..Comment::default()
                            });
                            scan_mark = end;
                            token_mark = scan_mark;
                        }
                    } else if !text.is_empty() && self.b(peek) != 0 {
                        text.push(b'\n');
                    }
                }
                if !is_break(self.buf(), self.buffer_pos + peek) {
                    break;
                }
                first_empty = false;
                recent_empty = true;
                column = 0;
                line += 1;
                peek += 1;
                continue;
            }
            if !text.is_empty()
                && (close_flow || (column - 1 < next_indent && column != start_mark.column as i64))
            {
                // The comment at the different indentation is a foot of the
                // preceding data rather than a head of the upcoming one.
                let end = Mark {
                    index: self.mark.index.wrapping_add(peek),
                    line,
                    column: column as usize,
                };
                self.comments.push(Comment {
                    scan_mark,
                    token_mark,
                    start_mark,
                    end_mark: end,
                    foot: std::mem::take(&mut text),
                    ..Comment::default()
                });
                scan_mark = end;
                token_mark = scan_mark;
            }
            if self.b(peek) != b'#' {
                break;
            }
            if text.is_empty() {
                start_mark = Mark {
                    index: self.mark.index.wrapping_add(peek),
                    line,
                    column: column as usize,
                };
            } else {
                text.push(b'\n');
            }
            recent_empty = false;
            // Consume until after the consumed comment line.
            let seen = self.mark.index.wrapping_add(peek);
            loop {
                if !self.cache(1) {
                    return false;
                }
                if is_breakz(self.buf(), self.buffer_pos) {
                    if self.mark.index >= seen {
                        break;
                    }
                    if !self.cache(2) {
                        return false;
                    }
                    self.skip_line();
                } else if self.mark.index >= seen {
                    self.read(&mut text);
                } else {
                    self.skip();
                }
            }
            column = 0;
            line = self.mark.line;
            next_indent = self.indent.max(0);
            // Go sets peek to 0 here, then its loop adds one.
            peek = 1;
        }
        if !text.is_empty() {
            self.comments.push(Comment {
                scan_mark,
                token_mark: start_mark,
                start_mark,
                end_mark: Mark {
                    index: self.mark.index.wrapping_add(peek).wrapping_sub(1),
                    line,
                    column: column as usize,
                },
                head: text,
                ..Comment::default()
            });
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::grow_cap;

    #[test]
    fn token_queue_grows_as_go_slices_do() {
        // What Go 1.27 prints appending yaml_token_t values one at a time.
        let mut cap = 0;
        let mut caps = Vec::new();
        while cap < 5000 {
            cap = grow_cap(cap, cap + 1);
            caps.push(cap);
        }
        assert_eq!(
            caps,
            [
                1, 2, 4, 8, 18, 37, 75, 151, 341, 625, 1024, 1479, 2048, 2787, 3697, 4835, 6257
            ]
        );
    }
}
