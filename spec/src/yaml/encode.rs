//! go-yaml v3's encoder (encode.go) without reflection: the scalar
//! writers (stringv, intv, ...), the mapping, sequence, and document
//! wrappers marshal uses, and node(), which writes a node tree. Callers
//! that marshal Go values (spec export) drive these the way encode.go's
//! marshal does.

#![allow(clippy::too_many_arguments)]

use super::emitter::{self, Emitter};
use super::resolve::{encode_base64, long_tag, resolve, short_tag};
use super::types::{
    BINARY_TAG, DOUBLE_QUOTED_STYLE, Encoding, FLOW_STYLE, FOLDED_STYLE, Kind, LITERAL_STYLE,
    MAP_TAG, MappingStyle, NodeId, SEQ_TAG, SINGLE_QUOTED_STYLE, STR_TAG, ScalarStyle,
    SequenceStyle, TAGGED_STYLE, Tree,
};

/// go-yaml's encoder. Errors are the texts go-yaml's failf gives.
#[derive(Debug)]
pub struct Encoder {
    pub emitter: Emitter,
    /// The next mapping or sequence is written in flow style.
    pub flow: bool,
    /// Indentation; 0 means go-yaml's default of 4.
    pub indent: usize,
    done_init: bool,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

fn fail<T>(msg: String) -> Result<T, String> {
    Err(format!("yaml: {msg}"))
}

impl Encoder {
    /// newEncoder: output to a string, as yaml.Marshal uses.
    pub fn new() -> Self {
        let mut emitter = Emitter::new();
        emitter.unicode = true;
        Encoder {
            emitter,
            flow: false,
            indent: 0,
            done_init: false,
        }
    }

    /// newEncoderWithWriter: output to a writer, as yaml.NewEncoder uses.
    /// What the writer would have received is in out().
    pub fn new_with_writer() -> Self {
        Self::new()
    }

    /// What the emitter wrote out so far.
    pub fn out(&self) -> &[u8] {
        &self.emitter.output
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.emitter.output
    }

    fn emit(&mut self, ev: super::types::Event) -> Result<(), String> {
        let ok = self.emitter.emit(ev);
        self.must(ok)
    }

    fn must(&self, ok: bool) -> Result<(), String> {
        if !ok {
            let msg = if self.emitter.problem.is_empty() {
                "unknown problem generating YAML content".to_string()
            } else {
                self.emitter.problem.clone()
            };
            return fail(msg);
        }
        Ok(())
    }

    /// encoder.init: starts the stream once.
    pub fn init(&mut self) -> Result<(), String> {
        if self.done_init {
            return Ok(());
        }
        if self.indent == 0 {
            self.indent = 4;
        }
        self.emitter.best_indent = self.indent as isize;
        self.emit(emitter::stream_start_event(Encoding::Utf8))?;
        self.done_init = true;
        Ok(())
    }

    /// encoder.finish: ends the stream (Encoder.Close, yaml.Marshal).
    pub fn finish(&mut self) -> Result<(), String> {
        self.emitter.open_ended = false;
        self.emit(emitter::stream_end_event())
    }

    /// The document start marshalDoc writes around a value that is not a
    /// document node; it starts the stream first.
    pub fn document_start(&mut self) -> Result<(), String> {
        self.init()?;
        self.emit(emitter::document_start_event(None, Vec::new(), true))
    }

    /// The document end marshalDoc writes after the value.
    pub fn document_end(&mut self) -> Result<(), String> {
        self.emit(emitter::document_end_event(true))
    }

    /// marshalDoc for a *Node: a document node is written as it is, any
    /// other node inside an implicit document.
    pub fn marshal_doc_node(&mut self, tree: &Tree, id: NodeId) -> Result<(), String> {
        self.init()?;
        if tree.get(id).kind == Kind::Document {
            self.node(tree, id, "")
        } else {
            self.emit(emitter::document_start_event(None, Vec::new(), true))?;
            self.node(tree, id, "")?;
            self.emit(emitter::document_end_event(true))
        }
    }

    /// The start of mappingv: block style unless flow was asked for.
    pub fn mapping_start(&mut self, tag: &str) -> Result<(), String> {
        let implicit = tag.is_empty();
        let mut style = MappingStyle::Block;
        if self.flow {
            self.flow = false;
            style = MappingStyle::Flow;
        }
        self.emit(emitter::mapping_start_event(
            b"",
            tag.as_bytes(),
            implicit,
            style,
        ))
    }

    /// The end of mappingv.
    pub fn mapping_end(&mut self) -> Result<(), String> {
        self.emit(emitter::mapping_end_event())
    }

    /// The start of slicev.
    pub fn sequence_start(&mut self, tag: &str) -> Result<(), String> {
        let implicit = tag.is_empty();
        let mut style = SequenceStyle::Block;
        if self.flow {
            self.flow = false;
            style = SequenceStyle::Flow;
        }
        self.emit(emitter::sequence_start_event(
            b"",
            tag.as_bytes(),
            implicit,
            style,
        ))
    }

    /// The end of slicev.
    pub fn sequence_end(&mut self) -> Result<(), String> {
        self.emit(emitter::sequence_end_event())
    }

    /// stringv for a valid UTF-8 string.
    pub fn stringv(&mut self, tag: &str, s: &str) -> Result<(), String> {
        self.stringv_bytes(tag, s.as_bytes())
    }

    /// stringv for any bytes: invalid UTF-8 becomes !!binary.
    pub fn stringv_bytes(&mut self, tag: &str, s: &[u8]) -> Result<(), String> {
        let tag = short_tag(tag);
        let mut tag = tag.as_str().to_string();
        let mut can_use_plain = true;
        let value: String;
        match std::str::from_utf8(s) {
            Err(_) => {
                if tag == BINARY_TAG {
                    return fail("explicitly tagged !!binary data must be base64-encoded".into());
                }
                if !tag.is_empty() {
                    return fail(format!(
                        "cannot marshal invalid UTF-8 data as {}",
                        short_tag(&tag)
                    ));
                }
                tag = BINARY_TAG.to_string();
                value = encode_base64(s);
            }
            Ok(v) => {
                value = v.to_string();
                if tag.is_empty() {
                    let (rtag, _) = resolve("", v)?;
                    can_use_plain = rtag == STR_TAG && !(is_base60_float(v) || is_old_bool(v));
                }
            }
        }
        let style = if value.contains('\n') {
            if self.flow {
                ScalarStyle::DoubleQuoted
            } else {
                ScalarStyle::Literal
            }
        } else if can_use_plain {
            ScalarStyle::Plain
        } else {
            ScalarStyle::DoubleQuoted
        };
        self.emit_scalar(&value, "", &tag, style, b"", b"", b"", b"")
    }

    /// boolv.
    pub fn boolv(&mut self, tag: &str, v: bool) -> Result<(), String> {
        let s = if v { "true" } else { "false" };
        self.emit_scalar(
            s,
            "",
            &short_tag(tag),
            ScalarStyle::Plain,
            b"",
            b"",
            b"",
            b"",
        )
    }

    /// intv.
    pub fn intv(&mut self, tag: &str, v: i64) -> Result<(), String> {
        self.emit_scalar(
            &v.to_string(),
            "",
            &short_tag(tag),
            ScalarStyle::Plain,
            b"",
            b"",
            b"",
            b"",
        )
    }

    /// uintv.
    pub fn uintv(&mut self, tag: &str, v: u64) -> Result<(), String> {
        self.emit_scalar(
            &v.to_string(),
            "",
            &short_tag(tag),
            ScalarStyle::Plain,
            b"",
            b"",
            b"",
            b"",
        )
    }

    /// floatv: strconv.FormatFloat(v, 'g', -1, 64), infinities and NaN as
    /// YAML writes them.
    pub fn floatv(&mut self, tag: &str, v: f64) -> Result<(), String> {
        let s = if v.is_nan() {
            ".nan".to_string()
        } else if v == f64::INFINITY {
            ".inf".to_string()
        } else if v == f64::NEG_INFINITY {
            "-.inf".to_string()
        } else {
            format_float_g(v)
        };
        self.emit_scalar(
            &s,
            "",
            &short_tag(tag),
            ScalarStyle::Plain,
            b"",
            b"",
            b"",
            b"",
        )
    }

    /// nilv.
    pub fn nilv(&mut self) -> Result<(), String> {
        self.emit_scalar("null", "", "", ScalarStyle::Plain, b"", b"", b"", b"")
    }

    /// emitScalar.
    pub fn emit_scalar(
        &mut self,
        value: &str,
        anchor: &str,
        tag: &str,
        style: ScalarStyle,
        head: &[u8],
        line: &[u8],
        foot: &[u8],
        tail: &[u8],
    ) -> Result<(), String> {
        let implicit = tag.is_empty();
        let tag = if implicit {
            String::new()
        } else {
            long_tag(tag)
        };
        let mut ev = emitter::scalar_event(
            anchor.as_bytes(),
            tag.as_bytes(),
            value.as_bytes(),
            implicit,
            implicit,
            style,
        );
        ev.head_comment = head.to_vec();
        ev.line_comment = line.to_vec();
        ev.foot_comment = foot.to_vec();
        ev.tail_comment = tail.to_vec();
        self.emit(ev)
    }

    /// encoder.node: writes a node tree.
    pub fn node(&mut self, tree: &Tree, id: NodeId, tail: &str) -> Result<(), String> {
        self.node_with(tree, id, tail, false)
    }

    /// node, with the node's foot comment left out when without_foot (the
    /// copy of a key encode.go makes).
    fn node_with(
        &mut self,
        tree: &Tree,
        id: NodeId,
        tail: &str,
        without_foot: bool,
    ) -> Result<(), String> {
        let mut owned;
        let mut node = tree.get(id);
        if without_foot {
            owned = node.clone();
            owned.foot_comment.clear();
            node = &owned;
        }
        if node.kind == Kind::Zero && node.is_zero() {
            return self.nilv();
        }
        let mut tag = node.tag.clone();
        let stag = short_tag(&tag);
        let mut force_quoting = false;
        if !tag.is_empty() && node.style & TAGGED_STYLE == 0 {
            if node.kind == Kind::Scalar {
                if stag == STR_TAG
                    && node.style
                        & (SINGLE_QUOTED_STYLE | DOUBLE_QUOTED_STYLE | LITERAL_STYLE | FOLDED_STYLE)
                        != 0
                {
                    tag.clear();
                } else {
                    let (rtag, _) = resolve("", &node.value)?;
                    if rtag == stag {
                        tag.clear();
                    } else if stag == STR_TAG {
                        tag.clear();
                        force_quoting = true;
                    }
                }
            } else {
                let rtag = match node.kind {
                    Kind::Mapping => MAP_TAG,
                    Kind::Sequence => SEQ_TAG,
                    _ => "",
                };
                if rtag == stag {
                    tag.clear();
                }
            }
        }

        match node.kind {
            Kind::Document => {
                let mut ev = emitter::document_start_event(None, Vec::new(), true);
                ev.head_comment = node.head_comment.as_bytes().to_vec();
                self.emit(ev)?;
                for &c in &node.content {
                    self.node(tree, c, "")?;
                }
                let mut ev = emitter::document_end_event(true);
                ev.foot_comment = node.foot_comment.as_bytes().to_vec();
                self.emit(ev)
            }
            Kind::Sequence => {
                let style = if node.style & FLOW_STYLE != 0 {
                    SequenceStyle::Flow
                } else {
                    SequenceStyle::Block
                };
                let mut ev = emitter::sequence_start_event(
                    node.anchor.as_bytes(),
                    long_tag(&tag).as_bytes(),
                    tag.is_empty(),
                    style,
                );
                ev.head_comment = node.head_comment.as_bytes().to_vec();
                self.emit(ev)?;
                for &c in &node.content {
                    self.node(tree, c, "")?;
                }
                let mut ev = emitter::sequence_end_event();
                ev.line_comment = node.line_comment.as_bytes().to_vec();
                ev.foot_comment = node.foot_comment.as_bytes().to_vec();
                self.emit(ev)
            }
            Kind::Mapping => {
                let style = if node.style & FLOW_STYLE != 0 {
                    MappingStyle::Flow
                } else {
                    MappingStyle::Block
                };
                let mut ev = emitter::mapping_start_event(
                    node.anchor.as_bytes(),
                    long_tag(&tag).as_bytes(),
                    tag.is_empty(),
                    style,
                );
                ev.tail_comment = tail.as_bytes().to_vec();
                ev.head_comment = node.head_comment.as_bytes().to_vec();
                self.emit(ev)?;
                // A key's foot comment is written as the tail of the next
                // key or of the mapping's end.
                let mut tail = String::new();
                let mut i = 0;
                while i + 1 < node.content.len() {
                    let k = node.content[i];
                    let foot = tree.get(k).foot_comment.clone();
                    self.node_with(tree, k, &tail, !foot.is_empty())?;
                    tail = foot;
                    self.node(tree, node.content[i + 1], "")?;
                    i += 2;
                }
                let mut ev = emitter::mapping_end_event();
                ev.tail_comment = tail.as_bytes().to_vec();
                ev.line_comment = node.line_comment.as_bytes().to_vec();
                ev.foot_comment = node.foot_comment.as_bytes().to_vec();
                self.emit(ev)
            }
            Kind::Alias => {
                let mut ev = emitter::alias_event(node.value.as_bytes());
                ev.head_comment = node.head_comment.as_bytes().to_vec();
                ev.line_comment = node.line_comment.as_bytes().to_vec();
                ev.foot_comment = node.foot_comment.as_bytes().to_vec();
                self.emit(ev)
            }
            Kind::Scalar => {
                // Node values are always valid UTF-8 here (Rust strings),
                // so go-yaml's !!binary fallback for invalid UTF-8 never
                // applies.
                let value = node.value.clone();
                let style = if node.style & DOUBLE_QUOTED_STYLE != 0 {
                    ScalarStyle::DoubleQuoted
                } else if node.style & SINGLE_QUOTED_STYLE != 0 {
                    ScalarStyle::SingleQuoted
                } else if node.style & LITERAL_STYLE != 0 {
                    ScalarStyle::Literal
                } else if node.style & FOLDED_STYLE != 0 {
                    ScalarStyle::Folded
                } else if value.contains('\n') {
                    ScalarStyle::Literal
                } else if force_quoting {
                    ScalarStyle::DoubleQuoted
                } else {
                    ScalarStyle::Plain
                };
                self.emit_scalar(
                    &value,
                    &node.anchor,
                    &tag,
                    style,
                    node.head_comment.as_bytes(),
                    node.line_comment.as_bytes(),
                    node.foot_comment.as_bytes(),
                    tail.as_bytes(),
                )
            }
            Kind::Zero => fail(format!(
                "cannot encode node with unknown kind {}",
                node.kind.number()
            )),
        }
    }
}

/// yaml.NewEncoder(&buf) [SetIndent(n)] Encode(node), without Close: the
/// bytes the buffer holds afterwards.
pub fn encode_node(tree: &Tree, id: NodeId, indent: Option<usize>) -> Result<Vec<u8>, String> {
    let mut e = Encoder::new_with_writer();
    if let Some(n) = indent {
        e.indent = n;
    }
    e.marshal_doc_node(tree, id)?;
    Ok(e.into_bytes())
}

/// isBase60Float: values YAML 1.1 reads as base 60 floats are quoted.
pub fn is_base60_float(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() {
        return false;
    }
    let c = b[0];
    if !(c == b'+' || c == b'-' || c.is_ascii_digit()) || !b.contains(&b':') {
        return false;
    }
    // ^[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?$
    let mut i = 0;
    if b[i] == b'+' || b[i] == b'-' {
        i += 1;
    }
    if i >= b.len() || !b[i].is_ascii_digit() {
        return false;
    }
    i += 1;
    while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'_') {
        i += 1;
    }
    let mut groups = 0;
    while i < b.len() && b[i] == b':' {
        let start = i + 1;
        let mut j = start;
        while j < b.len() && b[j].is_ascii_digit() && j - start < 2 {
            j += 1;
        }
        // [0-5]?[0-9]: one digit, or two with the first at most 5.
        let n = j - start;
        let ok = match n {
            1 => true,
            2 => b[start] <= b'5',
            _ => false,
        };
        if !ok {
            // Two digits with a first above 5: only the last can match,
            // which leaves the first unmatched, so it fails.
            return false;
        }
        i = j;
        groups += 1;
    }
    if groups == 0 {
        return false;
    }
    if i < b.len() && b[i] == b'.' {
        i += 1;
        while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'_') {
            i += 1;
        }
    }
    i == b.len()
}

/// isOldBool: YAML 1.1 booleans are quoted.
pub fn is_old_bool(s: &str) -> bool {
    matches!(
        s,
        "y" | "Y"
            | "yes"
            | "Yes"
            | "YES"
            | "on"
            | "On"
            | "ON"
            | "n"
            | "N"
            | "no"
            | "No"
            | "NO"
            | "off"
            | "Off"
            | "OFF"
    )
}

/// strconv.FormatFloat(v, 'g', -1, 64) for a finite v.
pub fn format_float_g(v: f64) -> String {
    if v == 0.0 {
        return if v.is_sign_negative() {
            "-0".into()
        } else {
            "0".into()
        };
    }
    // The shortest digits that round-trip, as Rust's {:e} gives them.
    let e = format!("{v:e}");
    let (mant, exp) = e.split_once('e').expect("exponent");
    let exp: i32 = exp.parse().expect("exponent number");
    let (neg, mant) = match mant.strip_prefix('-') {
        Some(m) => (true, m),
        None => (false, mant),
    };
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let n = digits.len() as i32;
    // %g with the shortest precision decides with a precision of 6.
    let eprec = 6;
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if exp < -4 || exp >= eprec {
        out.push_str(&digits[..1]);
        if n > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        if exp < 0 {
            out.push('-');
        } else {
            out.push('+');
        }
        let a = exp.unsigned_abs();
        if a < 10 {
            out.push('0');
        }
        out.push_str(&a.to_string());
    } else if exp < 0 {
        out.push_str("0.");
        for _ in 0..(-exp - 1) {
            out.push('0');
        }
        out.push_str(&digits);
    } else if exp + 1 >= n {
        out.push_str(&digits);
        for _ in 0..(exp + 1 - n) {
            out.push('0');
        }
    } else {
        let p = (exp + 1) as usize;
        out.push_str(&digits[..p]);
        out.push('.');
        out.push_str(&digits[p..]);
    }
    out
}
