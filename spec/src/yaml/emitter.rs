//! go-yaml v3's emitter (emitterc.go, writerc.go, and the emitter parts of
//! apic.go, yamlh.go, and yamlprivateh.go), ported function by function so
//! its output is the same byte for byte. The functions keep libyaml's
//! names and their order, and return false with `problem` set on an
//! error, as the Go code does.
#![allow(clippy::needless_bool, clippy::collapsible_match)]

use super::types::{
    Encoding, ErrorType, Event, EventType, MappingStyle, ScalarStyle, SequenceStyle, TagDirective,
    VersionDirective,
};

/// The byte at i, or 0 past the end (where Go would index out of range,
/// which valid UTF-8 input never reaches).
fn at(b: &[u8], i: usize) -> u8 {
    b.get(i).copied().unwrap_or(0)
}

fn is_alpha(b: &[u8], i: usize) -> bool {
    let c = at(b, i);
    c.is_ascii_digit() || c.is_ascii_uppercase() || c.is_ascii_lowercase() || c == b'_' || c == b'-'
}

fn is_ascii(b: &[u8], i: usize) -> bool {
    at(b, i) <= 0x7F
}

fn is_printable(b: &[u8], i: usize) -> bool {
    let (c0, c1, c2) = (at(b, i), at(b, i + 1), at(b, i + 2));
    c0 == 0x0A
        || (0x20..=0x7E).contains(&c0)
        || (c0 == 0xC2 && c1 >= 0xA0)
        || (c0 > 0xC2 && c0 < 0xED)
        || (c0 == 0xED && c1 < 0xA0)
        || c0 == 0xEE
        || (c0 == 0xEF
            && !(c1 == 0xBB && c2 == 0xBF)
            && !(c1 == 0xBF && (c2 == 0xBE || c2 == 0xBF)))
}

/// is_bom looks at the first three bytes whatever i is, as go-yaml does.
fn is_bom(b: &[u8], _i: usize) -> bool {
    at(b, 0) == 0xEF && at(b, 1) == 0xBB && at(b, 2) == 0xBF
}

fn is_space(b: &[u8], i: usize) -> bool {
    at(b, i) == b' '
}

fn is_blank(b: &[u8], i: usize) -> bool {
    let c = at(b, i);
    c == b' ' || c == b'\t'
}

fn is_break(b: &[u8], i: usize) -> bool {
    let (c0, c1, c2) = (at(b, i), at(b, i + 1), at(b, i + 2));
    c0 == b'\r'
        || c0 == b'\n'
        || (c0 == 0xC2 && c1 == 0x85)
        || (c0 == 0xE2 && c1 == 0x80 && c2 == 0xA8)
        || (c0 == 0xE2 && c1 == 0x80 && c2 == 0xA9)
}

fn is_blankz(b: &[u8], i: usize) -> bool {
    let c = at(b, i);
    c == b' ' || c == b'\t' || is_break(b, i) || c == 0
}

fn width(c: u8) -> usize {
    if c & 0x80 == 0x00 {
        1
    } else if c & 0xE0 == 0xC0 {
        2
    } else if c & 0xF0 == 0xE0 {
        3
    } else if c & 0xF8 == 0xF0 {
        4
    } else {
        0
    }
}

/// The number go-yaml stores as an event's style (yaml_style_t). go-yaml
/// compares a mapping's style with the flow sequence style through it, and
/// both flow styles are 2.
fn raw_style(event: &Event) -> i8 {
    use super::types::EventStyle;
    match event.style {
        EventStyle::Any => 0,
        EventStyle::Scalar(s) => match s {
            ScalarStyle::Any => 0,
            ScalarStyle::Plain => 2,
            ScalarStyle::SingleQuoted => 4,
            ScalarStyle::DoubleQuoted => 8,
            ScalarStyle::Literal => 16,
            ScalarStyle::Folded => 32,
        },
        EventStyle::Sequence(s) => match s {
            SequenceStyle::Any => 0,
            SequenceStyle::Block => 1,
            SequenceStyle::Flow => 2,
        },
        EventStyle::Mapping(s) => match s {
            MappingStyle::Any => 0,
            MappingStyle::Block => 1,
            MappingStyle::Flow => 2,
        },
    }
}

/// The line break the emitter writes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Break {
    #[default]
    Any,
    Cr,
    Ln,
    CrLn,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    StreamStart,
    FirstDocumentStart,
    DocumentStart,
    DocumentContent,
    DocumentEnd,
    FlowSequenceFirstItem,
    FlowSequenceTrailItem,
    FlowSequenceItem,
    FlowMappingFirstKey,
    FlowMappingTrailKey,
    FlowMappingKey,
    FlowMappingSimpleValue,
    FlowMappingValue,
    BlockSequenceFirstItem,
    BlockSequenceItem,
    BlockMappingFirstKey,
    BlockMappingKey,
    BlockMappingSimpleValue,
    BlockMappingValue,
    End,
}

/// The emitter (yaml_emitter_t). Output goes to `buffer` and moves to
/// `output` when the emitter flushes, which is what a string or a writer
/// receives in go-yaml.
#[derive(Debug)]
pub struct Emitter {
    pub error: ErrorType,
    pub problem: String,

    buffer: Vec<u8>,
    /// What the emitter flushed: the string output, or what a writer got.
    pub output: Vec<u8>,

    pub encoding: Encoding,
    pub canonical: bool,
    pub best_indent: isize,
    pub best_width: isize,
    pub unicode: bool,
    pub line_break: Break,

    state: State,
    states: Vec<State>,

    events: Vec<Event>,
    events_head: usize,

    indents: Vec<isize>,
    tag_directives: Vec<TagDirective>,
    indent: isize,
    pub compact_sequence_indent: bool,
    flow_level: isize,

    root_context: bool,
    sequence_context: bool,
    mapping_context: bool,
    simple_key_context: bool,

    line: isize,
    column: isize,
    whitespace: bool,
    indention: bool,
    pub open_ended: bool,

    space_above: bool,
    foot_indent: isize,

    anchor_data_anchor: Option<Vec<u8>>,
    anchor_data_alias: bool,

    tag_data_handle: Vec<u8>,
    tag_data_suffix: Vec<u8>,

    scalar_data_value: Vec<u8>,
    scalar_data_multiline: bool,
    scalar_data_flow_plain_allowed: bool,
    scalar_data_block_plain_allowed: bool,
    scalar_data_single_quoted_allowed: bool,
    scalar_data_block_allowed: bool,
    scalar_data_style: ScalarStyle,

    head_comment: Vec<u8>,
    line_comment: Vec<u8>,
    foot_comment: Vec<u8>,
    tail_comment: Vec<u8>,
    key_line_comment: Vec<u8>,
}

impl Default for Emitter {
    fn default() -> Self {
        Self::new()
    }
}

fn default_tag_directives() -> Vec<TagDirective> {
    vec![
        TagDirective {
            handle: b"!".to_vec(),
            prefix: b"!".to_vec(),
        },
        TagDirective {
            handle: b"!!".to_vec(),
            prefix: b"tag:yaml.org,2002:".to_vec(),
        },
    ]
}

impl Emitter {
    /// yaml_emitter_initialize.
    pub fn new() -> Self {
        Emitter {
            error: ErrorType::None,
            problem: String::new(),
            buffer: Vec::new(),
            output: Vec::new(),
            encoding: Encoding::Any,
            canonical: false,
            best_indent: 0,
            best_width: -1,
            unicode: false,
            line_break: Break::Any,
            state: State::StreamStart,
            states: Vec::new(),
            events: Vec::new(),
            events_head: 0,
            indents: Vec::new(),
            tag_directives: Vec::new(),
            indent: 0,
            compact_sequence_indent: false,
            flow_level: 0,
            root_context: false,
            sequence_context: false,
            mapping_context: false,
            simple_key_context: false,
            line: 0,
            column: 0,
            whitespace: false,
            indention: false,
            open_ended: false,
            space_above: false,
            foot_indent: 0,
            anchor_data_anchor: None,
            anchor_data_alias: false,
            tag_data_handle: Vec::new(),
            tag_data_suffix: Vec::new(),
            scalar_data_value: Vec::new(),
            scalar_data_multiline: false,
            scalar_data_flow_plain_allowed: false,
            scalar_data_block_plain_allowed: false,
            scalar_data_single_quoted_allowed: false,
            scalar_data_block_allowed: false,
            scalar_data_style: ScalarStyle::Any,
            head_comment: Vec::new(),
            line_comment: Vec::new(),
            foot_comment: Vec::new(),
            tail_comment: Vec::new(),
            key_line_comment: Vec::new(),
        }
    }

    // writerc.go

    /// yaml_emitter_flush: hands the buffer to the output.
    pub fn flush(&mut self) -> bool {
        if self.buffer.is_empty() {
            return true;
        }
        let b = std::mem::take(&mut self.buffer);
        self.output.extend_from_slice(&b);
        true
    }

    // emitterc.go: writing characters.

    fn put(&mut self, value: u8) -> bool {
        self.buffer.push(value);
        self.column += 1;
        true
    }

    fn put_break(&mut self) -> bool {
        match self.line_break {
            Break::Cr => self.buffer.push(b'\r'),
            Break::Ln => self.buffer.push(b'\n'),
            Break::CrLn => self.buffer.extend_from_slice(b"\r\n"),
            Break::Any => panic!("unknown line break setting"),
        }
        if self.column == 0 {
            self.space_above = true;
        }
        self.column = 0;
        self.line += 1;
        self.indention = true;
        true
    }

    fn write(&mut self, s: &[u8], i: &mut usize) -> bool {
        // A width of 0 (an invalid leading byte) panics in go-yaml; never
        // reached with valid UTF-8, copied as one byte here.
        let w = width(s[*i]).max(1);
        let end = (*i + w).min(s.len());
        self.buffer.extend_from_slice(&s[*i..end]);
        self.column += 1;
        *i += w;
        true
    }

    fn write_all(&mut self, s: &[u8]) -> bool {
        let mut i = 0;
        while i < s.len() {
            if !self.write(s, &mut i) {
                return false;
            }
        }
        true
    }

    fn write_break(&mut self, s: &[u8], i: &mut usize) -> bool {
        if s[*i] == b'\n' {
            if !self.put_break() {
                return false;
            }
            *i += 1;
        } else {
            if !self.write(s, i) {
                return false;
            }
            if self.column == 0 {
                self.space_above = true;
            }
            self.column = 0;
            self.line += 1;
            self.indention = true;
        }
        true
    }

    fn set_emitter_error(&mut self, problem: &str) -> bool {
        self.error = ErrorType::Emitter;
        self.problem = problem.to_string();
        false
    }

    /// yaml_emitter_emit: queues the event and emits what can be.
    pub fn emit(&mut self, event: Event) -> bool {
        self.events.push(event);
        while !self.need_more_events() {
            let event = std::mem::take(&mut self.events[self.events_head]);
            // The analysis and the state machine look at the queue's head,
            // so it stays in place while they run.
            self.events[self.events_head] = event.clone();
            if !self.analyze_event(&event) {
                return false;
            }
            if !self.state_machine(&event) {
                return false;
            }
            self.events[self.events_head] = Event::default();
            self.events_head += 1;
        }
        true
    }

    fn need_more_events(&self) -> bool {
        if self.events_head == self.events.len() {
            return true;
        }
        let accumulate = match self.events[self.events_head].typ {
            EventType::DocumentStart => 1,
            EventType::SequenceStart => 2,
            EventType::MappingStart => 3,
            _ => return false,
        };
        if self.events.len() - self.events_head > accumulate {
            return false;
        }
        let mut level = 0;
        for e in &self.events[self.events_head..] {
            match e.typ {
                EventType::StreamStart
                | EventType::DocumentStart
                | EventType::SequenceStart
                | EventType::MappingStart => level += 1,
                EventType::StreamEnd
                | EventType::DocumentEnd
                | EventType::SequenceEnd
                | EventType::MappingEnd => level -= 1,
                _ => {}
            }
            if level == 0 {
                return false;
            }
        }
        true
    }

    fn append_tag_directive(&mut self, value: &TagDirective, allow_duplicates: bool) -> bool {
        for d in &self.tag_directives {
            if d.handle == value.handle {
                if allow_duplicates {
                    return true;
                }
                return self.set_emitter_error("duplicate %TAG directive");
            }
        }
        self.tag_directives.push(value.clone());
        true
    }

    fn increase_indent_compact(&mut self, flow: bool, indentless: bool, compact_seq: bool) -> bool {
        self.indents.push(self.indent);
        if self.indent < 0 {
            if flow {
                self.indent = self.best_indent;
            } else {
                self.indent = 0;
            }
        } else if !indentless {
            if self.states.last() == Some(&State::BlockSequenceItem) {
                self.indent += 2;
            } else {
                self.indent =
                    self.best_indent * ((self.indent + self.best_indent) / self.best_indent);
                if compact_seq {
                    self.indent -= 2;
                }
            }
        }
        true
    }

    fn pop_indent(&mut self) {
        self.indent = self.indents.pop().expect("indent stack");
    }

    fn pop_state(&mut self) {
        self.state = self.states.pop().expect("state stack");
    }

    fn state_machine(&mut self, event: &Event) -> bool {
        match self.state {
            State::StreamStart => self.emit_stream_start(event),
            State::FirstDocumentStart => self.emit_document_start(event, true),
            State::DocumentStart => self.emit_document_start(event, false),
            State::DocumentContent => self.emit_document_content(event),
            State::DocumentEnd => self.emit_document_end(event),
            State::FlowSequenceFirstItem => self.emit_flow_sequence_item(event, true, false),
            State::FlowSequenceTrailItem => self.emit_flow_sequence_item(event, false, true),
            State::FlowSequenceItem => self.emit_flow_sequence_item(event, false, false),
            State::FlowMappingFirstKey => self.emit_flow_mapping_key(event, true, false),
            State::FlowMappingTrailKey => self.emit_flow_mapping_key(event, false, true),
            State::FlowMappingKey => self.emit_flow_mapping_key(event, false, false),
            State::FlowMappingSimpleValue => self.emit_flow_mapping_value(event, true),
            State::FlowMappingValue => self.emit_flow_mapping_value(event, false),
            State::BlockSequenceFirstItem => self.emit_block_sequence_item(event, true),
            State::BlockSequenceItem => self.emit_block_sequence_item(event, false),
            State::BlockMappingFirstKey => self.emit_block_mapping_key(event, true),
            State::BlockMappingKey => self.emit_block_mapping_key(event, false),
            State::BlockMappingSimpleValue => self.emit_block_mapping_value(event, true),
            State::BlockMappingValue => self.emit_block_mapping_value(event, false),
            State::End => self.set_emitter_error("expected nothing after STREAM-END"),
        }
    }

    fn emit_stream_start(&mut self, event: &Event) -> bool {
        if event.typ != EventType::StreamStart {
            return self.set_emitter_error("expected STREAM-START");
        }
        if self.encoding == Encoding::Any {
            self.encoding = event.encoding;
            if self.encoding == Encoding::Any {
                self.encoding = Encoding::Utf8;
            }
        }
        if self.best_indent < 2 || self.best_indent > 9 {
            self.best_indent = 2;
        }
        if self.best_width >= 0 && self.best_width <= self.best_indent * 2 {
            self.best_width = 80;
        }
        if self.best_width < 0 {
            self.best_width = (1 << 31) - 1;
        }
        if self.line_break == Break::Any {
            self.line_break = Break::Ln;
        }
        self.indent = -1;
        self.line = 0;
        self.column = 0;
        self.whitespace = true;
        self.indention = true;
        self.space_above = true;
        self.foot_indent = -1;
        if self.encoding != Encoding::Utf8 && !self.write_bom() {
            return false;
        }
        self.state = State::FirstDocumentStart;
        true
    }

    fn emit_document_start(&mut self, event: &Event, first: bool) -> bool {
        if event.typ == EventType::DocumentStart {
            if let Some(v) = &event.version_directive
                && !self.analyze_version_directive(v)
            {
                return false;
            }
            for td in &event.tag_directives {
                if !self.analyze_tag_directive(td) {
                    return false;
                }
                if !self.append_tag_directive(td, false) {
                    return false;
                }
            }
            for td in &default_tag_directives() {
                if !self.append_tag_directive(td, true) {
                    return false;
                }
            }
            let mut implicit = event.implicit;
            if !first || self.canonical {
                implicit = false;
            }
            if self.open_ended
                && (event.version_directive.is_some() || !event.tag_directives.is_empty())
            {
                if !self.write_indicator(b"...", true, false, false) {
                    return false;
                }
                if !self.write_indent() {
                    return false;
                }
            }
            if event.version_directive.is_some() {
                implicit = false;
                if !self.write_indicator(b"%YAML", true, false, false) {
                    return false;
                }
                if !self.write_indicator(b"1.1", true, false, false) {
                    return false;
                }
                if !self.write_indent() {
                    return false;
                }
            }
            if !event.tag_directives.is_empty() {
                implicit = false;
                for td in &event.tag_directives {
                    if !self.write_indicator(b"%TAG", true, false, false) {
                        return false;
                    }
                    if !self.write_tag_handle(&td.handle) {
                        return false;
                    }
                    if !self.write_tag_content(&td.prefix, true) {
                        return false;
                    }
                    if !self.write_indent() {
                        return false;
                    }
                }
            }
            if self.check_empty_document() {
                implicit = false;
            }
            if !implicit {
                if !self.write_indent() {
                    return false;
                }
                if !self.write_indicator(b"---", true, false, false) {
                    return false;
                }
                if !self.write_indent() {
                    return false;
                }
            }
            if !self.head_comment.is_empty() {
                if !self.process_head_comment() {
                    return false;
                }
                if !self.put_break() {
                    return false;
                }
            }
            self.state = State::DocumentContent;
            return true;
        }
        if event.typ == EventType::StreamEnd {
            if self.open_ended {
                if !self.write_indicator(b"...", true, false, false) {
                    return false;
                }
                if !self.write_indent() {
                    return false;
                }
            }
            if !self.flush() {
                return false;
            }
            self.state = State::End;
            return true;
        }
        self.set_emitter_error("expected DOCUMENT-START or STREAM-END")
    }

    fn increase_indent(&mut self, flow: bool, indentless: bool) -> bool {
        self.increase_indent_compact(flow, indentless, false)
    }

    fn process_line_comment(&mut self) -> bool {
        self.process_line_comment_linebreak(false)
    }

    fn emit_document_content(&mut self, event: &Event) -> bool {
        self.states.push(State::DocumentEnd);
        if !self.process_head_comment() {
            return false;
        }
        if !self.emit_node(event, true, false, false, false) {
            return false;
        }
        if !self.process_line_comment() {
            return false;
        }
        if !self.process_foot_comment() {
            return false;
        }
        true
    }

    fn emit_document_end(&mut self, event: &Event) -> bool {
        if event.typ != EventType::DocumentEnd {
            return self.set_emitter_error("expected DOCUMENT-END");
        }
        self.foot_indent = 0;
        if !self.process_foot_comment() {
            return false;
        }
        self.foot_indent = -1;
        if !self.write_indent() {
            return false;
        }
        if !event.implicit {
            if !self.write_indicator(b"...", true, false, false) {
                return false;
            }
            if !self.write_indent() {
                return false;
            }
        }
        if !self.flush() {
            return false;
        }
        self.state = State::DocumentStart;
        self.tag_directives.clear();
        true
    }

    fn comments_after(&self) -> bool {
        self.line_comment.len() + self.foot_comment.len() + self.tail_comment.len() > 0
    }

    fn emit_flow_sequence_item(&mut self, event: &Event, first: bool, trail: bool) -> bool {
        if first {
            if !self.write_indicator(b"[", true, true, false) {
                return false;
            }
            if !self.increase_indent(true, false) {
                return false;
            }
            self.flow_level += 1;
        }
        if event.typ == EventType::SequenceEnd {
            if self.canonical
                && !first
                && !trail
                && !self.write_indicator(b",", false, false, false)
            {
                return false;
            }
            self.flow_level -= 1;
            self.pop_indent();
            if (self.column == 0 || self.canonical && !first) && !self.write_indent() {
                return false;
            }
            if !self.write_indicator(b"]", false, false, false) {
                return false;
            }
            if !self.process_line_comment() {
                return false;
            }
            if !self.process_foot_comment() {
                return false;
            }
            self.pop_state();
            return true;
        }
        if !first && !trail && !self.write_indicator(b",", false, false, false) {
            return false;
        }
        if !self.process_head_comment() {
            return false;
        }
        if self.column == 0 && !self.write_indent() {
            return false;
        }
        if (self.canonical || self.column > self.best_width) && !self.write_indent() {
            return false;
        }
        if self.comments_after() {
            self.states.push(State::FlowSequenceTrailItem);
        } else {
            self.states.push(State::FlowSequenceItem);
        }
        if !self.emit_node(event, false, true, false, false) {
            return false;
        }
        if self.comments_after() && !self.write_indicator(b",", false, false, false) {
            return false;
        }
        if !self.process_line_comment() {
            return false;
        }
        if !self.process_foot_comment() {
            return false;
        }
        true
    }

    fn emit_flow_mapping_key(&mut self, event: &Event, first: bool, trail: bool) -> bool {
        if first {
            if !self.write_indicator(b"{", true, true, false) {
                return false;
            }
            if !self.increase_indent(true, false) {
                return false;
            }
            self.flow_level += 1;
        }
        if event.typ == EventType::MappingEnd {
            if (self.canonical
                || self.head_comment.len() + self.foot_comment.len() + self.tail_comment.len() > 0)
                && !first
                && !trail
                && !self.write_indicator(b",", false, false, false)
            {
                return false;
            }
            if !self.process_head_comment() {
                return false;
            }
            self.flow_level -= 1;
            self.pop_indent();
            if self.canonical && !first && !self.write_indent() {
                return false;
            }
            if !self.write_indicator(b"}", false, false, false) {
                return false;
            }
            if !self.process_line_comment() {
                return false;
            }
            if !self.process_foot_comment() {
                return false;
            }
            self.pop_state();
            return true;
        }
        if !first && !trail && !self.write_indicator(b",", false, false, false) {
            return false;
        }
        if !self.process_head_comment() {
            return false;
        }
        if self.column == 0 && !self.write_indent() {
            return false;
        }
        if (self.canonical || self.column > self.best_width) && !self.write_indent() {
            return false;
        }
        if !self.canonical && self.check_simple_key() {
            self.states.push(State::FlowMappingSimpleValue);
            return self.emit_node(event, false, false, true, true);
        }
        if !self.write_indicator(b"?", true, false, false) {
            return false;
        }
        self.states.push(State::FlowMappingValue);
        self.emit_node(event, false, false, true, false)
    }

    fn emit_flow_mapping_value(&mut self, event: &Event, simple: bool) -> bool {
        if simple {
            if !self.write_indicator(b":", false, false, false) {
                return false;
            }
        } else {
            if (self.canonical || self.column > self.best_width) && !self.write_indent() {
                return false;
            }
            if !self.write_indicator(b":", true, false, false) {
                return false;
            }
        }
        if self.comments_after() {
            self.states.push(State::FlowMappingTrailKey);
        } else {
            self.states.push(State::FlowMappingKey);
        }
        if !self.emit_node(event, false, false, true, false) {
            return false;
        }
        if self.comments_after() && !self.write_indicator(b",", false, false, false) {
            return false;
        }
        if !self.process_line_comment() {
            return false;
        }
        if !self.process_foot_comment() {
            return false;
        }
        true
    }

    fn emit_block_sequence_item(&mut self, event: &Event, first: bool) -> bool {
        if first {
            let seq = self.mapping_context
                && (self.column == 0 || !self.indention)
                && self.compact_sequence_indent;
            if !self.increase_indent_compact(false, false, seq) {
                return false;
            }
        }
        if event.typ == EventType::SequenceEnd {
            self.pop_indent();
            self.pop_state();
            return true;
        }
        if !self.process_head_comment() {
            return false;
        }
        if !self.write_indent() {
            return false;
        }
        if !self.write_indicator(b"-", true, false, true) {
            return false;
        }
        self.states.push(State::BlockSequenceItem);
        if !self.emit_node(event, false, true, false, false) {
            return false;
        }
        if !self.process_line_comment() {
            return false;
        }
        if !self.process_foot_comment() {
            return false;
        }
        true
    }

    fn emit_block_mapping_key(&mut self, event: &Event, first: bool) -> bool {
        if first && !self.increase_indent(false, false) {
            return false;
        }
        if !self.process_head_comment() {
            return false;
        }
        if event.typ == EventType::MappingEnd {
            self.pop_indent();
            self.pop_state();
            return true;
        }
        if !self.write_indent() {
            return false;
        }
        if !self.line_comment.is_empty() {
            self.key_line_comment = std::mem::take(&mut self.line_comment);
        }
        if self.check_simple_key() {
            self.states.push(State::BlockMappingSimpleValue);
            return self.emit_node(event, false, false, true, true);
        }
        if !self.write_indicator(b"?", true, false, true) {
            return false;
        }
        self.states.push(State::BlockMappingValue);
        self.emit_node(event, false, false, true, false)
    }

    fn emit_block_mapping_value(&mut self, event: &Event, simple: bool) -> bool {
        if simple {
            if !self.write_indicator(b":", false, false, false) {
                return false;
            }
        } else {
            if !self.write_indent() {
                return false;
            }
            if !self.write_indicator(b":", true, false, true) {
                return false;
            }
        }
        if !self.key_line_comment.is_empty() {
            if event.typ == EventType::Scalar {
                if self.line_comment.is_empty() {
                    self.line_comment = std::mem::take(&mut self.key_line_comment);
                }
            } else if raw_style(event) != 2
                && (event.typ == EventType::MappingStart || event.typ == EventType::SequenceStart)
            {
                std::mem::swap(&mut self.line_comment, &mut self.key_line_comment);
                if !self.process_line_comment() {
                    return false;
                }
                std::mem::swap(&mut self.line_comment, &mut self.key_line_comment);
            }
        }
        self.states.push(State::BlockMappingKey);
        if !self.emit_node(event, false, false, true, false) {
            return false;
        }
        if !self.process_line_comment() {
            return false;
        }
        if !self.process_foot_comment() {
            return false;
        }
        true
    }

    fn emit_node(
        &mut self,
        event: &Event,
        root: bool,
        sequence: bool,
        mapping: bool,
        simple_key: bool,
    ) -> bool {
        self.root_context = root;
        self.sequence_context = sequence;
        self.mapping_context = mapping;
        self.simple_key_context = simple_key;
        match event.typ {
            EventType::Alias => self.emit_alias(event),
            EventType::Scalar => self.emit_scalar(event),
            EventType::SequenceStart => self.emit_sequence_start(event),
            EventType::MappingStart => self.emit_mapping_start(event),
            t => self.set_emitter_error(&format!(
                "expected SCALAR, SEQUENCE-START, MAPPING-START, or ALIAS, but got {}",
                t.name()
            )),
        }
    }

    fn emit_alias(&mut self, _event: &Event) -> bool {
        if !self.process_anchor() {
            return false;
        }
        self.pop_state();
        true
    }

    fn emit_scalar(&mut self, event: &Event) -> bool {
        if !self.select_scalar_style(event) {
            return false;
        }
        if !self.process_anchor() {
            return false;
        }
        if !self.process_tag() {
            return false;
        }
        if !self.increase_indent(true, false) {
            return false;
        }
        if !self.process_scalar() {
            return false;
        }
        self.pop_indent();
        self.pop_state();
        true
    }

    fn emit_sequence_start(&mut self, event: &Event) -> bool {
        if !self.process_anchor() {
            return false;
        }
        if !self.process_tag() {
            return false;
        }
        if self.flow_level > 0
            || self.canonical
            || event.sequence_style() == SequenceStyle::Flow
            || self.check_empty_sequence()
        {
            self.state = State::FlowSequenceFirstItem;
        } else {
            self.state = State::BlockSequenceFirstItem;
        }
        true
    }

    fn emit_mapping_start(&mut self, event: &Event) -> bool {
        if !self.process_anchor() {
            return false;
        }
        if !self.process_tag() {
            return false;
        }
        if self.flow_level > 0
            || self.canonical
            || event.mapping_style() == MappingStyle::Flow
            || self.check_empty_mapping()
        {
            self.state = State::FlowMappingFirstKey;
        } else {
            self.state = State::BlockMappingFirstKey;
        }
        true
    }

    fn check_empty_document(&self) -> bool {
        false
    }

    fn check_empty_sequence(&self) -> bool {
        if self.events.len() - self.events_head < 2 {
            return false;
        }
        self.events[self.events_head].typ == EventType::SequenceStart
            && self.events[self.events_head + 1].typ == EventType::SequenceEnd
    }

    fn check_empty_mapping(&self) -> bool {
        if self.events.len() - self.events_head < 2 {
            return false;
        }
        self.events[self.events_head].typ == EventType::MappingStart
            && self.events[self.events_head + 1].typ == EventType::MappingEnd
    }

    fn anchor_len(&self) -> usize {
        self.anchor_data_anchor.as_ref().map_or(0, Vec::len)
    }

    fn check_simple_key(&self) -> bool {
        let length = match self.events[self.events_head].typ {
            EventType::Alias => self.anchor_len(),
            EventType::Scalar => {
                if self.scalar_data_multiline {
                    return false;
                }
                self.anchor_len()
                    + self.tag_data_handle.len()
                    + self.tag_data_suffix.len()
                    + self.scalar_data_value.len()
            }
            EventType::SequenceStart => {
                if !self.check_empty_sequence() {
                    return false;
                }
                self.anchor_len() + self.tag_data_handle.len() + self.tag_data_suffix.len()
            }
            EventType::MappingStart => {
                if !self.check_empty_mapping() {
                    return false;
                }
                self.anchor_len() + self.tag_data_handle.len() + self.tag_data_suffix.len()
            }
            _ => return false,
        };
        length <= 128
    }

    fn select_scalar_style(&mut self, event: &Event) -> bool {
        let no_tag = self.tag_data_handle.is_empty() && self.tag_data_suffix.is_empty();
        if no_tag && !event.implicit && !event.quoted_implicit {
            return self.set_emitter_error("neither tag nor implicit flags are specified");
        }
        let mut style = event.scalar_style();
        if style == ScalarStyle::Any {
            style = ScalarStyle::Plain;
        }
        if self.canonical {
            style = ScalarStyle::DoubleQuoted;
        }
        if self.simple_key_context && self.scalar_data_multiline {
            style = ScalarStyle::DoubleQuoted;
        }
        if style == ScalarStyle::Plain {
            if self.flow_level > 0 && !self.scalar_data_flow_plain_allowed
                || self.flow_level == 0 && !self.scalar_data_block_plain_allowed
            {
                style = ScalarStyle::SingleQuoted;
            }
            if self.scalar_data_value.is_empty() && (self.flow_level > 0 || self.simple_key_context)
            {
                style = ScalarStyle::SingleQuoted;
            }
            if no_tag && !event.implicit {
                style = ScalarStyle::SingleQuoted;
            }
        }
        if style == ScalarStyle::SingleQuoted && !self.scalar_data_single_quoted_allowed {
            style = ScalarStyle::DoubleQuoted;
        }
        if (style == ScalarStyle::Literal || style == ScalarStyle::Folded)
            && (!self.scalar_data_block_allowed || self.flow_level > 0 || self.simple_key_context)
        {
            style = ScalarStyle::DoubleQuoted;
        }
        if no_tag && !event.quoted_implicit && style != ScalarStyle::Plain {
            self.tag_data_handle = b"!".to_vec();
        }
        self.scalar_data_style = style;
        true
    }

    fn process_anchor(&mut self) -> bool {
        let Some(anchor) = self.anchor_data_anchor.clone() else {
            return true;
        };
        let c: &[u8] = if self.anchor_data_alias { b"*" } else { b"&" };
        if !self.write_indicator(c, true, false, false) {
            return false;
        }
        self.write_anchor(&anchor)
    }

    fn process_tag(&mut self) -> bool {
        if self.tag_data_handle.is_empty() && self.tag_data_suffix.is_empty() {
            return true;
        }
        let handle = self.tag_data_handle.clone();
        let suffix = self.tag_data_suffix.clone();
        if !handle.is_empty() {
            if !self.write_tag_handle(&handle) {
                return false;
            }
            if !suffix.is_empty() && !self.write_tag_content(&suffix, false) {
                return false;
            }
        } else {
            if !self.write_indicator(b"!<", true, false, false) {
                return false;
            }
            if !self.write_tag_content(&suffix, false) {
                return false;
            }
            if !self.write_indicator(b">", false, false, false) {
                return false;
            }
        }
        true
    }

    fn process_scalar(&mut self) -> bool {
        let value = self.scalar_data_value.clone();
        let allow = !self.simple_key_context;
        match self.scalar_data_style {
            ScalarStyle::Plain => self.write_plain_scalar(&value, allow),
            ScalarStyle::SingleQuoted => self.write_single_quoted_scalar(&value, allow),
            ScalarStyle::DoubleQuoted => self.write_double_quoted_scalar(&value, allow),
            ScalarStyle::Literal => self.write_literal_scalar(&value),
            ScalarStyle::Folded => self.write_folded_scalar(&value),
            ScalarStyle::Any => panic!("unknown scalar style"),
        }
    }

    fn process_head_comment(&mut self) -> bool {
        if !self.tail_comment.is_empty() {
            if !self.write_indent() {
                return false;
            }
            let c = std::mem::take(&mut self.tail_comment);
            if !self.write_comment(&c) {
                return false;
            }
            self.foot_indent = self.indent;
            if self.foot_indent < 0 {
                self.foot_indent = 0;
            }
        }
        if self.head_comment.is_empty() {
            return true;
        }
        if !self.write_indent() {
            return false;
        }
        let c = std::mem::take(&mut self.head_comment);
        if !self.write_comment(&c) {
            return false;
        }
        true
    }

    fn process_line_comment_linebreak(&mut self, linebreak: bool) -> bool {
        if self.line_comment.is_empty() {
            if linebreak && !self.put_break() {
                return false;
            }
            return true;
        }
        if !self.whitespace && !self.put(b' ') {
            return false;
        }
        let c = std::mem::take(&mut self.line_comment);
        if !self.write_comment(&c) {
            return false;
        }
        true
    }

    fn process_foot_comment(&mut self) -> bool {
        if self.foot_comment.is_empty() {
            return true;
        }
        if !self.write_indent() {
            return false;
        }
        let c = std::mem::take(&mut self.foot_comment);
        if !self.write_comment(&c) {
            return false;
        }
        self.foot_indent = self.indent;
        if self.foot_indent < 0 {
            self.foot_indent = 0;
        }
        true
    }

    fn analyze_version_directive(&mut self, v: &VersionDirective) -> bool {
        if v.major != 1 || v.minor != 1 {
            return self.set_emitter_error("incompatible %YAML directive");
        }
        true
    }

    fn analyze_tag_directive(&mut self, td: &TagDirective) -> bool {
        let handle = &td.handle;
        if handle.is_empty() {
            return self.set_emitter_error("tag handle must not be empty");
        }
        if handle[0] != b'!' {
            return self.set_emitter_error("tag handle must start with '!'");
        }
        if handle[handle.len() - 1] != b'!' {
            return self.set_emitter_error("tag handle must end with '!'");
        }
        let mut i = 1;
        while i < handle.len() - 1 {
            if !is_alpha(handle, i) {
                return self
                    .set_emitter_error("tag handle must contain alphanumerical characters only");
            }
            i += width(handle[i]).max(1);
        }
        if td.prefix.is_empty() {
            return self.set_emitter_error("tag prefix must not be empty");
        }
        true
    }

    fn analyze_anchor(&mut self, anchor: &[u8], alias: bool) -> bool {
        if anchor.is_empty() {
            let problem = if alias {
                "alias value must not be empty"
            } else {
                "anchor value must not be empty"
            };
            return self.set_emitter_error(problem);
        }
        let mut i = 0;
        while i < anchor.len() {
            if !is_alpha(anchor, i) {
                let problem = if alias {
                    "alias value must contain alphanumerical characters only"
                } else {
                    "anchor value must contain alphanumerical characters only"
                };
                return self.set_emitter_error(problem);
            }
            i += width(anchor[i]).max(1);
        }
        self.anchor_data_anchor = Some(anchor.to_vec());
        self.anchor_data_alias = alias;
        true
    }

    fn analyze_tag(&mut self, tag: &[u8]) -> bool {
        if tag.is_empty() {
            return self.set_emitter_error("tag value must not be empty");
        }
        for td in &self.tag_directives {
            if tag.starts_with(&td.prefix) {
                self.tag_data_handle = td.handle.clone();
                self.tag_data_suffix = tag[td.prefix.len()..].to_vec();
                return true;
            }
        }
        self.tag_data_suffix = tag.to_vec();
        true
    }

    fn analyze_scalar(&mut self, value: &[u8]) -> bool {
        let mut block_indicators = false;
        let mut flow_indicators = false;
        let mut line_breaks = false;
        let mut special_characters = false;
        let mut tab_characters = false;
        let mut leading_space = false;
        let mut leading_break = false;
        let mut trailing_space = false;
        let mut trailing_break = false;
        let mut break_space = false;
        let mut space_break = false;
        let mut previous_space = false;
        let mut previous_break = false;

        self.scalar_data_value = value.to_vec();
        if value.is_empty() {
            self.scalar_data_multiline = false;
            self.scalar_data_flow_plain_allowed = false;
            self.scalar_data_block_plain_allowed = true;
            self.scalar_data_single_quoted_allowed = true;
            self.scalar_data_block_allowed = false;
            return true;
        }
        if value.len() >= 3 && (value.starts_with(b"---") || value.starts_with(b"...")) {
            block_indicators = true;
            flow_indicators = true;
        }
        let mut preceded_by_whitespace = true;
        let mut i = 0;
        while i < value.len() {
            let w = width(value[i]);
            let followed_by_whitespace = i + w >= value.len() || is_blank(value, i + w);
            if i == 0 {
                match value[i] {
                    b'#' | b',' | b'[' | b']' | b'{' | b'}' | b'&' | b'*' | b'!' | b'|' | b'>'
                    | b'\'' | b'"' | b'%' | b'@' | b'`' => {
                        flow_indicators = true;
                        block_indicators = true;
                    }
                    b'?' | b':' => {
                        flow_indicators = true;
                        if followed_by_whitespace {
                            block_indicators = true;
                        }
                    }
                    b'-' => {
                        if followed_by_whitespace {
                            flow_indicators = true;
                            block_indicators = true;
                        }
                    }
                    _ => {}
                }
            } else {
                match value[i] {
                    b',' | b'?' | b'[' | b']' | b'{' | b'}' => flow_indicators = true,
                    b':' => {
                        flow_indicators = true;
                        if followed_by_whitespace {
                            block_indicators = true;
                        }
                    }
                    b'#' => {
                        if preceded_by_whitespace {
                            flow_indicators = true;
                            block_indicators = true;
                        }
                    }
                    _ => {}
                }
            }
            if value[i] == b'\t' {
                tab_characters = true;
            } else if !is_printable(value, i) || !is_ascii(value, i) && !self.unicode {
                special_characters = true;
            }
            if is_space(value, i) {
                if i == 0 {
                    leading_space = true;
                }
                if i + width(value[i]) == value.len() {
                    trailing_space = true;
                }
                if previous_break {
                    break_space = true;
                }
                previous_space = true;
                previous_break = false;
            } else if is_break(value, i) {
                line_breaks = true;
                if i == 0 {
                    leading_break = true;
                }
                if i + width(value[i]) == value.len() {
                    trailing_break = true;
                }
                if previous_space {
                    space_break = true;
                }
                previous_space = false;
                previous_break = true;
            } else {
                previous_space = false;
                previous_break = false;
            }
            preceded_by_whitespace = is_blankz(value, i);
            i += w.max(1);
        }

        self.scalar_data_multiline = line_breaks;
        self.scalar_data_flow_plain_allowed = true;
        self.scalar_data_block_plain_allowed = true;
        self.scalar_data_single_quoted_allowed = true;
        self.scalar_data_block_allowed = true;

        if leading_space || leading_break || trailing_space || trailing_break {
            self.scalar_data_flow_plain_allowed = false;
            self.scalar_data_block_plain_allowed = false;
        }
        if trailing_space {
            self.scalar_data_block_allowed = false;
        }
        if break_space {
            self.scalar_data_flow_plain_allowed = false;
            self.scalar_data_block_plain_allowed = false;
            self.scalar_data_single_quoted_allowed = false;
        }
        if space_break || tab_characters || special_characters {
            self.scalar_data_flow_plain_allowed = false;
            self.scalar_data_block_plain_allowed = false;
            self.scalar_data_single_quoted_allowed = false;
        }
        if space_break || special_characters {
            self.scalar_data_block_allowed = false;
        }
        if line_breaks {
            self.scalar_data_flow_plain_allowed = false;
            self.scalar_data_block_plain_allowed = false;
        }
        if flow_indicators {
            self.scalar_data_flow_plain_allowed = false;
        }
        if block_indicators {
            self.scalar_data_block_plain_allowed = false;
        }
        true
    }

    fn analyze_event(&mut self, event: &Event) -> bool {
        self.anchor_data_anchor = None;
        self.tag_data_handle.clear();
        self.tag_data_suffix.clear();
        self.scalar_data_value.clear();

        if !event.head_comment.is_empty() {
            self.head_comment = event.head_comment.clone();
        }
        if !event.line_comment.is_empty() {
            self.line_comment = event.line_comment.clone();
        }
        if !event.foot_comment.is_empty() {
            self.foot_comment = event.foot_comment.clone();
        }
        if !event.tail_comment.is_empty() {
            self.tail_comment = event.tail_comment.clone();
        }

        match event.typ {
            EventType::Alias => {
                if !self.analyze_anchor(&event.anchor, true) {
                    return false;
                }
            }
            EventType::Scalar => {
                if !event.anchor.is_empty() && !self.analyze_anchor(&event.anchor, false) {
                    return false;
                }
                if !event.tag.is_empty()
                    && (self.canonical || (!event.implicit && !event.quoted_implicit))
                    && !self.analyze_tag(&event.tag)
                {
                    return false;
                }
                if !self.analyze_scalar(&event.value) {
                    return false;
                }
            }
            EventType::SequenceStart | EventType::MappingStart => {
                if !event.anchor.is_empty() && !self.analyze_anchor(&event.anchor, false) {
                    return false;
                }
                if !event.tag.is_empty()
                    && (self.canonical || !event.implicit)
                    && !self.analyze_tag(&event.tag)
                {
                    return false;
                }
            }
            _ => {}
        }
        true
    }

    fn write_bom(&mut self) -> bool {
        self.buffer.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
        true
    }

    fn write_indent(&mut self) -> bool {
        let indent = self.indent.max(0);
        if (!self.indention || self.column > indent || (self.column == indent && !self.whitespace))
            && !self.put_break()
        {
            return false;
        }
        if self.foot_indent == indent && !self.put_break() {
            return false;
        }
        while self.column < indent {
            if !self.put(b' ') {
                return false;
            }
        }
        self.whitespace = true;
        self.space_above = false;
        self.foot_indent = -1;
        true
    }

    fn write_indicator(
        &mut self,
        indicator: &[u8],
        need_whitespace: bool,
        is_whitespace: bool,
        is_indention: bool,
    ) -> bool {
        if need_whitespace && !self.whitespace && !self.put(b' ') {
            return false;
        }
        if !self.write_all(indicator) {
            return false;
        }
        self.whitespace = is_whitespace;
        self.indention = self.indention && is_indention;
        self.open_ended = false;
        true
    }

    fn write_anchor(&mut self, value: &[u8]) -> bool {
        if !self.write_all(value) {
            return false;
        }
        self.whitespace = false;
        self.indention = false;
        true
    }

    fn write_tag_handle(&mut self, value: &[u8]) -> bool {
        if !self.whitespace && !self.put(b' ') {
            return false;
        }
        if !self.write_all(value) {
            return false;
        }
        self.whitespace = false;
        self.indention = false;
        true
    }

    fn write_tag_content(&mut self, value: &[u8], need_whitespace: bool) -> bool {
        if need_whitespace && !self.whitespace && !self.put(b' ') {
            return false;
        }
        let mut i = 0;
        while i < value.len() {
            let must_write = match value[i] {
                b';' | b'/' | b'?' | b':' | b'@' | b'&' | b'=' | b'+' | b'$' | b',' | b'_'
                | b'.' | b'~' | b'*' | b'\'' | b'(' | b')' | b'[' | b']' => true,
                _ => is_alpha(value, i),
            };
            if must_write {
                if !self.write(value, &mut i) {
                    return false;
                }
            } else {
                let w = width(value[i]);
                for _ in 0..w {
                    let octet = value[i];
                    i += 1;
                    if !self.put(b'%') {
                        return false;
                    }
                    for c in [octet >> 4, octet & 0x0f] {
                        let c = if c < 10 { c + b'0' } else { c + b'A' - 10 };
                        if !self.put(c) {
                            return false;
                        }
                    }
                }
                if w == 0 {
                    // go-yaml loops forever on an invalid leading byte.
                    i += 1;
                }
            }
        }
        self.whitespace = false;
        self.indention = false;
        true
    }

    fn write_plain_scalar(&mut self, value: &[u8], allow_breaks: bool) -> bool {
        if !value.is_empty() && !self.whitespace && !self.put(b' ') {
            return false;
        }
        let mut spaces = false;
        let mut breaks = false;
        let mut i = 0;
        while i < value.len() {
            if is_space(value, i) {
                if allow_breaks
                    && !spaces
                    && self.column > self.best_width
                    && !is_space(value, i + 1)
                {
                    if !self.write_indent() {
                        return false;
                    }
                    i += width(value[i]);
                } else if !self.write(value, &mut i) {
                    return false;
                }
                spaces = true;
            } else if is_break(value, i) {
                if !breaks && value[i] == b'\n' && !self.put_break() {
                    return false;
                }
                if !self.write_break(value, &mut i) {
                    return false;
                }
                breaks = true;
            } else {
                if breaks && !self.write_indent() {
                    return false;
                }
                if !self.write(value, &mut i) {
                    return false;
                }
                self.indention = false;
                spaces = false;
                breaks = false;
            }
        }
        if !value.is_empty() {
            self.whitespace = false;
        }
        self.indention = false;
        if self.root_context {
            self.open_ended = true;
        }
        true
    }

    fn write_single_quoted_scalar(&mut self, value: &[u8], allow_breaks: bool) -> bool {
        if !self.write_indicator(b"'", true, false, false) {
            return false;
        }
        let mut spaces = false;
        let mut breaks = false;
        let mut i = 0;
        while i < value.len() {
            if is_space(value, i) {
                if allow_breaks
                    && !spaces
                    && self.column > self.best_width
                    && i > 0
                    && i < value.len() - 1
                    && !is_space(value, i + 1)
                {
                    if !self.write_indent() {
                        return false;
                    }
                    i += width(value[i]);
                } else if !self.write(value, &mut i) {
                    return false;
                }
                spaces = true;
            } else if is_break(value, i) {
                if !breaks && value[i] == b'\n' && !self.put_break() {
                    return false;
                }
                if !self.write_break(value, &mut i) {
                    return false;
                }
                breaks = true;
            } else {
                if breaks && !self.write_indent() {
                    return false;
                }
                if value[i] == b'\'' && !self.put(b'\'') {
                    return false;
                }
                if !self.write(value, &mut i) {
                    return false;
                }
                self.indention = false;
                spaces = false;
                breaks = false;
            }
        }
        if !self.write_indicator(b"'", false, false, false) {
            return false;
        }
        self.whitespace = false;
        self.indention = false;
        true
    }

    fn write_double_quoted_scalar(&mut self, value: &[u8], allow_breaks: bool) -> bool {
        let mut spaces = false;
        if !self.write_indicator(b"\"", true, false, false) {
            return false;
        }
        let mut i = 0;
        while i < value.len() {
            if !is_printable(value, i)
                || (!self.unicode && !is_ascii(value, i))
                || is_bom(value, i)
                || is_break(value, i)
                || value[i] == b'"'
                || value[i] == b'\\'
            {
                let mut octet = value[i];
                let (mut w, mut v): (usize, u32) = if octet & 0x80 == 0x00 {
                    (1, (octet & 0x7F) as u32)
                } else if octet & 0xE0 == 0xC0 {
                    (2, (octet & 0x1F) as u32)
                } else if octet & 0xF0 == 0xE0 {
                    (3, (octet & 0x0F) as u32)
                } else if octet & 0xF8 == 0xF0 {
                    (4, (octet & 0x07) as u32)
                } else {
                    // go-yaml leaves w at 0 and loops forever; one byte here.
                    (1, octet as u32)
                };
                for k in 1..w {
                    octet = at(value, i + k);
                    v = (v << 6) + (octet as u32 & 0x3F);
                }
                i += w;
                if !self.put(b'\\') {
                    return false;
                }
                let ok = match v {
                    0x00 => self.put(b'0'),
                    0x07 => self.put(b'a'),
                    0x08 => self.put(b'b'),
                    0x09 => self.put(b't'),
                    0x0A => self.put(b'n'),
                    0x0b => self.put(b'v'),
                    0x0c => self.put(b'f'),
                    0x0d => self.put(b'r'),
                    0x1b => self.put(b'e'),
                    0x22 => self.put(b'"'),
                    0x5c => self.put(b'\\'),
                    0x85 => self.put(b'N'),
                    0xA0 => self.put(b'_'),
                    0x2028 => self.put(b'L'),
                    0x2029 => self.put(b'P'),
                    _ => {
                        let mut ok;
                        if v <= 0xFF {
                            ok = self.put(b'x');
                            w = 2;
                        } else if v <= 0xFFFF {
                            ok = self.put(b'u');
                            w = 4;
                        } else {
                            ok = self.put(b'U');
                            w = 8;
                        }
                        let mut k = (w as i32 - 1) * 4;
                        while ok && k >= 0 {
                            let digit = ((v >> k as u32) & 0x0F) as u8;
                            ok = if digit < 10 {
                                self.put(digit + b'0')
                            } else {
                                self.put(digit + b'A' - 10)
                            };
                            k -= 4;
                        }
                        ok
                    }
                };
                if !ok {
                    return false;
                }
                spaces = false;
            } else if is_space(value, i) {
                if allow_breaks
                    && !spaces
                    && self.column > self.best_width
                    && i > 0
                    && i < value.len() - 1
                {
                    if !self.write_indent() {
                        return false;
                    }
                    if is_space(value, i + 1) && !self.put(b'\\') {
                        return false;
                    }
                    i += width(value[i]);
                } else if !self.write(value, &mut i) {
                    return false;
                }
                spaces = true;
            } else {
                if !self.write(value, &mut i) {
                    return false;
                }
                spaces = false;
            }
        }
        if !self.write_indicator(b"\"", false, false, false) {
            return false;
        }
        self.whitespace = false;
        self.indention = false;
        true
    }

    fn write_block_scalar_hints(&mut self, value: &[u8]) -> bool {
        if is_space(value, 0) || is_break(value, 0) {
            let indent_hint = [b'0' + self.best_indent as u8];
            if !self.write_indicator(&indent_hint, false, false, false) {
                return false;
            }
        }
        self.open_ended = false;
        let mut chomp_hint = 0u8;
        if value.is_empty() {
            chomp_hint = b'-';
        } else {
            let mut i = value.len() - 1;
            while value[i] & 0xC0 == 0x80 && i > 0 {
                i -= 1;
            }
            if !is_break(value, i) {
                chomp_hint = b'-';
            } else if i == 0 {
                chomp_hint = b'+';
                self.open_ended = true;
            } else {
                i -= 1;
                while value[i] & 0xC0 == 0x80 && i > 0 {
                    i -= 1;
                }
                if is_break(value, i) {
                    chomp_hint = b'+';
                    self.open_ended = true;
                }
            }
        }
        if chomp_hint != 0 && !self.write_indicator(&[chomp_hint], false, false, false) {
            return false;
        }
        true
    }

    fn write_literal_scalar(&mut self, value: &[u8]) -> bool {
        if !self.write_indicator(b"|", true, false, false) {
            return false;
        }
        if !self.write_block_scalar_hints(value) {
            return false;
        }
        if !self.process_line_comment_linebreak(true) {
            return false;
        }
        self.whitespace = true;
        let mut breaks = true;
        let mut i = 0;
        while i < value.len() {
            if is_break(value, i) {
                if !self.write_break(value, &mut i) {
                    return false;
                }
                breaks = true;
            } else {
                if breaks && !self.write_indent() {
                    return false;
                }
                if !self.write(value, &mut i) {
                    return false;
                }
                self.indention = false;
                breaks = false;
            }
        }
        true
    }

    fn write_folded_scalar(&mut self, value: &[u8]) -> bool {
        if !self.write_indicator(b">", true, false, false) {
            return false;
        }
        if !self.write_block_scalar_hints(value) {
            return false;
        }
        if !self.process_line_comment_linebreak(true) {
            return false;
        }
        self.whitespace = true;
        let mut breaks = true;
        let mut leading_spaces = true;
        let mut i = 0;
        while i < value.len() {
            if is_break(value, i) {
                if !breaks && !leading_spaces && value[i] == b'\n' {
                    // go-yaml (as libyaml) scans from the start of the value
                    // here, not from i.
                    let mut k = 0;
                    while is_break(value, k) {
                        k += width(value[k]);
                    }
                    if !is_blankz(value, k) && !self.put_break() {
                        return false;
                    }
                }
                if !self.write_break(value, &mut i) {
                    return false;
                }
                breaks = true;
            } else {
                if breaks {
                    if !self.write_indent() {
                        return false;
                    }
                    leading_spaces = is_blank(value, i);
                }
                if !breaks
                    && is_space(value, i)
                    && !is_space(value, i + 1)
                    && self.column > self.best_width
                {
                    if !self.write_indent() {
                        return false;
                    }
                    i += width(value[i]);
                } else if !self.write(value, &mut i) {
                    return false;
                }
                self.indention = false;
                breaks = false;
            }
        }
        true
    }

    fn write_comment(&mut self, comment: &[u8]) -> bool {
        let mut breaks = false;
        let mut pound = false;
        let mut i = 0;
        while i < comment.len() {
            if is_break(comment, i) {
                if !self.write_break(comment, &mut i) {
                    return false;
                }
                breaks = true;
                pound = false;
            } else {
                if breaks && !self.write_indent() {
                    return false;
                }
                if !pound {
                    if comment[i] != b'#' && (!self.put(b'#') || !self.put(b' ')) {
                        return false;
                    }
                    pound = true;
                }
                if !self.write(comment, &mut i) {
                    return false;
                }
                self.indention = false;
                breaks = false;
            }
        }
        if !breaks && !self.put_break() {
            return false;
        }
        self.whitespace = true;
        true
    }
}

// apic.go: event constructors.

/// yaml_stream_start_event_initialize.
pub fn stream_start_event(encoding: Encoding) -> Event {
    Event {
        typ: EventType::StreamStart,
        encoding,
        ..Default::default()
    }
}

/// yaml_stream_end_event_initialize.
pub fn stream_end_event() -> Event {
    Event {
        typ: EventType::StreamEnd,
        ..Default::default()
    }
}

/// yaml_document_start_event_initialize.
pub fn document_start_event(
    version_directive: Option<VersionDirective>,
    tag_directives: Vec<TagDirective>,
    implicit: bool,
) -> Event {
    Event {
        typ: EventType::DocumentStart,
        version_directive,
        tag_directives,
        implicit,
        ..Default::default()
    }
}

/// yaml_document_end_event_initialize.
pub fn document_end_event(implicit: bool) -> Event {
    Event {
        typ: EventType::DocumentEnd,
        implicit,
        ..Default::default()
    }
}

/// yaml_alias_event_initialize.
pub fn alias_event(anchor: &[u8]) -> Event {
    Event {
        typ: EventType::Alias,
        anchor: anchor.to_vec(),
        ..Default::default()
    }
}

/// yaml_scalar_event_initialize.
pub fn scalar_event(
    anchor: &[u8],
    tag: &[u8],
    value: &[u8],
    plain_implicit: bool,
    quoted_implicit: bool,
    style: ScalarStyle,
) -> Event {
    Event {
        typ: EventType::Scalar,
        anchor: anchor.to_vec(),
        tag: tag.to_vec(),
        value: value.to_vec(),
        implicit: plain_implicit,
        quoted_implicit,
        style: super::types::EventStyle::Scalar(style),
        ..Default::default()
    }
}

/// yaml_sequence_start_event_initialize.
pub fn sequence_start_event(
    anchor: &[u8],
    tag: &[u8],
    implicit: bool,
    style: SequenceStyle,
) -> Event {
    Event {
        typ: EventType::SequenceStart,
        anchor: anchor.to_vec(),
        tag: tag.to_vec(),
        implicit,
        style: super::types::EventStyle::Sequence(style),
        ..Default::default()
    }
}

/// yaml_sequence_end_event_initialize.
pub fn sequence_end_event() -> Event {
    Event {
        typ: EventType::SequenceEnd,
        ..Default::default()
    }
}

/// yaml_mapping_start_event_initialize.
pub fn mapping_start_event(
    anchor: &[u8],
    tag: &[u8],
    implicit: bool,
    style: MappingStyle,
) -> Event {
    Event {
        typ: EventType::MappingStart,
        anchor: anchor.to_vec(),
        tag: tag.to_vec(),
        implicit,
        style: super::types::EventStyle::Mapping(style),
        ..Default::default()
    }
}

/// yaml_mapping_end_event_initialize.
pub fn mapping_end_event() -> Event {
    Event {
        typ: EventType::MappingEnd,
        ..Default::default()
    }
}
