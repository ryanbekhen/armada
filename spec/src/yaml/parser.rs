//! The event parser (go-yaml's parserc.go, with the parser's part of
//! apic.go and yamlh.go): turns the scanner's tokens into events, keeping
//! go-yaml's states, comment handling, and error texts.

use std::collections::HashMap;

use super::chars::{INITIAL_QUEUE_SIZE, INITIAL_STACK_SIZE};
use super::scanner::{Comment, SimpleKey, Token, TokenType};
use super::types::{
    Encoding, ErrorType, Event, EventStyle, EventType, MappingStyle, Mark, ScalarStyle,
    SequenceStyle, TagDirective, VersionDirective,
};

/// Parser states (yaml_parser_state_t).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum State {
    #[default]
    StreamStart,
    ImplicitDocumentStart,
    DocumentStart,
    DocumentContent,
    DocumentEnd,
    BlockNode,
    BlockNodeOrIndentlessSequence,
    FlowNode,
    BlockSequenceFirstEntry,
    BlockSequenceEntry,
    IndentlessSequenceEntry,
    BlockMappingFirstKey,
    BlockMappingKey,
    BlockMappingValue,
    FlowSequenceFirstEntry,
    FlowSequenceEntry,
    FlowSequenceEntryMappingKey,
    FlowSequenceEntryMappingValue,
    FlowSequenceEntryMappingEnd,
    FlowMappingFirstKey,
    FlowMappingKey,
    FlowMappingValue,
    FlowMappingEmptyValue,
    End,
}

/// A YAML parser (yaml_parser_t): the reader, scanner, and parser state.
#[derive(Default)]
pub struct Parser {
    pub error: ErrorType,
    pub problem: String,
    pub problem_offset: usize,
    pub problem_value: i64,
    pub problem_mark: Mark,
    pub context: String,
    pub context_mark: Mark,

    pub(super) input: Vec<u8>,
    pub(super) input_pos: usize,
    pub(super) eof: bool,

    /// The working buffer: its array (whose length is go-yaml's capacity)
    /// and the length of the slice go-yaml uses.
    pub(super) buffer: Vec<u8>,
    pub(super) buffer_len: usize,
    pub(super) buffer_pos: usize,
    pub(super) unread: usize,
    pub(super) newlines: usize,

    pub(super) raw_buffer: Vec<u8>,
    pub(super) raw_buffer_pos: usize,

    pub(super) encoding: Encoding,
    pub(super) offset: usize,
    pub(super) mark: Mark,

    pub(super) head_comment: Vec<u8>,
    pub(super) line_comment: Vec<u8>,
    pub(super) foot_comment: Vec<u8>,
    pub(super) tail_comment: Vec<u8>,
    pub(super) stem_comment: Vec<u8>,

    pub(super) comments: Vec<Comment>,
    pub(super) comments_head: usize,

    pub(super) stream_start_produced: bool,
    pub(super) stream_end_produced: bool,

    pub(super) flow_level: i64,

    pub(super) tokens: Vec<Token>,
    /// The capacity go-yaml's tokens slice would have: the queue is moved to
    /// its start only when full, which some checks of the last two tokens
    /// can see.
    pub(super) tokens_cap: usize,
    pub(super) tokens_head: usize,
    pub(super) tokens_parsed: usize,
    pub(super) token_available: bool,

    pub(super) indent: i64,
    pub(super) indents: Vec<i64>,

    pub(super) simple_key_allowed: bool,
    pub(super) simple_keys: Vec<SimpleKey>,
    pub(super) simple_keys_by_tok: HashMap<usize, usize>,

    pub(super) state: State,
    pub(super) states: Vec<State>,
    pub(super) marks: Vec<Mark>,
    pub(super) tag_directives: Vec<TagDirective>,
}

fn pop<T: Copy>(v: &mut Vec<T>) -> T {
    v.pop().expect("go-yaml's stacks are never popped empty")
}

impl Parser {
    pub fn new() -> Parser {
        Parser {
            raw_buffer: Vec::with_capacity(super::chars::INPUT_RAW_BUFFER_SIZE),
            states: Vec::with_capacity(INITIAL_STACK_SIZE),
            comments: Vec::with_capacity(INITIAL_QUEUE_SIZE),
            ..Parser::default()
        }
    }

    /// yaml_parser_set_input_string.
    pub fn set_input_string(&mut self, input: Vec<u8>) {
        self.input = input;
        self.input_pos = 0;
    }

    /// yaml_parser_set_input_reader with a bytes.Reader: it reads as the
    /// string input does.
    pub fn set_input_reader(&mut self, input: Vec<u8>) {
        self.set_input_string(input);
    }

    fn peek_token(&mut self) -> Option<Token> {
        if self.token_available || self.fetch_more_tokens() {
            let idx = self.tokens_head;
            self.unfold_comments(idx);
            return Some(self.tokens[idx].clone());
        }
        None
    }

    fn unfold_comments(&mut self, idx: usize) {
        let start = self.tokens[idx].start_mark.index as i64;
        let typ = self.tokens[idx].typ;
        while self.comments_head < self.comments.len()
            && start >= self.comments[self.comments_head].token_mark.index as i64
        {
            let comment = self.comments[self.comments_head].clone();
            if !comment.head.is_empty() {
                if typ == TokenType::BlockEnd {
                    // No heads on ends, so keep comment.head for a follow up token.
                    break;
                }
                if !self.head_comment.is_empty() {
                    self.head_comment.push(b'\n');
                }
                self.head_comment.extend_from_slice(&comment.head);
            }
            if !comment.foot.is_empty() {
                if !self.foot_comment.is_empty() {
                    self.foot_comment.push(b'\n');
                }
                self.foot_comment.extend_from_slice(&comment.foot);
            }
            if !comment.line.is_empty() {
                if !self.line_comment.is_empty() {
                    self.line_comment.push(b'\n');
                }
                self.line_comment.extend_from_slice(&comment.line);
            }
            self.comments[self.comments_head] = Comment::default();
            self.comments_head += 1;
        }
    }

    fn skip_token(&mut self) {
        self.token_available = false;
        self.tokens_parsed += 1;
        self.stream_end_produced = self.tokens[self.tokens_head].typ == TokenType::StreamEnd;
        self.tokens_head += 1;
    }

    /// yaml_parser_parse: the next event, or false with the error set.
    pub fn parse(&mut self, event: &mut Event) -> bool {
        *event = Event::default();
        if self.stream_end_produced || self.error != ErrorType::None || self.state == State::End {
            return true;
        }
        self.state_machine(event)
    }

    fn set_parser_error(&mut self, problem: &str, problem_mark: Mark) -> bool {
        self.error = ErrorType::Parser;
        self.problem = problem.to_string();
        self.problem_mark = problem_mark;
        false
    }

    fn set_parser_error_context(
        &mut self,
        context: &str,
        context_mark: Mark,
        problem: &str,
        problem_mark: Mark,
    ) -> bool {
        self.error = ErrorType::Parser;
        self.context = context.to_string();
        self.context_mark = context_mark;
        self.problem = problem.to_string();
        self.problem_mark = problem_mark;
        false
    }

    fn state_machine(&mut self, event: &mut Event) -> bool {
        match self.state {
            State::StreamStart => self.parse_stream_start(event),
            State::ImplicitDocumentStart => self.parse_document_start(event, true),
            State::DocumentStart => self.parse_document_start(event, false),
            State::DocumentContent => self.parse_document_content(event),
            State::DocumentEnd => self.parse_document_end(event),
            State::BlockNode => self.parse_node(event, true, false),
            State::BlockNodeOrIndentlessSequence => self.parse_node(event, true, true),
            State::FlowNode => self.parse_node(event, false, false),
            State::BlockSequenceFirstEntry => self.parse_block_sequence_entry(event, true),
            State::BlockSequenceEntry => self.parse_block_sequence_entry(event, false),
            State::IndentlessSequenceEntry => self.parse_indentless_sequence_entry(event),
            State::BlockMappingFirstKey => self.parse_block_mapping_key(event, true),
            State::BlockMappingKey => self.parse_block_mapping_key(event, false),
            State::BlockMappingValue => self.parse_block_mapping_value(event),
            State::FlowSequenceFirstEntry => self.parse_flow_sequence_entry(event, true),
            State::FlowSequenceEntry => self.parse_flow_sequence_entry(event, false),
            State::FlowSequenceEntryMappingKey => self.parse_flow_sequence_entry_mapping_key(event),
            State::FlowSequenceEntryMappingValue => {
                self.parse_flow_sequence_entry_mapping_value(event)
            }
            State::FlowSequenceEntryMappingEnd => self.parse_flow_sequence_entry_mapping_end(event),
            State::FlowMappingFirstKey => self.parse_flow_mapping_key(event, true),
            State::FlowMappingKey => self.parse_flow_mapping_key(event, false),
            State::FlowMappingValue => self.parse_flow_mapping_value(event, false),
            State::FlowMappingEmptyValue => self.parse_flow_mapping_value(event, true),
            State::End => panic!("invalid parser state"),
        }
    }

    fn parse_stream_start(&mut self, event: &mut Event) -> bool {
        let Some(token) = self.peek_token() else {
            return false;
        };
        if token.typ != TokenType::StreamStart {
            return self.set_parser_error("did not find expected <stream-start>", token.start_mark);
        }
        self.state = State::ImplicitDocumentStart;
        *event = Event {
            typ: EventType::StreamStart,
            start_mark: token.start_mark,
            end_mark: token.end_mark,
            encoding: token.encoding,
            ..Event::default()
        };
        self.skip_token();
        true
    }

    fn parse_document_start(&mut self, event: &mut Event, implicit: bool) -> bool {
        let Some(mut token) = self.peek_token() else {
            return false;
        };
        // Parse extra document end indicators.
        if !implicit {
            while token.typ == TokenType::DocumentEnd {
                self.skip_token();
                match self.peek_token() {
                    Some(t) => token = t,
                    None => return false,
                }
            }
        }
        if implicit
            && token.typ != TokenType::VersionDirective
            && token.typ != TokenType::TagDirective
            && token.typ != TokenType::DocumentStart
            && token.typ != TokenType::StreamEnd
        {
            // An implicit document.
            if !self.process_directives(None, None) {
                return false;
            }
            self.states.push(State::DocumentEnd);
            self.state = State::BlockNode;
            let mut head_comment = Vec::new();
            if !self.head_comment.is_empty() {
                // Scan the header comment backwards, and if an empty
                // line is found, break the header so the part before the
                // last empty line goes into the document header, while the
                // bottom of it goes into a follow up event.
                let hc = &self.head_comment;
                let mut i = hc.len() - 1;
                while i > 0 {
                    if hc[i] == b'\n' {
                        if i == hc.len() - 1 {
                            head_comment = hc[..i].to_vec();
                            self.head_comment = hc[i + 1..].to_vec();
                            break;
                        } else if hc[i - 1] == b'\n' {
                            head_comment = hc[..i - 1].to_vec();
                            self.head_comment = hc[i + 1..].to_vec();
                            break;
                        }
                    }
                    i -= 1;
                }
            }
            *event = Event {
                typ: EventType::DocumentStart,
                start_mark: token.start_mark,
                end_mark: token.end_mark,
                head_comment,
                ..Event::default()
            };
        } else if token.typ != TokenType::StreamEnd {
            // An explicit document.
            let start_mark = token.start_mark;
            let mut version_directive = None;
            let mut tag_directives = Vec::new();
            if !self.process_directives(Some(&mut version_directive), Some(&mut tag_directives)) {
                return false;
            }
            let Some(token) = self.peek_token() else {
                return false;
            };
            if token.typ != TokenType::DocumentStart {
                self.set_parser_error("did not find expected <document start>", token.start_mark);
                return false;
            }
            self.states.push(State::DocumentEnd);
            self.state = State::DocumentContent;
            *event = Event {
                typ: EventType::DocumentStart,
                start_mark,
                end_mark: token.end_mark,
                version_directive,
                tag_directives,
                implicit: false,
                ..Event::default()
            };
            self.skip_token();
        } else {
            // The stream end.
            self.state = State::End;
            *event = Event {
                typ: EventType::StreamEnd,
                start_mark: token.start_mark,
                end_mark: token.end_mark,
                ..Event::default()
            };
            self.skip_token();
        }
        true
    }

    fn parse_document_content(&mut self, event: &mut Event) -> bool {
        let Some(token) = self.peek_token() else {
            return false;
        };
        if matches!(
            token.typ,
            TokenType::VersionDirective
                | TokenType::TagDirective
                | TokenType::DocumentStart
                | TokenType::DocumentEnd
                | TokenType::StreamEnd
        ) {
            self.state = pop(&mut self.states);
            return self.process_empty_scalar(event, token.start_mark);
        }
        self.parse_node(event, true, false)
    }

    fn parse_document_end(&mut self, event: &mut Event) -> bool {
        let Some(token) = self.peek_token() else {
            return false;
        };
        let start_mark = token.start_mark;
        let mut end_mark = token.start_mark;
        let mut implicit = true;
        if token.typ == TokenType::DocumentEnd {
            end_mark = token.end_mark;
            self.skip_token();
            implicit = false;
        }
        self.tag_directives.clear();
        self.state = State::DocumentStart;
        *event = Event {
            typ: EventType::DocumentEnd,
            start_mark,
            end_mark,
            implicit,
            ..Event::default()
        };
        self.set_event_comments(event);
        if !event.head_comment.is_empty() && event.foot_comment.is_empty() {
            event.foot_comment = std::mem::take(&mut event.head_comment);
        }
        true
    }

    fn set_event_comments(&mut self, event: &mut Event) {
        event.head_comment = std::mem::take(&mut self.head_comment);
        event.line_comment = std::mem::take(&mut self.line_comment);
        event.foot_comment = std::mem::take(&mut self.foot_comment);
        self.tail_comment.clear();
        self.stem_comment.clear();
    }

    fn parse_node(&mut self, event: &mut Event, block: bool, indentless_sequence: bool) -> bool {
        let Some(mut token) = self.peek_token() else {
            return false;
        };
        if token.typ == TokenType::Alias {
            self.state = pop(&mut self.states);
            *event = Event {
                typ: EventType::Alias,
                start_mark: token.start_mark,
                end_mark: token.end_mark,
                anchor: token.value.clone(),
                ..Event::default()
            };
            self.set_event_comments(event);
            self.skip_token();
            return true;
        }
        let mut start_mark = token.start_mark;
        let mut end_mark = token.start_mark;
        let mut tag_token = false;
        let mut tag_handle = Vec::new();
        let mut tag_suffix = Vec::new();
        let mut anchor = Vec::new();
        let mut tag_mark = Mark::default();
        if token.typ == TokenType::Anchor {
            anchor = token.value.clone();
            start_mark = token.start_mark;
            end_mark = token.end_mark;
            self.skip_token();
            match self.peek_token() {
                Some(t) => token = t,
                None => return false,
            }
            if token.typ == TokenType::Tag {
                tag_token = true;
                tag_handle = token.value.clone();
                tag_suffix = token.suffix.clone();
                tag_mark = token.start_mark;
                end_mark = token.end_mark;
                self.skip_token();
                match self.peek_token() {
                    Some(t) => token = t,
                    None => return false,
                }
            }
        } else if token.typ == TokenType::Tag {
            tag_token = true;
            tag_handle = token.value.clone();
            tag_suffix = token.suffix.clone();
            start_mark = token.start_mark;
            tag_mark = token.start_mark;
            end_mark = token.end_mark;
            self.skip_token();
            match self.peek_token() {
                Some(t) => token = t,
                None => return false,
            }
            if token.typ == TokenType::Anchor {
                anchor = token.value.clone();
                end_mark = token.end_mark;
                self.skip_token();
                match self.peek_token() {
                    Some(t) => token = t,
                    None => return false,
                }
            }
        }

        let mut tag = Vec::new();
        if tag_token {
            if tag_handle.is_empty() {
                tag = tag_suffix;
            } else {
                for d in &self.tag_directives {
                    if d.handle == tag_handle {
                        tag = d.prefix.clone();
                        tag.extend_from_slice(&tag_suffix);
                        break;
                    }
                }
                if tag.is_empty() {
                    self.set_parser_error_context(
                        "while parsing a node",
                        start_mark,
                        "found undefined tag handle",
                        tag_mark,
                    );
                    return false;
                }
            }
        }

        let implicit = tag.is_empty();
        if indentless_sequence && token.typ == TokenType::BlockEntry {
            end_mark = token.end_mark;
            self.state = State::IndentlessSequenceEntry;
            *event = Event {
                typ: EventType::SequenceStart,
                start_mark,
                end_mark,
                anchor,
                tag,
                implicit,
                style: EventStyle::Sequence(SequenceStyle::Block),
                ..Event::default()
            };
            return true;
        }
        if token.typ == TokenType::Scalar {
            let mut plain_implicit = false;
            let mut quoted_implicit = false;
            end_mark = token.end_mark;
            if (tag.is_empty() && token.style == ScalarStyle::Plain)
                || (tag.len() == 1 && tag[0] == b'!')
            {
                plain_implicit = true;
            } else if tag.is_empty() {
                quoted_implicit = true;
            }
            self.state = pop(&mut self.states);
            *event = Event {
                typ: EventType::Scalar,
                start_mark,
                end_mark,
                anchor,
                tag,
                value: token.value.clone(),
                implicit: plain_implicit,
                quoted_implicit,
                style: EventStyle::Scalar(token.style),
                ..Event::default()
            };
            self.set_event_comments(event);
            self.skip_token();
            return true;
        }
        if token.typ == TokenType::FlowSequenceStart {
            // Some of the events below can be merged as they differ only on style.
            end_mark = token.end_mark;
            self.state = State::FlowSequenceFirstEntry;
            *event = Event {
                typ: EventType::SequenceStart,
                start_mark,
                end_mark,
                anchor,
                tag,
                implicit,
                style: EventStyle::Sequence(SequenceStyle::Flow),
                ..Event::default()
            };
            self.set_event_comments(event);
            return true;
        }
        if token.typ == TokenType::FlowMappingStart {
            end_mark = token.end_mark;
            self.state = State::FlowMappingFirstKey;
            *event = Event {
                typ: EventType::MappingStart,
                start_mark,
                end_mark,
                anchor,
                tag,
                implicit,
                style: EventStyle::Mapping(MappingStyle::Flow),
                ..Event::default()
            };
            self.set_event_comments(event);
            return true;
        }
        if block && token.typ == TokenType::BlockSequenceStart {
            end_mark = token.end_mark;
            self.state = State::BlockSequenceFirstEntry;
            *event = Event {
                typ: EventType::SequenceStart,
                start_mark,
                end_mark,
                anchor,
                tag,
                implicit,
                style: EventStyle::Sequence(SequenceStyle::Block),
                ..Event::default()
            };
            if !self.stem_comment.is_empty() {
                event.head_comment = std::mem::take(&mut self.stem_comment);
            }
            return true;
        }
        if block && token.typ == TokenType::BlockMappingStart {
            end_mark = token.end_mark;
            self.state = State::BlockMappingFirstKey;
            *event = Event {
                typ: EventType::MappingStart,
                start_mark,
                end_mark,
                anchor,
                tag,
                implicit,
                style: EventStyle::Mapping(MappingStyle::Block),
                ..Event::default()
            };
            if !self.stem_comment.is_empty() {
                event.head_comment = std::mem::take(&mut self.stem_comment);
            }
            return true;
        }
        if !anchor.is_empty() || !tag.is_empty() {
            self.state = pop(&mut self.states);
            *event = Event {
                typ: EventType::Scalar,
                start_mark,
                end_mark,
                anchor,
                tag,
                implicit,
                quoted_implicit: false,
                style: EventStyle::Scalar(ScalarStyle::Plain),
                ..Event::default()
            };
            return true;
        }
        let context = if block {
            "while parsing a block node"
        } else {
            "while parsing a flow node"
        };
        self.set_parser_error_context(
            context,
            start_mark,
            "did not find expected node content",
            token.start_mark,
        );
        false
    }

    fn parse_block_sequence_entry(&mut self, event: &mut Event, first: bool) -> bool {
        if first {
            let Some(token) = self.peek_token() else {
                return false;
            };
            self.marks.push(token.start_mark);
            self.skip_token();
        }
        let Some(mut token) = self.peek_token() else {
            return false;
        };
        if token.typ == TokenType::BlockEntry {
            let mark = token.end_mark;
            let prior_head_len = self.head_comment.len();
            self.skip_token();
            self.split_stem_comment(prior_head_len);
            match self.peek_token() {
                Some(t) => token = t,
                None => return false,
            }
            if token.typ != TokenType::BlockEntry && token.typ != TokenType::BlockEnd {
                self.states.push(State::BlockSequenceEntry);
                return self.parse_node(event, true, false);
            }
            self.state = State::BlockSequenceEntry;
            return self.process_empty_scalar(event, mark);
        }
        if token.typ == TokenType::BlockEnd {
            self.state = pop(&mut self.states);
            self.marks.pop();
            *event = Event {
                typ: EventType::SequenceEnd,
                start_mark: token.start_mark,
                end_mark: token.end_mark,
                ..Event::default()
            };
            self.skip_token();
            return true;
        }
        let context_mark = pop(&mut self.marks);
        self.set_parser_error_context(
            "while parsing a block collection",
            context_mark,
            "did not find expected '-' indicator",
            token.start_mark,
        )
    }

    fn parse_indentless_sequence_entry(&mut self, event: &mut Event) -> bool {
        let Some(mut token) = self.peek_token() else {
            return false;
        };
        if token.typ == TokenType::BlockEntry {
            let mark = token.end_mark;
            let prior_head_len = self.head_comment.len();
            self.skip_token();
            self.split_stem_comment(prior_head_len);
            match self.peek_token() {
                Some(t) => token = t,
                None => return false,
            }
            if token.typ != TokenType::BlockEntry
                && token.typ != TokenType::Key
                && token.typ != TokenType::Value
                && token.typ != TokenType::BlockEnd
            {
                self.states.push(State::IndentlessSequenceEntry);
                return self.parse_node(event, true, false);
            }
            self.state = State::IndentlessSequenceEntry;
            return self.process_empty_scalar(event, mark);
        }
        self.state = pop(&mut self.states);
        *event = Event {
            typ: EventType::SequenceEnd,
            start_mark: token.start_mark,
            end_mark: token.start_mark,
            ..Event::default()
        };
        true
    }

    /// Split stem comment from head comment: when a sequence or mapping is
    /// found under a sequence entry, the former head comment is assigned to
    /// the underlying sequence or mapping.
    fn split_stem_comment(&mut self, stem_len: usize) {
        if stem_len == 0 {
            return;
        }
        let Some(token) = self.peek_token() else {
            return;
        };
        if token.typ != TokenType::BlockSequenceStart && token.typ != TokenType::BlockMappingStart {
            return;
        }
        self.stem_comment = self.head_comment[..stem_len].to_vec();
        if self.head_comment.len() == stem_len {
            self.head_comment.clear();
        } else {
            // Copy suffix to prevent very strange bugs if someone ever
            // appends further bytes to the prefix in the stem_comment slice above.
            self.head_comment = self.head_comment[stem_len + 1..].to_vec();
        }
    }

    fn parse_block_mapping_key(&mut self, event: &mut Event, first: bool) -> bool {
        if first {
            let Some(token) = self.peek_token() else {
                return false;
            };
            self.marks.push(token.start_mark);
            self.skip_token();
        }
        let Some(mut token) = self.peek_token() else {
            return false;
        };
        // A tail comment was left from the prior mapping value processed. Emit an event
        //      as it needs to be processed with that value and not the following key.
        if !self.tail_comment.is_empty() {
            *event = Event {
                typ: EventType::TailComment,
                start_mark: token.start_mark,
                end_mark: token.end_mark,
                foot_comment: std::mem::take(&mut self.tail_comment),
                ..Event::default()
            };
            return true;
        }
        if token.typ == TokenType::Key {
            let mark = token.end_mark;
            self.skip_token();
            match self.peek_token() {
                Some(t) => token = t,
                None => return false,
            }
            if token.typ != TokenType::Key
                && token.typ != TokenType::Value
                && token.typ != TokenType::BlockEnd
            {
                self.states.push(State::BlockMappingValue);
                return self.parse_node(event, true, true);
            }
            self.state = State::BlockMappingValue;
            return self.process_empty_scalar(event, mark);
        } else if token.typ == TokenType::BlockEnd {
            self.state = pop(&mut self.states);
            self.marks.pop();
            *event = Event {
                typ: EventType::MappingEnd,
                start_mark: token.start_mark,
                end_mark: token.end_mark,
                ..Event::default()
            };
            self.set_event_comments(event);
            self.skip_token();
            return true;
        }
        let context_mark = pop(&mut self.marks);
        self.set_parser_error_context(
            "while parsing a block mapping",
            context_mark,
            "did not find expected key",
            token.start_mark,
        )
    }

    fn parse_block_mapping_value(&mut self, event: &mut Event) -> bool {
        let Some(mut token) = self.peek_token() else {
            return false;
        };
        if token.typ == TokenType::Value {
            let mark = token.end_mark;
            self.skip_token();
            match self.peek_token() {
                Some(t) => token = t,
                None => return false,
            }
            if token.typ != TokenType::Key
                && token.typ != TokenType::Value
                && token.typ != TokenType::BlockEnd
            {
                self.states.push(State::BlockMappingKey);
                return self.parse_node(event, true, true);
            }
            self.state = State::BlockMappingKey;
            return self.process_empty_scalar(event, mark);
        }
        self.state = State::BlockMappingKey;
        self.process_empty_scalar(event, token.start_mark)
    }

    fn parse_flow_sequence_entry(&mut self, event: &mut Event, first: bool) -> bool {
        if first {
            let Some(token) = self.peek_token() else {
                return false;
            };
            self.marks.push(token.start_mark);
            self.skip_token();
        }
        let Some(mut token) = self.peek_token() else {
            return false;
        };
        if token.typ != TokenType::FlowSequenceEnd {
            if !first {
                if token.typ == TokenType::FlowEntry {
                    self.skip_token();
                    match self.peek_token() {
                        Some(t) => token = t,
                        None => return false,
                    }
                } else {
                    let context_mark = pop(&mut self.marks);
                    return self.set_parser_error_context(
                        "while parsing a flow sequence",
                        context_mark,
                        "did not find expected ',' or ']'",
                        token.start_mark,
                    );
                }
            }
            if token.typ == TokenType::Key {
                self.state = State::FlowSequenceEntryMappingKey;
                *event = Event {
                    typ: EventType::MappingStart,
                    start_mark: token.start_mark,
                    end_mark: token.end_mark,
                    implicit: true,
                    style: EventStyle::Mapping(MappingStyle::Flow),
                    ..Event::default()
                };
                self.skip_token();
                return true;
            } else if token.typ != TokenType::FlowSequenceEnd {
                self.states.push(State::FlowSequenceEntry);
                return self.parse_node(event, false, false);
            }
        }
        self.state = pop(&mut self.states);
        self.marks.pop();
        *event = Event {
            typ: EventType::SequenceEnd,
            start_mark: token.start_mark,
            end_mark: token.end_mark,
            ..Event::default()
        };
        self.set_event_comments(event);
        self.skip_token();
        true
    }

    fn parse_flow_sequence_entry_mapping_key(&mut self, event: &mut Event) -> bool {
        let Some(token) = self.peek_token() else {
            return false;
        };
        if token.typ != TokenType::Value
            && token.typ != TokenType::FlowEntry
            && token.typ != TokenType::FlowSequenceEnd
        {
            self.states.push(State::FlowSequenceEntryMappingValue);
            return self.parse_node(event, false, false);
        }
        let mark = token.end_mark;
        self.skip_token();
        self.state = State::FlowSequenceEntryMappingValue;
        self.process_empty_scalar(event, mark)
    }

    fn parse_flow_sequence_entry_mapping_value(&mut self, event: &mut Event) -> bool {
        let Some(token) = self.peek_token() else {
            return false;
        };
        if token.typ == TokenType::Value {
            self.skip_token();
            let Some(token) = self.peek_token() else {
                return false;
            };
            if token.typ != TokenType::FlowEntry && token.typ != TokenType::FlowSequenceEnd {
                self.states.push(State::FlowSequenceEntryMappingEnd);
                return self.parse_node(event, false, false);
            }
        }
        self.state = State::FlowSequenceEntryMappingEnd;
        // The outer token's mark, as go-yaml's shadowed variable keeps it.
        self.process_empty_scalar(event, token.start_mark)
    }

    fn parse_flow_sequence_entry_mapping_end(&mut self, event: &mut Event) -> bool {
        let Some(token) = self.peek_token() else {
            return false;
        };
        self.state = State::FlowSequenceEntry;
        *event = Event {
            typ: EventType::MappingEnd,
            start_mark: token.start_mark,
            end_mark: token.start_mark,
            ..Event::default()
        };
        true
    }

    fn parse_flow_mapping_key(&mut self, event: &mut Event, first: bool) -> bool {
        if first {
            let token = self.peek_token().expect("go-yaml dereferences this token");
            self.marks.push(token.start_mark);
            self.skip_token();
        }
        let Some(mut token) = self.peek_token() else {
            return false;
        };
        if token.typ != TokenType::FlowMappingEnd {
            if !first {
                if token.typ == TokenType::FlowEntry {
                    self.skip_token();
                    match self.peek_token() {
                        Some(t) => token = t,
                        None => return false,
                    }
                } else {
                    let context_mark = pop(&mut self.marks);
                    return self.set_parser_error_context(
                        "while parsing a flow mapping",
                        context_mark,
                        "did not find expected ',' or '}'",
                        token.start_mark,
                    );
                }
            }
            if token.typ == TokenType::Key {
                self.skip_token();
                match self.peek_token() {
                    Some(t) => token = t,
                    None => return false,
                }
                if token.typ != TokenType::Value
                    && token.typ != TokenType::FlowEntry
                    && token.typ != TokenType::FlowMappingEnd
                {
                    self.states.push(State::FlowMappingValue);
                    return self.parse_node(event, false, false);
                }
                self.state = State::FlowMappingValue;
                return self.process_empty_scalar(event, token.start_mark);
            } else if token.typ != TokenType::FlowMappingEnd {
                self.states.push(State::FlowMappingEmptyValue);
                return self.parse_node(event, false, false);
            }
        }
        self.state = pop(&mut self.states);
        self.marks.pop();
        *event = Event {
            typ: EventType::MappingEnd,
            start_mark: token.start_mark,
            end_mark: token.end_mark,
            ..Event::default()
        };
        self.set_event_comments(event);
        self.skip_token();
        true
    }

    fn parse_flow_mapping_value(&mut self, event: &mut Event, empty: bool) -> bool {
        let Some(mut token) = self.peek_token() else {
            return false;
        };
        if empty {
            self.state = State::FlowMappingKey;
            return self.process_empty_scalar(event, token.start_mark);
        }
        if token.typ == TokenType::Value {
            self.skip_token();
            match self.peek_token() {
                Some(t) => token = t,
                None => return false,
            }
            if token.typ != TokenType::FlowEntry && token.typ != TokenType::FlowMappingEnd {
                self.states.push(State::FlowMappingKey);
                return self.parse_node(event, false, false);
            }
        }
        self.state = State::FlowMappingKey;
        self.process_empty_scalar(event, token.start_mark)
    }

    fn process_empty_scalar(&mut self, event: &mut Event, mark: Mark) -> bool {
        *event = Event {
            typ: EventType::Scalar,
            start_mark: mark,
            end_mark: mark,
            implicit: true,
            style: EventStyle::Scalar(ScalarStyle::Plain),
            ..Event::default()
        };
        true
    }

    fn process_directives(
        &mut self,
        version_directive_ref: Option<&mut Option<VersionDirective>>,
        tag_directives_ref: Option<&mut Vec<TagDirective>>,
    ) -> bool {
        let mut version_directive: Option<VersionDirective> = None;
        let mut tag_directives = Vec::new();
        let Some(mut token) = self.peek_token() else {
            return false;
        };
        while token.typ == TokenType::VersionDirective || token.typ == TokenType::TagDirective {
            if token.typ == TokenType::VersionDirective {
                if version_directive.is_some() {
                    self.set_parser_error("found duplicate %YAML directive", token.start_mark);
                    return false;
                }
                if token.major != 1 || token.minor != 1 {
                    self.set_parser_error("found incompatible YAML document", token.start_mark);
                    return false;
                }
                version_directive = Some(VersionDirective {
                    major: token.major,
                    minor: token.minor,
                });
            } else {
                let value = TagDirective {
                    handle: token.value.clone(),
                    prefix: token.prefix.clone(),
                };
                if !self.append_tag_directive(value.clone(), false, token.start_mark) {
                    return false;
                }
                tag_directives.push(value);
            }
            self.skip_token();
            match self.peek_token() {
                Some(t) => token = t,
                None => return false,
            }
        }
        let defaults = [
            TagDirective {
                handle: b"!".to_vec(),
                prefix: b"!".to_vec(),
            },
            TagDirective {
                handle: b"!!".to_vec(),
                prefix: b"tag:yaml.org,2002:".to_vec(),
            },
        ];
        for d in defaults {
            if !self.append_tag_directive(d, true, token.start_mark) {
                return false;
            }
        }
        if let Some(r) = version_directive_ref {
            *r = version_directive;
        }
        if let Some(r) = tag_directives_ref {
            *r = tag_directives;
        }
        true
    }

    fn append_tag_directive(
        &mut self,
        value: TagDirective,
        allow_duplicates: bool,
        mark: Mark,
    ) -> bool {
        if self.tag_directives.iter().any(|d| d.handle == value.handle) {
            if allow_duplicates {
                return true;
            }
            return self.set_parser_error("found duplicate %TAG directive", mark);
        }
        self.tag_directives.push(value);
        true
    }
}
