//! Builds node trees from events (the `parser` type of go-yaml's
//! decode.go), with its comment placement, anchors, and error texts.

use std::collections::HashMap;

use super::parser::Parser;
use super::resolve::{resolve, short_tag};
use super::types::{
    DOUBLE_QUOTED_STYLE, ErrorType, Event, EventType, FLOW_STYLE, FOLDED_STYLE, Kind,
    LITERAL_STYLE, MAP_TAG, MERGE_TAG, MappingStyle, Node, NodeId, SEQ_TAG, SINGLE_QUOTED_STYLE,
    STR_TAG, ScalarStyle, SequenceStyle, TAGGED_STYLE, Tree,
};

/// Reads documents into nodes of one tree. Anchors stay known across the
/// documents of a stream, as in go-yaml.
pub struct Composer {
    parser: Parser,
    event: Event,
    pub tree: Tree,
    anchors: HashMap<String, NodeId>,
    done_init: bool,
    /// Leave lines, columns, and comments out of the nodes.
    pub textless: bool,
}

/// Bytes as a string, each invalid UTF-8 byte replaced by U+FFFD (only a
/// tag spelled with %-escapes can hold such bytes).
fn text(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => {
            let mut out = String::new();
            let mut rest = b;
            while !rest.is_empty() {
                match std::str::from_utf8(rest) {
                    Ok(s) => {
                        out.push_str(s);
                        break;
                    }
                    Err(e) => {
                        let good = e.valid_up_to();
                        out.push_str(std::str::from_utf8(&rest[..good]).expect("valid prefix"));
                        out.push('\u{fffd}');
                        rest = &rest[good + 1..];
                    }
                }
            }
            out
        }
    }
}

impl Composer {
    fn with_input(data: Vec<u8>) -> Composer {
        let mut parser = Parser::new();
        parser.set_input_string(data);
        Composer {
            parser,
            event: Event::default(),
            tree: Tree::default(),
            anchors: HashMap::new(),
            done_init: false,
            textless: false,
        }
    }

    /// newParser: a composer of a string; an empty one reads as "\n".
    pub fn new(data: &[u8]) -> Composer {
        if data.is_empty() {
            return Composer::with_input(b"\n".to_vec());
        }
        Composer::with_input(data.to_vec())
    }

    /// newParserFromReader: a composer of a reader's bytes, as
    /// yaml.NewDecoder reads them.
    pub fn from_reader(data: &[u8]) -> Composer {
        Composer::with_input(data.to_vec())
    }

    fn fail(&self) -> String {
        let p = &self.parser;
        let mut line = 0;
        if p.context_mark.line != 0 {
            line = p.context_mark.line;
            // Scanner errors don't iterate line before returning error
            if p.error == ErrorType::Scanner {
                line += 1;
            }
        } else if p.problem_mark.line != 0 {
            line = p.problem_mark.line;
            if p.error == ErrorType::Scanner {
                line += 1;
            }
        }
        let place = if line != 0 {
            format!("line {line}: ")
        } else {
            String::new()
        };
        let msg = if p.problem.is_empty() {
            "unknown problem parsing YAML content"
        } else {
            &p.problem
        };
        format!("yaml: {place}{msg}")
    }

    fn expect(&mut self, e: EventType) -> Result<(), String> {
        if self.event.typ == EventType::NoEvent && !self.parser.parse(&mut self.event) {
            return Err(self.fail());
        }
        if self.event.typ == EventType::StreamEnd {
            return Err(
                "yaml: attempted to go past the end of stream; corrupted value?".to_string(),
            );
        }
        if self.event.typ != e {
            self.parser.problem = format!(
                "expected {} event but got {}",
                e.name(),
                self.event.typ.name()
            );
            return Err(self.fail());
        }
        self.event = Event::default();
        Ok(())
    }

    fn peek(&mut self) -> Result<EventType, String> {
        if self.event.typ != EventType::NoEvent {
            return Ok(self.event.typ);
        }
        // It's curious choice from the underlying API to generally return a
        // positive result on success, but on this case return true in an error
        // scenario. This was the source of bugs in the past (issue #666).
        if !self.parser.parse(&mut self.event) || self.parser.error != ErrorType::None {
            return Err(self.fail());
        }
        Ok(self.event.typ)
    }

    /// The next document's node (or a node, inside one), None at the
    /// stream's end, or the error go-yaml gives.
    pub fn parse(&mut self) -> Result<Option<NodeId>, String> {
        if !self.done_init {
            self.expect(EventType::StreamStart)?;
            self.done_init = true;
        }
        match self.peek()? {
            EventType::Scalar => self.scalar().map(Some),
            EventType::Alias => self.alias().map(Some),
            EventType::MappingStart => self.mapping().map(Some),
            EventType::SequenceStart => self.sequence().map(Some),
            EventType::DocumentStart => self.document().map(Some),
            EventType::StreamEnd => Ok(None),
            EventType::TailComment => {
                Err("internal error: unexpected tail comment event (please report)".to_string())
            }
            t => Err(format!(
                "internal error: attempted to parse unknown event (please report): {}",
                t.name()
            )),
        }
    }

    fn node(&mut self, kind: Kind, default_tag: &str, tag: &str, value: &str) -> NodeId {
        let mut style = 0;
        let tag = if !tag.is_empty() && tag != "!" {
            style = TAGGED_STYLE;
            short_tag(tag)
        } else if !default_tag.is_empty() {
            default_tag.to_string()
        } else if kind == Kind::Scalar {
            resolve("", value).map(|(t, _)| t).unwrap_or_default()
        } else {
            tag.to_string()
        };
        let mut n = Node {
            kind,
            tag,
            value: value.to_string(),
            style,
            ..Node::default()
        };
        if !self.textless {
            n.line = self.event.start_mark.line.wrapping_add(1);
            n.column = self.event.start_mark.column.wrapping_add(1);
            n.head_comment = text(&self.event.head_comment);
            n.line_comment = text(&self.event.line_comment);
            n.foot_comment = text(&self.event.foot_comment);
        }
        self.tree.add(n)
    }

    fn parse_child(&mut self, parent: NodeId) -> Result<NodeId, String> {
        let child = match self.parse()? {
            Some(c) => c,
            None => {
                return Err(
                    "yaml: attempted to go past the end of stream; corrupted value?".to_string(),
                );
            }
        };
        self.tree.get_mut(parent).content.push(child);
        Ok(child)
    }

    fn set_anchor(&mut self, n: NodeId, anchor: &[u8]) {
        if !anchor.is_empty() {
            let name = text(anchor);
            self.tree.get_mut(n).anchor = name.clone();
            self.anchors.insert(name, n);
        }
    }

    fn document(&mut self) -> Result<NodeId, String> {
        let n = self.node(Kind::Document, "", "", "");
        self.expect(EventType::DocumentStart)?;
        self.parse_child(n)?;
        if self.peek()? == EventType::DocumentEnd {
            self.tree.get_mut(n).foot_comment = text(&self.event.foot_comment);
        }
        self.expect(EventType::DocumentEnd)?;
        Ok(n)
    }

    fn alias(&mut self) -> Result<NodeId, String> {
        let anchor = text(&self.event.anchor);
        let n = self.node(Kind::Alias, "", "", &anchor);
        match self.anchors.get(&anchor) {
            Some(&target) => self.tree.get_mut(n).alias = Some(target),
            None => return Err(format!("yaml: unknown anchor '{anchor}' referenced")),
        }
        self.expect(EventType::Alias)?;
        Ok(n)
    }

    fn scalar(&mut self) -> Result<NodeId, String> {
        let node_style = match self.event.scalar_style() {
            ScalarStyle::DoubleQuoted => DOUBLE_QUOTED_STYLE,
            ScalarStyle::SingleQuoted => SINGLE_QUOTED_STYLE,
            ScalarStyle::Literal => LITERAL_STYLE,
            ScalarStyle::Folded => FOLDED_STYLE,
            _ => 0,
        };
        let value = text(&self.event.value);
        let tag = text(&self.event.tag);
        let default_tag = if node_style == 0 {
            if value == "<<" { MERGE_TAG } else { "" }
        } else {
            STR_TAG
        };
        let n = self.node(Kind::Scalar, default_tag, &tag, &value);
        self.tree.get_mut(n).style |= node_style;
        let anchor = std::mem::take(&mut self.event.anchor);
        self.set_anchor(n, &anchor);
        self.expect(EventType::Scalar)?;
        Ok(n)
    }

    fn sequence(&mut self) -> Result<NodeId, String> {
        let tag = text(&self.event.tag);
        let n = self.node(Kind::Sequence, SEQ_TAG, &tag, "");
        if self.event.sequence_style() == SequenceStyle::Flow {
            self.tree.get_mut(n).style |= FLOW_STYLE;
        }
        let anchor = std::mem::take(&mut self.event.anchor);
        self.set_anchor(n, &anchor);
        self.expect(EventType::SequenceStart)?;
        while self.peek()? != EventType::SequenceEnd {
            self.parse_child(n)?;
        }
        let node = self.tree.get_mut(n);
        node.line_comment = text(&self.event.line_comment);
        node.foot_comment = text(&self.event.foot_comment);
        self.expect(EventType::SequenceEnd)?;
        Ok(n)
    }

    fn mapping(&mut self) -> Result<NodeId, String> {
        let tag = text(&self.event.tag);
        let n = self.node(Kind::Mapping, MAP_TAG, &tag, "");
        let mut block = true;
        if self.event.mapping_style() == MappingStyle::Flow {
            block = false;
            self.tree.get_mut(n).style |= FLOW_STYLE;
        }
        let anchor = std::mem::take(&mut self.event.anchor);
        self.set_anchor(n, &anchor);
        self.expect(EventType::MappingStart)?;
        while self.peek()? != EventType::MappingEnd {
            let k = self.parse_child(n)?;
            if block && !self.tree.get(k).foot_comment.is_empty() {
                // Must be a foot comment for the prior value when being dedented.
                let len = self.tree.get(n).content.len();
                if len > 2 {
                    let prior = self.tree.get(n).content[len - 3];
                    let foot = std::mem::take(&mut self.tree.get_mut(k).foot_comment);
                    self.tree.get_mut(prior).foot_comment = foot;
                }
            }
            let v = self.parse_child(n)?;
            if self.tree.get(k).foot_comment.is_empty() && !self.tree.get(v).foot_comment.is_empty()
            {
                let foot = std::mem::take(&mut self.tree.get_mut(v).foot_comment);
                self.tree.get_mut(k).foot_comment = foot;
            }
            if self.peek()? == EventType::TailComment {
                if self.tree.get(k).foot_comment.is_empty() {
                    self.tree.get_mut(k).foot_comment = text(&self.event.foot_comment);
                }
                self.expect(EventType::TailComment)?;
            }
        }
        let line = text(&self.event.line_comment);
        let foot = text(&self.event.foot_comment);
        let node = self.tree.get_mut(n);
        node.line_comment = line;
        node.foot_comment = foot;
        if node.style & FLOW_STYLE == 0 && !node.foot_comment.is_empty() && node.content.len() > 1 {
            let key = node.content[node.content.len() - 2];
            let foot = std::mem::take(&mut node.foot_comment);
            self.tree.get_mut(key).foot_comment = foot;
        }
        self.expect(EventType::MappingEnd)?;
        Ok(n)
    }
}
