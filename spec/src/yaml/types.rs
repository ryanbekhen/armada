//! The types the YAML reader, scanner, parser, composer, and emitter share:
//! go-yaml v3's events (yamlh.go) and nodes (yaml.go), with the same
//! fields, so the code ported from it keeps its shape.

/// A position in the input: byte index, line, and column, all from 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mark {
    pub index: usize,
    pub line: usize,
    pub column: usize,
}

/// The input's or output's encoding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Encoding {
    #[default]
    Any,
    Utf8,
    Utf16Le,
    Utf16Be,
}

/// The kinds of errors go-yaml's parser and emitter record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ErrorType {
    #[default]
    None,
    Memory,
    Reader,
    Scanner,
    Parser,
    Composer,
    Writer,
    Emitter,
}

/// Scalar styles (yaml_scalar_style_t).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ScalarStyle {
    #[default]
    Any,
    Plain,
    SingleQuoted,
    DoubleQuoted,
    Literal,
    Folded,
}

/// Sequence styles (yaml_sequence_style_t).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SequenceStyle {
    #[default]
    Any,
    Block,
    Flow,
}

/// Mapping styles (yaml_mapping_style_t).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MappingStyle {
    #[default]
    Any,
    Block,
    Flow,
}

/// Event types (yaml_event_type_t).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EventType {
    #[default]
    NoEvent,
    StreamStart,
    StreamEnd,
    DocumentStart,
    DocumentEnd,
    Alias,
    Scalar,
    SequenceStart,
    SequenceEnd,
    MappingStart,
    MappingEnd,
    TailComment,
}

impl EventType {
    /// The name go-yaml prints for the event type (eventStrings).
    pub fn name(self) -> &'static str {
        match self {
            EventType::NoEvent => "none",
            EventType::StreamStart => "stream start",
            EventType::StreamEnd => "stream end",
            EventType::DocumentStart => "document start",
            EventType::DocumentEnd => "document end",
            EventType::Alias => "alias",
            EventType::Scalar => "scalar",
            EventType::SequenceStart => "sequence start",
            EventType::SequenceEnd => "sequence end",
            EventType::MappingStart => "mapping start",
            EventType::MappingEnd => "mapping end",
            EventType::TailComment => "tail comment",
        }
    }
}

/// A %TAG directive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TagDirective {
    pub handle: Vec<u8>,
    pub prefix: Vec<u8>,
}

/// A %YAML directive's version.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VersionDirective {
    pub major: i8,
    pub minor: i8,
}

/// The style of a scalar, sequence, or mapping event (yaml_style_t): which
/// one applies depends on the event's type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EventStyle {
    #[default]
    Any,
    Scalar(ScalarStyle),
    Sequence(SequenceStyle),
    Mapping(MappingStyle),
}

/// An event (yaml_event_t). An empty anchor or tag means none, as a nil
/// slice does in go-yaml.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Event {
    pub typ: EventType,
    pub start_mark: Mark,
    pub end_mark: Mark,
    pub encoding: Encoding,
    pub version_directive: Option<VersionDirective>,
    pub tag_directives: Vec<TagDirective>,
    pub head_comment: Vec<u8>,
    pub line_comment: Vec<u8>,
    pub foot_comment: Vec<u8>,
    pub tail_comment: Vec<u8>,
    pub anchor: Vec<u8>,
    pub tag: Vec<u8>,
    pub value: Vec<u8>,
    pub implicit: bool,
    pub quoted_implicit: bool,
    pub style: EventStyle,
}

impl Event {
    pub fn scalar_style(&self) -> ScalarStyle {
        match self.style {
            EventStyle::Scalar(s) => s,
            _ => ScalarStyle::Any,
        }
    }
    pub fn sequence_style(&self) -> SequenceStyle {
        match self.style {
            EventStyle::Sequence(s) => s,
            _ => SequenceStyle::Any,
        }
    }
    pub fn mapping_style(&self) -> MappingStyle {
        match self.style {
            EventStyle::Mapping(s) => s,
            _ => MappingStyle::Any,
        }
    }
}

/// A node's kind (yaml.Kind); Zero is the kind of a zero Node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    #[default]
    Zero,
    Document,
    Sequence,
    Mapping,
    Scalar,
    Alias,
}

impl Kind {
    /// The number go-yaml gives the kind (1 << iota from DocumentNode).
    pub fn number(self) -> u32 {
        match self {
            Kind::Zero => 0,
            Kind::Document => 1,
            Kind::Sequence => 2,
            Kind::Mapping => 4,
            Kind::Scalar => 8,
            Kind::Alias => 16,
        }
    }
}

/// Node style bits (yaml.Style).
pub const TAGGED_STYLE: u32 = 1;
pub const DOUBLE_QUOTED_STYLE: u32 = 2;
pub const SINGLE_QUOTED_STYLE: u32 = 4;
pub const LITERAL_STYLE: u32 = 8;
pub const FOLDED_STYLE: u32 = 16;
pub const FLOW_STYLE: u32 = 32;

/// An index into a Tree's nodes.
pub type NodeId = usize;

/// A node (yaml.Node). Children and alias targets are indices into the
/// Tree that holds it, so an alias shares its anchor's node as a pointer
/// does in go-yaml.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Node {
    pub kind: Kind,
    pub style: u32,
    pub tag: String,
    pub value: String,
    pub anchor: String,
    pub alias: Option<NodeId>,
    pub content: Vec<NodeId>,
    pub head_comment: String,
    pub line_comment: String,
    pub foot_comment: String,
    pub line: usize,
    pub column: usize,
}

/// The nodes of one parser's documents.
#[derive(Clone, Debug, Default)]
pub struct Tree {
    pub nodes: Vec<Node>,
}

impl Tree {
    pub fn add(&mut self, n: Node) -> NodeId {
        self.nodes.push(n);
        self.nodes.len() - 1
    }
    pub fn get(&self, id: NodeId) -> &Node {
        &self.nodes[id]
    }
    pub fn get_mut(&mut self, id: NodeId) -> &mut Node {
        &mut self.nodes[id]
    }
}

/// Short tags (resolve.go).
pub const NULL_TAG: &str = "!!null";
pub const BOOL_TAG: &str = "!!bool";
pub const STR_TAG: &str = "!!str";
pub const INT_TAG: &str = "!!int";
pub const FLOAT_TAG: &str = "!!float";
pub const TIMESTAMP_TAG: &str = "!!timestamp";
pub const SEQ_TAG: &str = "!!seq";
pub const MAP_TAG: &str = "!!map";
pub const BINARY_TAG: &str = "!!binary";
pub const MERGE_TAG: &str = "!!merge";
