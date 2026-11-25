//! Decoding YAML nodes into spec types as go-yaml v3's decoder does
//! (decode.go): the same order of checks, type errors collected with Go's
//! texts and Go's type names, fatal errors where Go panics, aliases,
//! merge keys, duplicate keys, and strict fields. The UnmarshalYAML
//! methods of internal/spec are here too, decodeStrict included: it
//! encodes the node again and decodes that text, so its errors count lines
//! the way Go's do.

use std::collections::{BTreeMap, HashSet};

use crate::go::{self, quote};
use crate::spec::*;
use crate::yaml::compose::Composer;
use crate::yaml::encode::encode_node;
use crate::yaml::resolve::{Resolved, resolve, short_tag};
use crate::yaml::types::*;

/// A fatal error (a panic in go-yaml), with Go's text.
pub(crate) type R<T> = Result<T, String>;

/// A value a key decodes to when go-yaml decodes into interface{}, as a
/// key of its mergedFields set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
enum Key {
    #[default]
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    /// The bits of a float; NaN never equals itself in Go, so each NaN gets
    /// a key of its own.
    Float(u64),
    Nan(usize),
    Str(String),
    Time(String),
    /// A map or slice, which Go cannot hash; the type's name.
    Unhashable(String),
}

pub(crate) struct Decoder<'t> {
    tree: &'t Tree,
    pub(crate) terrors: Vec<String>,
    known_fields: bool,
    aliases: HashSet<NodeId>,
    decode_count: u64,
    alias_count: u64,
    alias_depth: u64,
    merged_fields: Option<HashSet<Key>>,
    nans: usize,
}

pub(crate) trait Decode: Default {
    /// The Go type's name in type errors.
    fn type_name() -> String;

    /// UnmarshalYAML, for the types that have one; None otherwise.
    fn custom(_d: &mut Decoder, _id: NodeId, _out: &mut Self) -> Option<R<bool>> {
        None
    }

    /// prepare, then the node's kind: Option<T> (a pointer) allocates here.
    fn prepared(d: &mut Decoder, id: NodeId, out: &mut Self, null: bool) -> R<bool> {
        if !null && let Some(r) = Self::custom(d, id, out) {
            return r;
        }
        d.dispatch(id, out)
    }

    fn scalar(d: &mut Decoder, id: NodeId, out: &mut Self) -> R<bool> {
        let (tag, res) = d.resolved(id)?;
        if res == Resolved::Null {
            return Ok(Self::null(out));
        }
        d.terror(id, &tag, &Self::type_name());
        Ok(false)
    }

    fn mapping(d: &mut Decoder, id: NodeId, _out: &mut Self) -> R<bool> {
        d.terror(id, MAP_TAG, &Self::type_name());
        Ok(false)
    }

    fn sequence(d: &mut Decoder, id: NodeId, _out: &mut Self) -> R<bool> {
        d.terror(id, SEQ_TAG, &Self::type_name());
        Ok(false)
    }

    /// decoder.null: only pointers, maps, slices, and interfaces are set.
    fn null(_out: &mut Self) -> bool {
        false
    }
}

const ALIAS_RATIO_RANGE_LOW: u64 = 400_000;
const ALIAS_RATIO_RANGE_HIGH: u64 = 4_000_000;

fn allowed_alias_ratio(decode_count: u64) -> f64 {
    if decode_count <= ALIAS_RATIO_RANGE_LOW {
        0.99
    } else if decode_count >= ALIAS_RATIO_RANGE_HIGH {
        0.10
    } else {
        0.99 - 0.89
            * ((decode_count - ALIAS_RATIO_RANGE_LOW) as f64
                / (ALIAS_RATIO_RANGE_HIGH - ALIAS_RATIO_RANGE_LOW) as f64)
    }
}

/// 2^63 as a float.
const TWO63: f64 = 9_223_372_036_854_775_808.0;

/// Go's conversion of a float64 to int64 on amd64: out of range is MinInt64.
fn float_to_int(f: f64) -> i64 {
    if f.is_nan() || !(-TWO63..TWO63).contains(&f) {
        i64::MIN
    } else {
        f as i64
    }
}

/// base64.StdEncoding.DecodeString, which skips line breaks.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = s.bytes().filter(|&c| c != b'\n' && c != b'\r').collect();
    if !clean.len().is_multiple_of(4) {
        return None;
    }
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };
    let mut out = Vec::new();
    let chunks = clean.len() / 4;
    for (i, q) in clean.chunks(4).enumerate() {
        let last = i + 1 == chunks;
        let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &q[..4 - pad] {
            n = n << 6 | val(c)?;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

/// What decodeStrict and Node.Decode give back: type errors (a TypeError)
/// or a fatal error.
pub(crate) enum DecodeError {
    Type(Vec<String>),
    Fatal(String),
}

impl<'t> Decoder<'t> {
    pub(crate) fn new(tree: &'t Tree, known_fields: bool) -> Decoder<'t> {
        Decoder {
            tree,
            terrors: Vec::new(),
            known_fields,
            aliases: HashSet::new(),
            decode_count: 0,
            alias_count: 0,
            alias_depth: 0,
            merged_fields: None,
            nans: 0,
        }
    }

    fn node(&self, id: NodeId) -> &'t Node {
        self.tree.get(id)
    }

    /// decoder.terror.
    pub(crate) fn terror(&mut self, id: NodeId, tag: &str, typ: &str) {
        let n = self.node(id);
        let tag = if n.tag.is_empty() {
            tag.to_string()
        } else {
            n.tag.clone()
        };
        let mut value = String::new();
        if tag != SEQ_TAG && tag != MAP_TAG {
            let b = n.value.as_bytes();
            if b.len() > 10 {
                value = format!(" `{}...`", go::lossy(&b[..7]));
            } else {
                value = format!(" `{}`", n.value);
            }
        }
        self.terrors.push(format!(
            "line {}: cannot unmarshal {}{} into {}",
            n.line,
            short_tag(&tag),
            value,
            typ
        ));
    }

    /// decoder.unmarshal.
    pub(crate) fn unmarshal<T: Decode>(&mut self, id: NodeId, out: &mut T) -> R<bool> {
        self.decode_count += 1;
        if self.alias_depth > 0 {
            self.alias_count += 1;
        }
        if self.alias_count > 100
            && self.decode_count > 1000
            && self.alias_count as f64 / self.decode_count as f64
                > allowed_alias_ratio(self.decode_count)
        {
            return Err("yaml: document contains excessive aliasing".to_string());
        }
        let n = self.node(id);
        match n.kind {
            Kind::Document => {
                if n.content.len() == 1 {
                    self.unmarshal(n.content[0], out)?;
                    return Ok(true);
                }
                return Ok(false);
            }
            Kind::Alias => {
                if self.aliases.contains(&id) {
                    return Err(format!("yaml: anchor '{}' value contains itself", n.value));
                }
                self.aliases.insert(id);
                self.alias_depth += 1;
                let target = n.alias.expect("an alias node has its anchor");
                let good = self.unmarshal(target, out);
                self.alias_depth -= 1;
                self.aliases.remove(&id);
                return good;
            }
            _ => {}
        }
        let null = self.tree.short_tag(id) == NULL_TAG;
        T::prepared(self, id, out, null)
    }

    /// The kind switch of decoder.unmarshal, after prepare.
    pub(crate) fn dispatch<T: Decode>(&mut self, id: NodeId, out: &mut T) -> R<bool> {
        let n = self.node(id);
        match n.kind {
            Kind::Scalar => T::scalar(self, id, out),
            Kind::Mapping => {
                if self.duplicate_keys(id) {
                    return Ok(false);
                }
                T::mapping(self, id, out)
            }
            Kind::Sequence => T::sequence(self, id, out),
            Kind::Zero if n.is_zero() => Ok(T::null(out)),
            k => Err(format!(
                "yaml: cannot decode node with unknown kind {}",
                k.number()
            )),
        }
    }

    /// The uniqueKeys check at the start of decoder.mapping.
    fn duplicate_keys(&mut self, id: NodeId) -> bool {
        let n = self.node(id);
        let before = self.terrors.len();
        let l = n.content.len();
        let mut i = 0;
        while i < l {
            let ni = self.node(n.content[i]);
            let mut j = i + 2;
            while j < l {
                let nj = self.node(n.content[j]);
                if ni.kind == nj.kind && ni.value == nj.value {
                    self.terrors.push(format!(
                        "line {}: mapping key {} already defined at line {}",
                        nj.line,
                        quote(&nj.value),
                        ni.line
                    ));
                }
                j += 2;
            }
            i += 2;
        }
        self.terrors.len() > before
    }

    /// The tag and value decoder.scalar works with.
    pub(crate) fn resolved(&mut self, id: NodeId) -> R<(String, Resolved)> {
        let n = self.node(id);
        if self.tree.indicated_string(id) {
            return Ok((STR_TAG.to_string(), Resolved::Str(n.value.clone())));
        }
        let (tag, res) = resolve(&n.tag, &n.value)?;
        if tag == BINARY_TAG {
            let Resolved::Str(s) = &res else {
                return Ok((tag, res));
            };
            let data =
                base64_decode(s).ok_or("yaml: !!binary value contains invalid base64 data")?;
            return Ok((tag, Resolved::Str(go::lossy(&data))));
        }
        Ok((tag, res))
    }

    fn is_merge(&self, id: NodeId) -> bool {
        let n = self.node(id);
        n.kind == Kind::Scalar
            && n.value == "<<"
            && (n.tag.is_empty() || n.tag == "!" || short_tag(&n.tag) == MERGE_TAG)
    }

    fn key_of(&mut self, k: Key) -> R<Key> {
        if let Key::Unhashable(t) = &k {
            return Err(format!("yaml: runtime error: hash of unhashable type {t}"));
        }
        Ok(k)
    }

    /// decoder.mappingStruct.
    fn mapping_struct<T: Fields + Decode>(
        &mut self,
        id: NodeId,
        out: &mut T,
        name: &str,
    ) -> R<bool> {
        let mut merged = self.merged_fields.take();
        let mut done = vec![false; T::KEYS.len()];
        let mut merge_node = None;
        let content = self.node(id).content.clone();
        let mut i = 0;
        while i + 1 < content.len() + 1 && i < content.len() {
            let (ki, vi) = (content[i], content[i + 1]);
            i += 2;
            if self.is_merge(ki) {
                merge_node = Some(vi);
                continue;
            }
            let mut key = String::new();
            if !self.unmarshal(ki, &mut key)? {
                continue;
            }
            if let Some(m) = &mut merged {
                let k = Key::Str(key.clone());
                if m.contains(&k) {
                    continue;
                }
                m.insert(k);
            }
            if let Some(idx) = T::KEYS.iter().position(|k| *k == key) {
                if done[idx] {
                    let line = self.node(ki).line;
                    self.terrors.push(format!(
                        "line {line}: field {key} already set in type {name}"
                    ));
                    continue;
                }
                done[idx] = true;
                out.set(self, idx, vi)?;
            } else if self.known_fields {
                let line = self.node(ki).line;
                self.terrors
                    .push(format!("line {line}: field {key} not found in type {name}"));
            }
        }
        self.merged_fields = merged;
        if let Some(m) = merge_node {
            self.merge(id, m, out)?;
        }
        Ok(true)
    }

    /// decoder.merge.
    fn merge<T: Decode>(&mut self, parent: NodeId, merge: NodeId, out: &mut T) -> R<()> {
        let saved = self.merged_fields.clone();
        if saved.is_none() {
            self.merged_fields = Some(HashSet::new());
            let keys: Vec<NodeId> = self
                .node(parent)
                .content
                .iter()
                .copied()
                .step_by(2)
                .collect();
            for k in keys {
                let mut v = Iface::default();
                if self.unmarshal(k, &mut v)? {
                    let key = self.key_of(v.0)?;
                    if let Some(m) = &mut self.merged_fields {
                        m.insert(key);
                    }
                }
            }
        }
        let want_map =
            || Err("yaml: map merge requires map or sequence of maps as the value".to_string());
        let m = self.node(merge);
        match m.kind {
            Kind::Mapping => {
                self.unmarshal(merge, out)?;
            }
            Kind::Alias => {
                if let Some(a) = m.alias
                    && self.node(a).kind != Kind::Mapping
                {
                    return want_map();
                }
                self.unmarshal(merge, out)?;
            }
            Kind::Sequence => {
                for ni in m.content.clone() {
                    let n = self.node(ni);
                    if n.kind == Kind::Alias {
                        if let Some(a) = n.alias
                            && self.node(a).kind != Kind::Mapping
                        {
                            return want_map();
                        }
                    } else if n.kind != Kind::Mapping {
                        return want_map();
                    }
                    self.unmarshal(ni, out)?;
                }
            }
            _ => return want_map(),
        }
        self.merged_fields = saved;
        Ok(())
    }

    /// decoder.mapping into a map[string]V, V decoded by D.
    fn mapping_map<D: Decode + Into<V> + From<V>, V: Default>(
        &mut self,
        id: NodeId,
        out: &mut BTreeMap<String, V>,
    ) -> R<bool> {
        let merged = self.merged_fields.take();
        let mut merged = merged;
        let map_is_new = out.is_empty();
        let mut merge_node = None;
        let content = self.node(id).content.clone();
        let mut i = 0;
        while i < content.len() {
            let (ki, vi) = (content[i], content[i + 1]);
            i += 2;
            if self.is_merge(ki) {
                merge_node = Some(vi);
                continue;
            }
            let mut key = String::new();
            if self.unmarshal(ki, &mut key)? {
                if let Some(m) = &mut merged {
                    let k = Key::Str(key.clone());
                    if m.contains(&k) {
                        continue;
                    }
                    m.insert(k);
                }
                let mut e = D::default();
                let good = self.unmarshal(vi, &mut e)?;
                if good
                    || (self.tree.short_tag(vi) == NULL_TAG
                        && (map_is_new || !out.contains_key(&key)))
                {
                    out.insert(key, e.into());
                }
            }
        }
        self.merged_fields = merged;
        if let Some(m) = merge_node {
            let mut wrapped = MapOf::<D, V>(std::mem::take(out), std::marker::PhantomData);
            self.merge(id, m, &mut wrapped)?;
            *out = wrapped.0;
        }
        Ok(true)
    }

    /// decodeStrict: the node encoded again and decoded from that text
    /// with unknown fields refused.
    pub(crate) fn decode_strict<T: Decode>(&self, id: NodeId) -> Result<T, DecodeError> {
        let text = encode_node(self.tree, id, None).map_err(DecodeError::Fatal)?;
        let mut c = Composer::from_reader(&text);
        let doc = match c.parse() {
            Err(e) => return Err(DecodeError::Fatal(e)),
            Ok(None) => return Err(DecodeError::Fatal("EOF".to_string())),
            Ok(Some(doc)) => doc,
        };
        let mut d = Decoder::new(&c.tree, true);
        let mut v = T::default();
        d.unmarshal(doc, &mut v).map_err(DecodeError::Fatal)?;
        if !d.terrors.is_empty() {
            return Err(DecodeError::Type(d.terrors));
        }
        Ok(v)
    }

    /// Node.Decode: a fresh decoder on the same node.
    fn node_decode<T: Decode>(&self, id: NodeId) -> Result<T, DecodeError> {
        let mut d = Decoder::new(self.tree, false);
        let mut v = T::default();
        d.unmarshal(id, &mut v).map_err(DecodeError::Fatal)?;
        if !d.terrors.is_empty() {
            return Err(DecodeError::Type(d.terrors));
        }
        Ok(v)
    }

    /// callUnmarshaler: type errors are kept and the value is not good.
    fn call_unmarshaler<T>(&mut self, r: Result<T, DecodeError>, out: &mut T) -> R<bool> {
        match r {
            Ok(v) => {
                *out = v;
                Ok(true)
            }
            Err(DecodeError::Type(errs)) => {
                self.terrors.extend(errs);
                Ok(false)
            }
            Err(DecodeError::Fatal(e)) => Err(e),
        }
    }
}

/// A map[string]V seen as one value, for merges into maps.
#[derive(Default)]
struct MapOf<D, V>(BTreeMap<String, V>, std::marker::PhantomData<D>);

impl<D: Decode + Into<V> + From<V>, V: Default> Decode for MapOf<D, V> {
    fn type_name() -> String {
        format!("map[string]{}", D::type_name())
    }
    fn mapping(d: &mut Decoder, id: NodeId, out: &mut Self) -> R<bool> {
        d.mapping_map::<D, V>(id, &mut out.0)
    }
    fn null(out: &mut Self) -> bool {
        out.0.clear();
        true
    }
}

/// interface{}: what merge keys decode to.
#[derive(Default)]
struct Iface(Key);

impl Decode for Iface {
    fn type_name() -> String {
        "interface {}".to_string()
    }
    fn scalar(d: &mut Decoder, id: NodeId, out: &mut Self) -> R<bool> {
        let (_, res) = d.resolved(id)?;
        out.0 = match res {
            Resolved::Null => Key::Null,
            Resolved::Bool(b) => Key::Bool(b),
            Resolved::Int(i) => Key::Int(i),
            Resolved::Uint(u) => Key::Uint(u),
            Resolved::Float(f) if f.is_nan() => {
                d.nans += 1;
                Key::Nan(d.nans)
            }
            Resolved::Float(f) => Key::Float(if f == 0.0 { 0 } else { f.to_bits() }),
            Resolved::Str(s) => Key::Str(s),
            Resolved::Timestamp(t) => Key::Time(t),
        };
        Ok(true)
    }
    fn mapping(d: &mut Decoder, id: NodeId, out: &mut Self) -> R<bool> {
        let n = d.node(id);
        let string_map = n.content.iter().step_by(2).all(|&k| {
            let t = d.tree.short_tag(k);
            t == STR_TAG || t == MERGE_TAG
        });
        let content = n.content.clone();
        let mut i = 0;
        while i + 1 < content.len() {
            let mut k = Iface::default();
            if d.unmarshal(content[i], &mut k)? {
                let mut v = Iface::default();
                d.unmarshal(content[i + 1], &mut v)?;
            }
            i += 2;
        }
        out.0 = Key::Unhashable(
            if string_map {
                "map[string]interface {}"
            } else {
                "map[interface {}]interface {}"
            }
            .to_string(),
        );
        Ok(true)
    }
    fn sequence(d: &mut Decoder, id: NodeId, out: &mut Self) -> R<bool> {
        for c in d.node(id).content.clone() {
            let mut v = Iface::default();
            d.unmarshal(c, &mut v)?;
        }
        out.0 = Key::Unhashable("[]interface {}".to_string());
        Ok(true)
    }
    fn null(out: &mut Self) -> bool {
        out.0 = Key::Null;
        true
    }
}

impl Decode for String {
    fn type_name() -> String {
        "string".to_string()
    }
    fn scalar(d: &mut Decoder, id: NodeId, out: &mut Self) -> R<bool> {
        let (tag, res) = d.resolved(id)?;
        match res {
            Resolved::Null => Ok(false),
            Resolved::Str(s) if tag == BINARY_TAG => {
                *out = s;
                Ok(true)
            }
            _ => {
                *out = d.node(id).value.clone();
                Ok(true)
            }
        }
    }
}

/// The scalar cases of decoder.scalar for a signed integer.
fn int_scalar(d: &mut Decoder, id: NodeId, out: &mut i64, typ: &str) -> R<bool> {
    let (tag, res) = d.resolved(id)?;
    let v = match res {
        Resolved::Null => return Ok(false),
        Resolved::Int(i) => Some(i),
        Resolved::Uint(u) if u <= i64::MAX as u64 => Some(u as i64),
        Resolved::Float(f) if f <= i64::MAX as f64 => Some(float_to_int(f)),
        _ => None,
    };
    match v {
        Some(v) => {
            *out = v;
            Ok(true)
        }
        None => {
            d.terror(id, &tag, typ);
            Ok(false)
        }
    }
}

impl Decode for i64 {
    fn type_name() -> String {
        "int".to_string()
    }
    fn scalar(d: &mut Decoder, id: NodeId, out: &mut Self) -> R<bool> {
        int_scalar(d, id, out, "int")
    }
}

/// An int64 field (Go's type name differs from int's).
#[derive(Default)]
pub(crate) struct Int64(pub i64);

impl From<i64> for Int64 {
    fn from(v: i64) -> Int64 {
        Int64(v)
    }
}

impl From<Int64> for i64 {
    fn from(v: Int64) -> i64 {
        v.0
    }
}

impl Decode for Int64 {
    fn type_name() -> String {
        "int64".to_string()
    }
    fn scalar(d: &mut Decoder, id: NodeId, out: &mut Self) -> R<bool> {
        int_scalar(d, id, &mut out.0, "int64")
    }
}

impl Decode for bool {
    fn type_name() -> String {
        "bool".to_string()
    }
    fn scalar(d: &mut Decoder, id: NodeId, out: &mut Self) -> R<bool> {
        let (tag, res) = d.resolved(id)?;
        match res {
            Resolved::Null => Ok(false),
            Resolved::Bool(b) => {
                *out = b;
                Ok(true)
            }
            Resolved::Str(s)
                if matches!(
                    s.as_str(),
                    "y" | "Y" | "yes" | "Yes" | "YES" | "on" | "On" | "ON"
                ) =>
            {
                *out = true;
                Ok(true)
            }
            Resolved::Str(s)
                if matches!(
                    s.as_str(),
                    "n" | "N" | "no" | "No" | "NO" | "off" | "Off" | "OFF"
                ) =>
            {
                *out = false;
                Ok(true)
            }
            _ => {
                d.terror(id, &tag, "bool");
                Ok(false)
            }
        }
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn type_name() -> String {
        format!("[]{}", T::type_name())
    }
    fn sequence(d: &mut Decoder, id: NodeId, out: &mut Self) -> R<bool> {
        let content = d.node(id).content.clone();
        out.clear();
        for c in content {
            let mut e = T::default();
            if d.unmarshal(c, &mut e)? {
                out.push(e);
            }
        }
        Ok(true)
    }
    fn null(out: &mut Self) -> bool {
        out.clear();
        true
    }
}

/// A slice whose nil-ness is kept (JSON writes nil as null).
#[derive(Default)]
pub(crate) struct NilList<T>(pub Option<Vec<T>>);

impl<T> From<Option<Vec<T>>> for NilList<T> {
    fn from(v: Option<Vec<T>>) -> NilList<T> {
        NilList(v)
    }
}

impl<T> From<NilList<T>> for Option<Vec<T>> {
    fn from(v: NilList<T>) -> Option<Vec<T>> {
        v.0
    }
}

impl<T: Decode> Decode for NilList<T> {
    fn type_name() -> String {
        format!("[]{}", T::type_name())
    }
    fn sequence(d: &mut Decoder, id: NodeId, out: &mut Self) -> R<bool> {
        let mut v = Vec::new();
        let r = <Vec<T> as Decode>::sequence(d, id, &mut v);
        out.0 = Some(v);
        r
    }
    fn null(out: &mut Self) -> bool {
        out.0 = None;
        true
    }
}

impl<T: Decode> Decode for Option<T> {
    fn type_name() -> String {
        format!("*{}", T::type_name())
    }
    fn prepared(d: &mut Decoder, id: NodeId, out: &mut Self, null: bool) -> R<bool> {
        if null {
            return d.dispatch(id, out);
        }
        let inner = out.get_or_insert_with(T::default);
        T::prepared(d, id, inner, false)
    }
    fn null(out: &mut Self) -> bool {
        *out = None;
        true
    }
}

impl Decode for Duration {
    fn type_name() -> String {
        "spec.Duration".to_string()
    }
    fn custom(d: &mut Decoder, id: NodeId, out: &mut Self) -> Option<R<bool>> {
        let n = d.node(id);
        if n.kind != Kind::Scalar {
            return Some(Err(format!(
                "line {}: duration must be a string like \"10s\"",
                n.line
            )));
        }
        Some(match go::parse_duration(&n.value) {
            Ok(v) => {
                *out = Duration(v);
                Ok(true)
            }
            Err(_) => Err(format!(
                "line {}: invalid duration {}",
                n.line,
                quote(&n.value)
            )),
        })
    }
}

/// A struct decoded field by field (getStructInfo's fields in order).
pub(crate) trait Fields: Default {
    const NAME: &'static str;
    const KEYS: &'static [&'static str];
    fn set(&mut self, d: &mut Decoder, idx: usize, v: NodeId) -> R<()>;
}

/// A struct decoded as the local type `plain` of an UnmarshalYAML method,
/// which has the struct's fields and no UnmarshalYAML.
#[derive(Default)]
pub(crate) struct Plain<T>(pub T);

impl<T: Fields> Decode for Plain<T> {
    fn type_name() -> String {
        "spec.plain".to_string()
    }
    fn mapping(d: &mut Decoder, id: NodeId, out: &mut Self) -> R<bool> {
        d.mapping_struct(id, out, "spec.plain")
    }
}

impl<T: Fields> Fields for Plain<T> {
    const NAME: &'static str = "spec.plain";
    const KEYS: &'static [&'static str] = T::KEYS;
    fn set(&mut self, d: &mut Decoder, idx: usize, v: NodeId) -> R<()> {
        self.0.set(d, idx, v)
    }
}

/// Fields for a struct, with the type each field decodes as (its own, or a
/// wrapper with Go's type name).
macro_rules! fields {
    ($ty:ty, $name:literal, [$($key:literal => $field:ident : $dty:ty),* $(,)?]) => {
        impl Fields for $ty {
            const NAME: &'static str = $name;
            const KEYS: &'static [&'static str] = &[$($key),*];
            #[allow(unused_assignments)]
            fn set(&mut self, d: &mut Decoder, idx: usize, v: NodeId) -> R<()> {
                let mut i = 0;
                $(
                    if idx == i {
                        let mut t: $dty = From::from(std::mem::take(&mut self.$field));
                        let r = d.unmarshal(v, &mut t);
                        self.$field = t.into();
                        r?;
                        return Ok(());
                    }
                    i += 1;
                )*
                Ok(())
            }
        }
    };
}

/// Decode for a struct without UnmarshalYAML.
macro_rules! plain_struct {
    ($ty:ty) => {
        impl Decode for $ty {
            fn type_name() -> String {
                <$ty as Fields>::NAME.to_string()
            }
            fn mapping(d: &mut Decoder, id: NodeId, out: &mut Self) -> R<bool> {
                d.mapping_struct(id, out, <$ty as Fields>::NAME)
            }
        }
    };
}

fields!(App, "spec.App", [
    "apiVersion" => api_version: String,
    "kind" => kind: String,
    "name" => name: String,
    "image" => image: String,
    "command" => command: Vec<String>,
    "args" => args: Vec<String>,
    "env" => env: Vec<EnvVar>,
    "envFrom" => env_from: EnvFrom,
    "secretFiles" => secret_files: Vec<SecretFile>,
    "registry" => registry: Option<Registry>,
    "ingress" => ingress: Option<Ingress>,
    "revisions" => revisions: Option<Revisions>,
    "probes" => probes: Option<Probes>,
    "scale" => scale: Option<Scale>,
    "resources" => resources: Option<Resources>,
    "placement" => placement: Option<Placement>,
    "volumes" => volumes: Vec<Volume>,
    "initContainers" => init_containers: Vec<Container>,
    "sidecars" => sidecars: Vec<Container>,
    "drain" => drain: Duration,
    "schedule" => schedule: String,
    "timeZone" => time_zone: String,
    "timeout" => timeout: Duration,
    "retries" => retries: i64,
    "concurrency" => concurrency: String,
    "history" => history: Option<i64>,
    "tasks" => tasks: i64,
    "parallelism" => parallelism: i64,
    "trigger" => trigger: Option<Trigger>,
]);
plain_struct!(App);

fields!(EnvVar, "spec.EnvVar", [
    "name" => name: String,
    "value" => value: String,
    "secretRef" => secret_ref: String,
]);
plain_struct!(EnvVar);

fields!(Ingress, "spec.Ingress", [
    "type" => typ: String,
    "protocol" => protocol: String,
    "port" => port: i64,
    "domains" => domains: Vec<String>,
    "routes" => routes: Vec<Route>,
    "allow" => allow: Vec<String>,
    "ipAllow" => ip_allow: Vec<IPRule>,
    "ipDeny" => ip_deny: Vec<IPRule>,
    "sticky" => sticky: bool,
    "cors" => cors: Option<Cors>,
    "timeout" => timeout: Duration,
    "dns" => dns: Option<IngressDns>,
]);
plain_struct!(Ingress);

fields!(IngressDns, "spec.IngressDNS", [
    "provider" => provider: String,
    "tokenSecretRef" => token_secret_ref: String,
]);
plain_struct!(IngressDns);

fields!(Route, "spec.Route", [
    "path" => path: String,
    "stripPrefix" => strip_prefix: bool,
]);
plain_struct!(Route);

fields!(Revisions, "spec.Revisions", [
    "mode" => mode: String,
    "traffic" => traffic: Vec<TrafficTarget>,
]);
plain_struct!(Revisions);

fields!(TrafficTarget, "spec.TrafficTarget", [
    "revision" => revision: String,
    "weight" => weight: i64,
    "label" => label: String,
]);
plain_struct!(TrafficTarget);

fields!(Probes, "spec.Probes", [
    "startup" => startup: Option<Probe>,
    "readiness" => readiness: Option<Probe>,
    "liveness" => liveness: Option<Probe>,
]);
plain_struct!(Probes);

fields!(Probe, "spec.Probe", [
    "path" => path: String,
    "command" => command: Vec<String>,
    "port" => port: i64,
    "initialDelay" => initial_delay: Duration,
    "period" => period: Duration,
    "timeout" => timeout: Duration,
    "failureThreshold" => failure_threshold: i64,
]);

impl Decode for Probe {
    fn type_name() -> String {
        "spec.Probe".to_string()
    }
    fn custom(d: &mut Decoder, id: NodeId, out: &mut Self) -> Option<R<bool>> {
        let n = d.node(id);
        if n.kind == Kind::Scalar {
            *out = Probe {
                path: n.value.clone(),
                ..Probe::default()
            };
            return Some(Ok(true));
        }
        let r = d.decode_strict::<Plain<Probe>>(id).map(|p| p.0);
        Some(d.call_unmarshaler(r, out))
    }
}

fields!(Cors, "spec.CORS", [
    "allowOrigins" => allow_origins: NilList<String>,
    "allowMethods" => allow_methods: Vec<String>,
    "allowHeaders" => allow_headers: Vec<String>,
    "exposeHeaders" => expose_headers: Vec<String>,
    "maxAge" => max_age: Duration,
    "allowCredentials" => allow_credentials: bool,
]);
plain_struct!(Cors);

fields!(IPRule, "spec.IPRule", [
    "range" => range: String,
    "name" => name: String,
    "description" => description: String,
]);

impl Decode for IPRule {
    fn type_name() -> String {
        "spec.IPRule".to_string()
    }
    fn custom(d: &mut Decoder, id: NodeId, out: &mut Self) -> Option<R<bool>> {
        let n = d.node(id);
        if n.kind == Kind::Scalar {
            *out = IPRule {
                range: n.value.clone(),
                ..IPRule::default()
            };
            return Some(Ok(true));
        }
        let r = d.decode_strict::<Plain<IPRule>>(id).map(|p| p.0);
        Some(d.call_unmarshaler(r, out))
    }
}

fields!(Scale, "spec.Scale", [
    "min" => min: Option<i64>,
    "max" => max: Option<i64>,
    "rules" => rules: Vec<ScaleRule>,
    "idleAfter" => idle_after: Duration,
]);
plain_struct!(Scale);

fields!(ScaleRule, "spec.ScaleRule", [
    "type" => typ: String,
    "concurrent" => concurrent: i64,
    "utilization" => utilization: i64,
    "command" => command: Vec<String>,
    "urlSecretRef" => url_secret_ref: String,
    "list" => list: String,
    "queue" => queue: String,
    "length" => length: i64,
    "schedule" => schedule: String,
    "timeZone" => time_zone: String,
    "duration" => duration: Duration,
    "replicas" => replicas: i64,
]);
plain_struct!(ScaleRule);

fields!(Resources, "spec.Resources", [
    "cpu" => cpu: String,
    "memory" => memory: String,
]);
plain_struct!(Resources);

/// LabelValues: a scalar or a sequence of scalars.
#[derive(Default)]
pub(crate) struct LabelVals(pub LabelValues);

impl From<LabelValues> for LabelVals {
    fn from(v: LabelValues) -> LabelVals {
        LabelVals(v)
    }
}

impl From<LabelVals> for LabelValues {
    fn from(v: LabelVals) -> LabelValues {
        v.0
    }
}

impl Decode for LabelVals {
    fn type_name() -> String {
        "spec.LabelValues".to_string()
    }
    fn custom(d: &mut Decoder, id: NodeId, out: &mut Self) -> Option<R<bool>> {
        let n = d.node(id);
        if n.kind == Kind::Scalar {
            out.0 = Some(vec![n.value.clone()]);
            return Some(Ok(true));
        }
        let r = d.node_decode::<NilList<String>>(id).map(|l| l.0);
        Some(d.call_unmarshaler(r, &mut out.0))
    }
    fn null(out: &mut Self) -> bool {
        out.0 = None;
        true
    }
}

/// placement.require: map[string]spec.LabelValues.
#[derive(Default)]
pub(crate) struct Require(pub BTreeMap<String, LabelValues>);

impl From<BTreeMap<String, LabelValues>> for Require {
    fn from(v: BTreeMap<String, LabelValues>) -> Require {
        Require(v)
    }
}

impl From<Require> for BTreeMap<String, LabelValues> {
    fn from(v: Require) -> BTreeMap<String, LabelValues> {
        v.0
    }
}

impl Decode for Require {
    fn type_name() -> String {
        "map[string]spec.LabelValues".to_string()
    }
    fn mapping(d: &mut Decoder, id: NodeId, out: &mut Self) -> R<bool> {
        d.mapping_map::<LabelVals, LabelValues>(id, &mut out.0)
    }
    fn null(out: &mut Self) -> bool {
        out.0.clear();
        true
    }
}

fields!(Placement, "spec.Placement", [
    "require" => require: Require,
    "spreadBy" => spread_by: String,
]);
plain_struct!(Placement);

fields!(Volume, "spec.Volume", [
    "name" => name: String,
    "path" => path: String,
    "owner" => owner: String,
    "backup" => backup: Option<VolumeBackup>,
    "failover" => failover: String,
    "nfs" => nfs: Option<NfsSource>,
]);
plain_struct!(Volume);

fields!(NfsSource, "spec.NFSSource", [
    "server" => server: String,
    "path" => path: String,
    "readOnly" => read_only: bool,
]);
plain_struct!(NfsSource);

fields!(VolumeBackup, "spec.VolumeBackup", [
    "every" => every: Duration,
    "schedule" => schedule: String,
    "timeZone" => time_zone: String,
    "keep" => keep: BackupKeep,
    "urlSecretRef" => url_secret_ref: String,
    "keySecretRef" => key_secret_ref: String,
    "stop" => stop: bool,
]);
plain_struct!(VolumeBackup);

fields!(BackupKeep, "spec.BackupKeep", [
    "last" => last: i64,
    "hourly" => hourly: i64,
    "daily" => daily: i64,
    "weekly" => weekly: i64,
    "monthly" => monthly: i64,
]);

impl Decode for BackupKeep {
    fn type_name() -> String {
        "spec.BackupKeep".to_string()
    }
    fn custom(d: &mut Decoder, id: NodeId, out: &mut Self) -> Option<R<bool>> {
        let n = d.node(id);
        if n.kind == Kind::Scalar {
            return Some(match d.node_decode::<i64>(id) {
                Ok(last) => {
                    *out = BackupKeep {
                        last,
                        ..BackupKeep::default()
                    };
                    Ok(true)
                }
                Err(_) => Err(
                    "keep: must be a number or a mapping of last, hourly, daily, weekly, monthly"
                        .to_string(),
                ),
            });
        }
        let r = d.decode_strict::<Plain<BackupKeep>>(id).map(|p| p.0);
        Some(d.call_unmarshaler(r, out))
    }
}

fields!(Container, "spec.Container", [
    "name" => name: String,
    "image" => image: String,
    "command" => command: Vec<String>,
    "args" => args: Vec<String>,
    "env" => env: Vec<EnvVar>,
    "resources" => resources: Option<Resources>,
    "volumes" => volumes: Vec<String>,
    "secretFiles" => secret_files: Vec<String>,
]);
plain_struct!(Container);

fields!(SecretFile, "spec.SecretFile", [
    "secretRef" => secret_ref: String,
    "path" => path: String,
]);
plain_struct!(SecretFile);

fields!(Registry, "spec.Registry", [
    "server" => server: String,
    "username" => username: String,
    "passwordSecretRef" => password_secret_ref: String,
]);
plain_struct!(Registry);

fields!(EnvFromSecret, "spec.EnvFromSecret", [
    "secret" => secret: String,
]);
plain_struct!(EnvFromSecret);

impl Decode for EnvFrom {
    fn type_name() -> String {
        "spec.EnvFrom".to_string()
    }
    fn custom(d: &mut Decoder, id: NodeId, out: &mut Self) -> Option<R<bool>> {
        let n = d.node(id);
        if n.kind == Kind::Scalar {
            if n.value != crate::validate::ENV_FROM_SECRETS {
                return Some(Err(format!(
                    "line {}: envFrom must be {} or a list of secrets (- secret: NAME)",
                    n.line,
                    quote(crate::validate::ENV_FROM_SECRETS)
                )));
            }
            *out = EnvFrom {
                own: true,
                secrets: None,
            };
            return Some(Ok(true));
        }
        let r = d
            .decode_strict::<NilList<EnvFromSecret>>(id)
            .map(|l| EnvFrom {
                own: false,
                secrets: l.0,
            });
        Some(d.call_unmarshaler(r, out))
    }
}

fields!(Trigger, "spec.Trigger", [
    "queue" => queue: Option<QueueTrigger>,
    "pollingInterval" => polling_interval: Duration,
    "parallelism" => parallelism: i64,
]);
plain_struct!(Trigger);

fields!(QueueTrigger, "spec.QueueTrigger", [
    "type" => typ: String,
    "urlSecretRef" => url_secret_ref: String,
    "list" => list: String,
    "queue" => queue: String,
    "perRun" => per_run: Int64,
]);
plain_struct!(QueueTrigger);

/// The first document of data decoded into an App as Parse does: a
/// strict Decoder, then a check that no second document follows.
pub fn decode_app(data: &[u8]) -> Result<App, String> {
    let mut c = Composer::from_reader(data);
    let doc = match c.parse() {
        Err(e) => return Err(format!("invalid spec: {e}")),
        Ok(None) => return Err("spec is empty".to_string()),
        Ok(Some(doc)) => doc,
    };
    let mut app = App::default();
    {
        let mut d = Decoder::new(&c.tree, true);
        d.unmarshal(doc, &mut app)
            .map_err(|e| format!("invalid spec: {e}"))?;
        if !d.terrors.is_empty() {
            return Err(format!(
                "invalid spec: yaml: unmarshal errors:\n  {}",
                d.terrors.join("\n  ")
            ));
        }
    }
    match c.parse() {
        Ok(None) => Ok(app),
        _ => Err("spec must contain exactly one YAML document".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVs\nbG8h").unwrap(), b"hello!");
        assert!(base64_decode("aGV").is_none());
    }
}
