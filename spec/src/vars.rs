//! spec.Substitute: ${NAME} in a spec's values (ADR 0029).

use std::collections::{BTreeSet, HashMap};
use std::io::Read;

use crate::spec::MAX_SPEC_BYTES;
use crate::yaml::compose::Composer;
use crate::yaml::encode::encode_node;
use crate::yaml::types::{Kind, NodeId, Tree};

/// VarNameRe: what a spec variable may be called.
pub fn valid_var_name(s: &str) -> bool {
    crate::validate::env_name_re(s)
}

fn nonce() -> String {
    let mut b = [0u8; 8];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .is_err()
    {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        b = (t as u64).to_le_bytes();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The length of a `${NAME}` at the start of s, or of `$${`.
fn var_at(s: &[u8]) -> Option<(usize, Option<&[u8]>)> {
    if s.starts_with(b"$${") {
        return Some((3, None));
    }
    if !s.starts_with(b"${") {
        return None;
    }
    let name = &s[2..];
    let first = *name.first()?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let n = name
        .iter()
        .position(|&c| !(c.is_ascii_alphanumeric() || c == b'_'))
        .unwrap_or(name.len());
    if name.get(n) != Some(&b'}') {
        return None;
    }
    Some((n + 3, Some(&name[..n])))
}

/// Replaces every placeholder prefix<digits>e in value through f.
fn replace_tokens(value: &str, prefix: &str, mut f: impl FnMut(usize) -> String) -> String {
    let mut out = String::new();
    let mut rest = value;
    while let Some(i) = rest.find(prefix) {
        let after = &rest[i + prefix.len()..];
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 && after.as_bytes().get(digits) == Some(&b'e') {
            out.push_str(&rest[..i]);
            out.push_str(&f(after[..digits].parse().unwrap_or(usize::MAX)));
            rest = &after[digits + 1..];
        } else {
            // No match here: move on by one character.
            let c = rest[i..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&rest[..i + c]);
            rest = &rest[i + c..];
        }
    }
    out.push_str(rest);
    out
}

/// Substitute replaces ${NAME} with vars[NAME] in the values of a spec;
/// $${ stays a literal ${. A variable the spec uses but vars lacks, or one
/// in a key, is an error. Comments are dropped.
pub fn substitute(data: &[u8], vars: &HashMap<String, String>) -> Result<Vec<u8>, String> {
    substitute_with(data, vars, &nonce())
}

pub(crate) fn substitute_with(
    data: &[u8],
    vars: &HashMap<String, String>,
    nonce: &str,
) -> Result<Vec<u8>, String> {
    if data.len() > MAX_SPEC_BYTES {
        return Err(format!("spec is larger than {MAX_SPEC_BYTES} bytes"));
    }
    let prefix = format!("av{nonce}n");
    let mut names: Vec<Option<String>> = Vec::new();
    let mut marked: Vec<u8> = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if let Some((len, name)) = var_at(&data[i..]) {
            names.push(name.map(|n| String::from_utf8_lossy(n).into_owned()));
            marked.extend_from_slice(format!("{prefix}{}e", names.len() - 1).as_bytes());
            i += len;
        } else {
            marked.push(data[i]);
            i += 1;
        }
    }
    let mut c = Composer::new(&marked);
    let doc = match c.parse() {
        Err(e) => return Err(format!("invalid spec: {e}")),
        Ok(None) => return Err("spec is empty".to_string()),
        Ok(Some(doc)) => doc,
    };
    let mut tree = std::mem::take(&mut c.tree);
    let mut missing = BTreeSet::new();
    let mut flags = Flags::default();
    let mut w = Walk {
        prefix: &prefix,
        nonce,
        names: &names,
        vars,
    };
    w.walk(&mut tree, doc, &mut missing, &mut flags);
    if flags.in_key {
        return Err("variables are only allowed in values, not in keys".to_string());
    }
    if flags.escaped {
        return Err(
            "a variable follows an escape sequence that takes its first character; put it outside the escape"
                .to_string(),
        );
    }
    if !missing.is_empty() {
        return Err(format!(
            "the spec uses variables that are not set: {} (pass --var NAME=VALUE or --vars FILE)",
            missing.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    let out = encode_node(&tree, doc, Some(2))?;
    if out.len() > MAX_SPEC_BYTES {
        return Err(format!(
            "spec is larger than {MAX_SPEC_BYTES} bytes once its variables are set"
        ));
    }
    Ok(out)
}

#[derive(Default)]
struct Flags {
    in_key: bool,
    escaped: bool,
}

struct Walk<'a> {
    prefix: &'a str,
    nonce: &'a str,
    names: &'a [Option<String>],
    vars: &'a HashMap<String, String>,
}

impl Walk<'_> {
    fn walk(&mut self, tree: &mut Tree, id: NodeId, missing: &mut BTreeSet<String>, f: &mut Flags) {
        let (prefix, names, vars) = (self.prefix, self.names, self.vars);
        let n = tree.get_mut(id);
        n.head_comment.clear();
        n.line_comment.clear();
        n.foot_comment.clear();
        match n.kind {
            Kind::Scalar => {
                // An escape before a variable (\x6${X}) takes the start of
                // its placeholder, which is then never set: the rest of the
                // nonce stays.
                if n.value.matches(self.nonce).count() > n.value.matches(prefix).count() {
                    f.escaped = true;
                }
                if !n.value.contains(prefix) {
                    return;
                }
                n.value = replace_tokens(&n.value, prefix, |i| match names.get(i) {
                    Some(None) => "${".to_string(),
                    Some(Some(name)) => match vars.get(name) {
                        Some(v) => v.clone(),
                        None => {
                            missing.insert(name.clone());
                            String::new()
                        }
                    },
                    None => String::new(),
                });
                if n.style == 0 {
                    // Resolve the type again from the new value.
                    n.tag.clear();
                }
            }
            Kind::Mapping => {
                let content = n.content.clone();
                for (i, c) in content.into_iter().enumerate() {
                    if i % 2 == 0 && tree.get(c).value.contains(prefix) {
                        f.in_key = true;
                    }
                    self.walk(tree, c, missing, f);
                }
            }
            _ => {
                let content = n.content.clone();
                for c in content {
                    self.walk(tree, c, missing, f);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_variable_inside_an_escape_is_refused() {
        let vars = HashMap::from([("IMAGE".to_string(), "x".to_string())]);
        for src in [
            "name: web\nimage: \"a\\x6${IMAGE}\"\n",
            "name: web\nimage: \"a\\u004${IMAGE}\"\n",
        ] {
            let err = substitute(src.as_bytes(), &vars).unwrap_err();
            assert!(err.contains("escape sequence"), "{src:?}: {err}");
        }
        let out = substitute(b"name: web\nimage: \"\\x41${IMAGE}\"\n", &vars).unwrap();
        assert!(String::from_utf8_lossy(&out).contains("Ax"));
    }
}
