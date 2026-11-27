//! Image references as the agent reads them (distribution/reference's
//! ParseDockerRef and FamiliarName), and the registry a reference or a
//! credential names (registryHost, pullKey).

use super::digest::Digest;
use sha2::{Digest as _, Sha256};

const DEFAULT_DOMAIN: &str = "docker.io";
const LEGACY_DEFAULT_DOMAIN: &str = "index.docker.io";
const OFFICIAL_REPO_PREFIX: &str = "library/";
const NAME_TOTAL_LENGTH_MAX: usize = 255;

/// A normalized reference: always a domain, and a tag or a digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    pub domain: String,
    pub path: String,
    pub tag: String,
    pub digest: Option<Digest>,
}

impl Reference {
    /// The name without tag or digest ("docker.io/library/nginx").
    pub fn name(&self) -> String {
        format!("{}/{}", self.domain, self.path)
    }

    /// FamiliarName: Docker Hub's domain and official prefix dropped.
    pub fn familiar_name(&self) -> String {
        if self.domain != DEFAULT_DOMAIN {
            return self.name();
        }
        if let Some(rest) = self.path.strip_prefix(OFFICIAL_REPO_PREFIX)
            && !rest.contains('/')
        {
            return rest.to_string();
        }
        self.path.clone()
    }
}

impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())?;
        if !self.tag.is_empty() {
            write!(f, ":{}", self.tag)?;
        }
        if let Some(d) = &self.digest {
            write!(f, "@{d}")?;
        }
        Ok(())
    }
}

/// reference.ParseDockerRef: a reference with both a tag and a digest
/// keeps only the digest; one with neither gets "latest".
pub fn parse_docker_ref(s: &str) -> Result<Reference, String> {
    let mut r = parse_normalized_named(s)?;
    if r.digest.is_some() {
        r.tag.clear();
    } else if r.tag.is_empty() {
        r.tag = "latest".into();
    }
    Ok(r)
}

fn parse_normalized_named(s: &str) -> Result<Reference, String> {
    if s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!(
            "invalid repository name ({s}), cannot specify 64-byte hexadecimal strings"
        ));
    }
    let (domain, remainder) = split_docker_domain(s);
    let remote = match remainder.find(':') {
        Some(i) => &remainder[..i],
        None => &remainder,
    };
    if remote.to_lowercase() != remote {
        return Err(format!(
            "invalid reference format: repository name ({remote}) must be lowercase"
        ));
    }
    parse(&domain, &remainder)
}

fn split_docker_domain(name: &str) -> (String, String) {
    let Some((maybe_domain, maybe_remote)) = name.split_once('/') else {
        return (
            DEFAULT_DOMAIN.into(),
            format!("{OFFICIAL_REPO_PREFIX}{name}"),
        );
    };
    let (domain, mut remote) = if maybe_domain == "localhost" {
        (maybe_domain.to_string(), maybe_remote.to_string())
    } else if maybe_domain == LEGACY_DEFAULT_DOMAIN {
        (DEFAULT_DOMAIN.to_string(), maybe_remote.to_string())
    } else if maybe_domain.contains(['.', ':']) || maybe_domain.to_lowercase() != maybe_domain {
        (maybe_domain.to_string(), maybe_remote.to_string())
    } else {
        (DEFAULT_DOMAIN.to_string(), name.to_string())
    };
    if domain == DEFAULT_DOMAIN && !remote.contains('/') {
        remote = format!("{OFFICIAL_REPO_PREFIX}{remote}");
    }
    (domain, remote)
}

/// reference.Parse of DOMAIN/REMAINDER.
fn parse(domain: &str, remainder: &str) -> Result<Reference, String> {
    let invalid = || "invalid reference format".to_string();
    let (before, digest) = match remainder.split_once('@') {
        Some((b, d)) => (b, Some(d)),
        None => (remainder, None),
    };
    let (path, tag) = match before.split_once(':') {
        Some((p, t)) => (p, t),
        None => (before, ""),
    };
    if !valid_domain(domain) {
        return Err(invalid());
    }
    if !valid_remote_name(path) {
        if valid_remote_name(&path.to_lowercase()) {
            return Err("invalid reference format: repository name must be lowercase".into());
        }
        return Err(invalid());
    }
    if before.contains(':') && !valid_tag(tag) {
        return Err(invalid());
    }
    let digest = match digest {
        None => None,
        Some(d) => {
            if !valid_digest_pattern(d) {
                return Err(invalid());
            }
            Some(Digest::parse(d)?)
        }
    };
    if path.len() > NAME_TOTAL_LENGTH_MAX {
        return Err(format!(
            "repository name must not be more than {NAME_TOTAL_LENGTH_MAX} characters"
        ));
    }
    Ok(Reference {
        domain: domain.to_string(),
        path: path.to_string(),
        tag: tag.to_string(),
        digest,
    })
}

fn alnum_lower(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

/// pathComponent: [a-z0-9]+ ((?:[._]|__|[-]+)[a-z0-9]+)*
fn valid_path_component(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    let run = |i: &mut usize| {
        let start = *i;
        while *i < b.len() && alnum_lower(b[*i]) {
            *i += 1;
        }
        *i > start
    };
    if !run(&mut i) {
        return false;
    }
    while i < b.len() {
        match b[i] {
            b'.' => i += 1,
            b'_' => {
                i += 1;
                if i < b.len() && b[i] == b'_' {
                    i += 1;
                }
            }
            b'-' => {
                while i < b.len() && b[i] == b'-' {
                    i += 1;
                }
            }
            _ => return false,
        }
        if !run(&mut i) {
            return false;
        }
    }
    true
}

fn valid_remote_name(s: &str) -> bool {
    !s.is_empty() && s.split('/').all(valid_path_component)
}

/// domainAndPort: (domainName | [ipv6]) (:[0-9]+)?
fn valid_domain(s: &str) -> bool {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return false;
        };
        let inner = &rest[..end];
        if inner.is_empty() || !inner.bytes().all(|b| b.is_ascii_hexdigit() || b == b':') {
            return false;
        }
        (None, &rest[end + 1..])
    } else {
        match s.find(':') {
            Some(i) => (Some(&s[..i]), &s[i..]),
            None => (Some(s), ""),
        }
    };
    if let Some(host) = host {
        let ok = host.split('.').all(|c| {
            let b = c.as_bytes();
            !b.is_empty()
                && b[0].is_ascii_alphanumeric()
                && b[b.len() - 1].is_ascii_alphanumeric()
                && b.iter().all(|x| x.is_ascii_alphanumeric() || *x == b'-')
        });
        if !ok {
            return false;
        }
    }
    match port.strip_prefix(':') {
        None => port.is_empty(),
        Some(p) => !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()),
    }
}

/// tag: [\w][\w.-]{0,127}
fn valid_tag(s: &str) -> bool {
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && word(b[0])
        && b[1..].iter().all(|x| word(*x) || *x == b'.' || *x == b'-')
}

/// digestPat: [A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*[:][[:xdigit:]]{32,}
fn valid_digest_pattern(s: &str) -> bool {
    let Some((alg, hex)) = s.split_once(':') else {
        return false;
    };
    if hex.len() < 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    alg.split(['-', '_', '+', '.']).all(|c| {
        let b = c.as_bytes();
        !b.is_empty() && b[0].is_ascii_alphabetic() && b.iter().all(|x| x.is_ascii_alphanumeric())
    })
}

/// registryHost: a registry address reduced to its host, Docker Hub's
/// aliases folded into the host the resolver uses.
pub fn registry_host(s: &str) -> String {
    let s = s.strip_prefix("https://").unwrap_or(s);
    let s = s.strip_prefix("http://").unwrap_or(s);
    let s = s.split('/').next().unwrap_or("").to_lowercase();
    match s.as_str() {
        ""
        | "docker.io"
        | "index.docker.io"
        | "registry-1.docker.io"
        | "registry.hub.docker.com" => "registry-1.docker.io".into(),
        _ => s,
    }
}

/// Credentials for a private registry; never printed.
#[derive(serde::Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct RegistryAuth {
    pub username: String,
    pub password: String,
    pub server_address: String,
}

impl std::fmt::Debug for RegistryAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}@{} (password redacted)",
            self.username, self.server_address
        )
    }
}

pub const PULL_LABEL: &str = "armada.pulled-with/";
pub const PULL_ANYONE: &str = "anyone";

/// pullKey: "anyone" without credentials for ref's registry, else a hash
/// of the registry, user, and password.
pub fn pull_key(r: &Reference, auth: Option<&RegistryAuth>) -> String {
    let host = registry_host(&r.domain);
    match auth {
        Some(a) if registry_host(&a.server_address) == host => {
            let mut h = Sha256::new();
            h.update(host.as_bytes());
            h.update([0]);
            h.update(a.username.as_bytes());
            h.update([0]);
            h.update(a.password.as_bytes());
            h.finalize()[..16]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        }
        _ => PULL_ANYONE.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_as_docker() {
        for (input, want, familiar) in [
            ("nginx", "docker.io/library/nginx:latest", "nginx"),
            ("library/nginx:1.2", "docker.io/library/nginx:1.2", "nginx"),
            ("index.docker.io/a/b", "docker.io/a/b:latest", "a/b"),
            ("ghcr.io/a/b:v1", "ghcr.io/a/b:v1", "ghcr.io/a/b"),
            ("localhost/x", "localhost/x:latest", "localhost/x"),
            (
                "Host.example:5000/x/y",
                "Host.example:5000/x/y:latest",
                "Host.example:5000/x/y",
            ),
            ("[::1]:5000/x", "[::1]:5000/x:latest", "[::1]:5000/x"),
        ] {
            let r = parse_docker_ref(input).unwrap();
            assert_eq!(r.to_string(), want, "{input}");
            assert_eq!(r.familiar_name(), familiar, "{input}");
        }
        let d = Digest::sha256(b"x");
        let r = parse_docker_ref(&format!("nginx:1@{d}")).unwrap();
        assert_eq!(r.to_string(), format!("docker.io/library/nginx@{d}"));
        for bad in [
            "",
            "x/UPPER",
            "x:",
            "a//b",
            "a/-b",
            "x@sha256:abc",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ] {
            assert!(parse_docker_ref(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn keys_credentials_by_registry() {
        let r = parse_docker_ref("nginx").unwrap();
        assert_eq!(pull_key(&r, None), PULL_ANYONE);
        let a = RegistryAuth {
            username: "u".into(),
            password: "p".into(),
            server_address: "https://index.docker.io/v1/".into(),
        };
        assert_ne!(pull_key(&r, Some(&a)), PULL_ANYONE);
        let other = parse_docker_ref("ghcr.io/x").unwrap();
        assert_eq!(pull_key(&other, Some(&a)), PULL_ANYONE);
        assert_eq!(
            format!("{a:?}"),
            "u@https://index.docker.io/v1/ (password redacted)"
        );
    }
}
