//! DNS messages, as far as the resolver reads and writes them: the header,
//! the one question of a query, and the replies it builds itself. Every
//! other query is forwarded as the bytes that arrived.

pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;

const TYPE_A: u16 = 1;
const TYPE_ANY: u16 = 255;
const CLASS_INET: u16 = 1;
const QR: u16 = 0x8000;
const AA: u16 = 0x0400;
const RD: u16 = 0x0100;
const CD: u16 = 0x0010;
const OPCODE_QUERY: u16 = 0;

/// What a datagram or TCP message asks for.
pub enum Request {
    /// Not a query (a response, or too short): no answer at all.
    Drop,
    /// An answer made without looking at the name: an error.
    Reply(Vec<u8>),
    /// A query of a name in the internal zone, with the app part of the
    /// name when it is made of valid labels.
    Internal(Query, Option<String>),
    /// A query to forward.
    Forward,
}

/// The parts of a query a reply repeats.
pub struct Query {
    id: u16,
    flags: u16,
    /// The question as it arrived (name, type, class).
    question: Vec<u8>,
    qtype: u16,
    qclass: u16,
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// Reads a message, applying these checks:
/// responses are ignored, opcodes other than QUERY get NOTIMP, and a
/// message with other than one question, or more records than a query
/// carries, gets FORMERR.
pub fn parse(pkt: &[u8], zone: &str) -> Request {
    if pkt.len() < 12 {
        return Request::Drop;
    }
    let (id, flags) = (be16(pkt, 0), be16(pkt, 2));
    if flags & QR != 0 {
        return Request::Drop;
    }
    if (flags >> 11) & 0xF != OPCODE_QUERY {
        return Request::Reply(header_only(id, flags, RCODE_NOTIMP));
    }
    let (qd, an, ns, ar) = (be16(pkt, 4), be16(pkt, 6), be16(pkt, 8), be16(pkt, 10));
    if qd != 1 || an > 1 || ns > 1 || ar > 2 {
        return Request::Reply(header_only(id, flags, RCODE_FORMERR));
    }
    let Some((labels, end)) = read_name(pkt, 12) else {
        return Request::Reply(header_only(id, flags, RCODE_FORMERR));
    };
    if end + 4 > pkt.len() {
        return Request::Reply(header_only(id, flags, RCODE_FORMERR));
    }
    let in_zone = labels
        .last()
        .is_some_and(|l| l.eq_ignore_ascii_case(zone.as_bytes()));
    if !in_zone {
        return Request::Forward;
    }
    let q = Query {
        id,
        flags,
        question: pkt[12..end + 4].to_vec(),
        qtype: be16(pkt, end),
        qclass: be16(pkt, end + 2),
    };
    let app = &labels[..labels.len() - 1];
    let valid = !app.is_empty()
        && app
            .iter()
            .all(|l| l.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-'));
    let name = valid.then(|| {
        app.iter()
            .map(|l| String::from_utf8_lossy(l).to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(".")
    });
    Request::Internal(q, name)
}

/// Reads the uncompressed name at `at` (a query's question has no
/// pointers): its labels, and the offset after it.
fn read_name(pkt: &[u8], mut at: usize) -> Option<(Vec<&[u8]>, usize)> {
    let mut labels = Vec::new();
    let mut total = 0;
    loop {
        let len = *pkt.get(at)? as usize;
        at += 1;
        if len == 0 {
            return Some((labels, at));
        }
        if len > 63 {
            return None;
        }
        total += len + 1;
        if total > 254 {
            return None;
        }
        labels.push(pkt.get(at..at + len)?);
        at += len;
    }
}

/// The ID of a message, if it is long enough to have one.
pub fn id(pkt: &[u8]) -> Option<u16> {
    (pkt.len() >= 12).then(|| be16(pkt, 0))
}

/// Whether pkt is a response with the given ID.
pub fn is_response(pkt: &[u8], want: u16) -> bool {
    pkt.len() >= 12 && be16(pkt, 0) == want && be16(pkt, 2) & QR != 0
}

fn header_only(id: u16, flags: u16, rcode: u8) -> Vec<u8> {
    let f = QR | (flags & 0x7800) | rcode as u16;
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&f.to_be_bytes());
    out.extend_from_slice(&[0; 8]);
    out
}

/// A reply to a query with its question and rcode: the flags of the
/// query that a reply keeps (RD, CD), and AA for the internal zone.
fn reply(q: &Query, rcode: u8, aa: bool, answers: u16) -> Vec<u8> {
    let mut f = QR | (q.flags & (RD | CD)) | rcode as u16;
    if aa {
        f |= AA;
    }
    let mut out = Vec::with_capacity(12 + q.question.len() + 16);
    out.extend_from_slice(&q.id.to_be_bytes());
    out.extend_from_slice(&f.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&q.question);
    out
}

/// The answer for an internal name: NXDOMAIN, or the ingress address for
/// A (and ANY) queries of the INET class and no records for other types.
pub fn answer(q: &Query, found: bool, addr: [u8; 4], ttl: u32) -> Vec<u8> {
    if !found {
        return reply(q, RCODE_NXDOMAIN, true, 0);
    }
    if q.qclass != CLASS_INET || (q.qtype != TYPE_A && q.qtype != TYPE_ANY) {
        return reply(q, 0, true, 0);
    }
    let mut out = reply(q, 0, true, 1);
    // The name is the question's (a pointer to offset 12).
    out.extend_from_slice(&[0xC0, 0x0C]);
    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&CLASS_INET.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&addr);
    out
}

/// SERVFAIL for a query that could not be forwarded, with its question
/// when it can be read.
pub fn servfail(pkt: &[u8]) -> Vec<u8> {
    if pkt.len() >= 12
        && let Some((_, end)) = read_name(pkt, 12)
        && end + 4 <= pkt.len()
    {
        let q = Query {
            id: be16(pkt, 0),
            flags: be16(pkt, 2),
            question: pkt[12..end + 4].to_vec(),
            qtype: 0,
            qclass: 0,
        };
        return reply(&q, RCODE_SERVFAIL, false, 0);
    }
    header_only(id(pkt).unwrap_or(0), 0, RCODE_SERVFAIL)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16, flags: u16, counts: [u16; 4]) -> Vec<u8> {
        let mut p = vec![0x12, 0x34];
        p.extend_from_slice(&flags.to_be_bytes());
        for c in counts {
            p.extend_from_slice(&c.to_be_bytes());
        }
        for l in name.split('.').filter(|l| !l.is_empty()) {
            p.push(l.len() as u8);
            p.extend_from_slice(l.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p
    }

    #[test]
    fn internal_names() {
        let p = query("Shop-API.internal.", TYPE_A, RD, [1, 0, 0, 0]);
        let Request::Internal(q, Some(name)) = parse(&p, "internal") else {
            panic!("not internal");
        };
        assert_eq!(name, "shop-api");
        let a = answer(&q, true, [10, 0, 0, 1], 5);
        assert_eq!(&a[..2], &[0x12, 0x34]);
        assert_eq!(be16(&a, 2), QR | AA | RD);
        assert_eq!(be16(&a, 6), 1);
        assert_eq!(&a[a.len() - 4..], &[10, 0, 0, 1]);
        let nx = answer(&q, false, [10, 0, 0, 1], 5);
        assert_eq!(be16(&nx, 2) & 0xF, RCODE_NXDOMAIN as u16);
        let aaaa = query("web.internal.", 28, 0, [1, 0, 0, 0]);
        let Request::Internal(q, _) = parse(&aaaa, "internal") else {
            panic!();
        };
        assert_eq!(be16(&answer(&q, true, [1, 2, 3, 4], 5), 6), 0);
        // The zone alone and odd bytes have no app name.
        assert!(matches!(
            parse(&query("internal.", TYPE_A, 0, [1, 0, 0, 0]), "internal"),
            Request::Internal(_, None)
        ));
        assert!(matches!(
            parse(&query("a_b.internal.", TYPE_A, 0, [1, 0, 0, 0]), "internal"),
            Request::Internal(_, None)
        ));
        let mut dotted = query("web.internal.", TYPE_A, 0, [1, 0, 0, 0]);
        dotted[13 + 1] = b'.';
        assert!(matches!(
            parse(&dotted, "internal"),
            Request::Internal(_, None)
        ));
    }

    #[test]
    fn checks() {
        assert!(matches!(parse(&[0; 5], "internal"), Request::Drop));
        assert!(matches!(
            parse(&query("x.", 1, QR, [1, 0, 0, 0]), "internal"),
            Request::Drop
        ));
        let Request::Reply(r) = parse(&query("x.", 1, 5 << 11, [1, 0, 0, 0]), "internal") else {
            panic!();
        };
        assert_eq!(be16(&r, 2) & 0xF, RCODE_NOTIMP as u16);
        for counts in [
            [0, 0, 0, 0],
            [2, 0, 0, 0],
            [1, 2, 0, 0],
            [1, 0, 2, 0],
            [1, 0, 0, 3],
        ] {
            let Request::Reply(r) = parse(&query("x.", 1, 0, counts), "internal") else {
                panic!("{counts:?}");
            };
            assert_eq!(be16(&r, 2) & 0xF, RCODE_FORMERR as u16);
        }
        let mut cut = query("example.com.", 1, 0, [1, 0, 0, 0]);
        cut.truncate(cut.len() - 2);
        assert!(matches!(parse(&cut, "internal"), Request::Reply(_)));
        let mut pointer = query("example.com.", 1, 0, [1, 0, 0, 0]);
        pointer[12] = 0xC0;
        assert!(matches!(parse(&pointer, "internal"), Request::Reply(_)));
        assert!(matches!(
            parse(&query("example.com.", 1, 0, [1, 0, 0, 1]), "internal"),
            Request::Forward
        ));
        let sf = servfail(&query("example.com.", 1, RD, [1, 0, 0, 1]));
        assert_eq!(be16(&sf, 2), QR | RD | RCODE_SERVFAIL as u16);
        assert_eq!(be16(&sf, 4), 1);
    }
}
