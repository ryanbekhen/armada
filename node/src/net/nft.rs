//! The nftables isolation tables (isolation_linux.go, ADR 0026) as the
//! nf_tables netlink messages Go's nftables library sends for them, encoded
//! here by hand: no netfilter library is linked and no `nft` binary is
//! needed. `isolate`, `update_isolation`, and `remove_isolation` build the
//! batch of one transaction; `decide` is the agent's choice between keeping,
//! updating, and rebuilding the tables (Net.isolate).
//!
//! Messages come out with sequence number and port ID 0; the socket that
//! sends them numbers them (kernel.rs). Set IDs, which name a set created
//! in the same batch, count up from the batch's first one: Go takes them
//! from a counter shared by the whole process.

use super::addr::{Addr, Prefix};
use super::policy::Policy;
use sha2::{Digest, Sha256};

/// The tables' name, in the ip and bridge families (isolationTable).
pub const TABLE: &str = "armada";
/// The container bridge (embedded.BridgeName).
const BRIDGE: &str = "armada0";

const DNS_PORT: u16 = 53;
const HTTP_PORT: u16 = 80;
const HTTPS_PORT: u16 = 443;

/// blockedRanges: what an isolated container never reaches outside the
/// cluster CIDR.
const BLOCKED: [([u8; 4], u8); 9] = [
    ([10, 0, 0, 0], 8),
    ([172, 16, 0, 0], 12),
    ([192, 168, 0, 0], 16),
    ([100, 64, 0, 0], 10),
    ([169, 254, 0, 0], 16),
    ([127, 0, 0, 0], 8),
    ([0, 0, 0, 0], 8),
    ([224, 0, 0, 0], 4),
    ([240, 0, 0, 0], 4),
];

// Address families (NFPROTO_*).
pub const FAMILY_IPV4: u8 = 2;
pub const FAMILY_BRIDGE: u8 = 7;
pub const FAMILIES: [u8; 2] = [FAMILY_IPV4, FAMILY_BRIDGE];

// Netlink header flags.
const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_ACK: u16 = 0x4;
const NLM_F_ECHO: u16 = 0x8;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_APPEND: u16 = 0x800;
const NLA_F_NESTED: u16 = 0x8000;

// nfnetlink.
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = 16;
const NFNL_MSG_BATCH_END: u16 = 17;
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_GETTABLE: u16 = 1;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_DELCHAIN: u16 = 5;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_DELRULE: u16 = 8;
const NFT_MSG_NEWSET: u16 = 9;
const NFT_MSG_DELSET: u16 = 11;
const NFT_MSG_NEWSETELEM: u16 = 12;
const NFT_MSG_DELSETELEM: u16 = 14;

// Set key types (nftables' datatype magic numbers) and flags.
const TYPE_IPADDR: (u32, u32) = (7, 4);
const TYPE_INET_SERVICE: (u32, u32) = (13, 2);
const NFT_SET_MAP: u32 = 8;
const NFT_DATA_VERDICT: u32 = 0xffff_ff00;

// Chains.
const HOOK_INPUT: u32 = 1;
const HOOK_FORWARD: u32 = 2;
const POLICY_ACCEPT: u32 = 1;

// Expressions.
const META_PROTOCOL: u32 = 1;
const META_L4PROTO: u32 = 16;
const META_BRI_IIFNAME: u32 = 17;
const CT_STATE: u32 = 0;
const CT_ESTABLISHED: u32 = 2;
const CT_RELATED: u32 = 4;
const SOCKET_WILDCARD: u32 = 2;
const CMP_EQ: u32 = 0;
const CMP_NEQ: u32 = 1;
const BASE_NETWORK: u32 = 1;
const BASE_TRANSPORT: u32 = 2;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const VERDICT_JUMP: i32 = -3;
const VERDICT_DROP: i32 = 0;
const VERDICT_ACCEPT: i32 = 1;

/// One netlink attribute, as mdlayher/netlink marshals it: length and type
/// in host order, the data padded to four bytes. The length is 16 bits and
/// wraps like Go's.
fn attr(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    out.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(data);
    out.resize(out.len().next_multiple_of(4), 0);
}

fn attrs(list: &[(u16, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (ty, data) in list {
        attr(&mut out, *ty, data);
    }
    out
}

fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

fn cstr(s: &str) -> Vec<u8> {
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    b
}

/// NFTA_DATA_VALUE around data.
fn value(data: &[u8]) -> Vec<u8> {
    attrs(&[(1, data)])
}

/// One message of a batch, before the socket numbers it.
#[derive(Clone, Debug, PartialEq)]
pub struct Msg {
    pub ty: u16,
    pub flags: u16,
    pub data: Vec<u8>,
}

impl Msg {
    /// The message's bytes, with seq and port ID as given.
    pub fn bytes(&self, seq: u32, pid: u32) -> Vec<u8> {
        let len = (16 + self.data.len()).next_multiple_of(4);
        let mut b = Vec::with_capacity(len);
        b.extend_from_slice(&(len as u32).to_ne_bytes());
        b.extend_from_slice(&self.ty.to_ne_bytes());
        b.extend_from_slice(&self.flags.to_ne_bytes());
        b.extend_from_slice(&seq.to_ne_bytes());
        b.extend_from_slice(&pid.to_ne_bytes());
        b.extend_from_slice(&self.data);
        b.resize(len, 0);
        b
    }
}

/// extraHeader: the nfgenmsg in front of every message.
fn gen_header(family: u8, res_id: u16) -> Vec<u8> {
    let mut b = vec![family, 0];
    b.extend_from_slice(&res_id.to_be_bytes());
    b
}

fn nft_type(msg: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | msg
}

/// The messages of one transaction (nftables.Conn's queue).
pub struct Batch {
    pub msgs: Vec<Msg>,
    next_set_id: u32,
}

/// A set as the batch refers to it: by name, and by ID when it was created
/// in this batch (0 otherwise).
#[derive(Clone)]
struct Set {
    family: u8,
    name: String,
    id: u32,
}

/// A set element: a key, and in a verdict map a jump to a chain.
struct Elem {
    key: Vec<u8>,
    jump: Option<String>,
}

/// An expression of a rule, with Go's registers (1, or 0 for verdicts).
enum Expr {
    Payload { base: u32, offset: u32, len: u32 },
    Cmp { op: u32, data: Vec<u8> },
    Bitwise { mask: Vec<u8>, xor: Vec<u8> },
    Lookup { set: Set, invert: bool, map: bool },
    Meta { key: u32 },
    Ct { key: u32 },
    Socket { key: u32 },
    Verdict { kind: i32, chain: Option<String> },
}

impl Expr {
    fn encode(&self) -> Vec<u8> {
        let (name, data) = match self {
            Expr::Payload { base, offset, len } => (
                "payload",
                attrs(&[
                    (1, &be32(1)),
                    (2, &be32(*base)),
                    (3, &be32(*offset)),
                    (4, &be32(*len)),
                ]),
            ),
            Expr::Cmp { op, data } => (
                "cmp",
                attrs(&[
                    (1, &be32(1)),
                    (2, &be32(*op)),
                    (3 | NLA_F_NESTED, &value(data)),
                ]),
            ),
            Expr::Bitwise { mask, xor } => (
                "bitwise",
                attrs(&[
                    (1, &be32(1)),
                    (2, &be32(1)),
                    (3, &be32(mask.len() as u32)),
                    (4 | NLA_F_NESTED, &value(mask)),
                    (5 | NLA_F_NESTED, &value(xor)),
                ]),
            ),
            Expr::Lookup { set, invert, map } => {
                let mut b = Vec::new();
                attr(&mut b, 2, &be32(1));
                if *map {
                    attr(&mut b, 3, &be32(0));
                }
                if *invert {
                    attr(&mut b, 5, &be32(1));
                }
                attr(&mut b, 1, &cstr(&set.name));
                attr(&mut b, 4, &be32(set.id));
                ("lookup", b)
            }
            Expr::Meta { key } => ("meta", attrs(&[(2, &be32(*key)), (1, &be32(1))])),
            Expr::Ct { key } => ("ct", attrs(&[(2, &be32(*key)), (1, &be32(1))])),
            Expr::Socket { key } => (
                "socket",
                attrs(&[(2, &be32(1)), (1, &be32(*key)), (3, &be32(0))]),
            ),
            Expr::Verdict { kind, chain } => {
                let mut code = Vec::new();
                attr(&mut code, 1, &be32(*kind as u32));
                if let Some(c) = chain {
                    attr(&mut code, 2, &cstr(c));
                }
                let imm = attrs(&[(2 | NLA_F_NESTED, &code)]);
                (
                    "immediate",
                    attrs(&[(1, &be32(0)), (2 | NLA_F_NESTED, &imm)]),
                )
            }
        };
        attrs(&[(1, &cstr(name)), (2 | NLA_F_NESTED, &data)])
    }
}

fn addr_bytes(a: &Addr) -> Vec<u8> {
    match a {
        Addr::V4(b) => b.to_vec(),
        Addr::V6(b, _) => b.to_vec(),
    }
}

/// The netmask of a prefix's IPv4 address, as Go computes it.
fn mask4(bits: u8) -> Vec<u8> {
    let m = u32::MAX
        .checked_shl(32u32.saturating_sub(u32::from(bits)))
        .unwrap_or(0);
    m.to_be_bytes().to_vec()
}

fn accept() -> Vec<Expr> {
    vec![Expr::Verdict {
        kind: VERDICT_ACCEPT,
        chain: None,
    }]
}

fn drop() -> Vec<Expr> {
    vec![Expr::Verdict {
        kind: VERDICT_DROP,
        chain: None,
    }]
}

fn ether_type(proto: u16, invert: bool) -> Vec<Expr> {
    vec![
        Expr::Meta { key: META_PROTOCOL },
        Expr::Cmp {
            op: if invert { CMP_NEQ } else { CMP_EQ },
            data: proto.to_be_bytes().to_vec(),
        },
    ]
}

/// payload: 4 bytes of the IPv4 header at off; the bridge family checks
/// first that the frame carries IPv4.
fn payload(bridge: bool, off: u32) -> Vec<Expr> {
    let mut out = if bridge {
        ether_type(ETH_P_IP, false)
    } else {
        Vec::new()
    };
    out.push(Expr::Payload {
        base: BASE_NETWORK,
        offset: off,
        len: 4,
    });
    out
}

fn cmp(data: Vec<u8>) -> Vec<Expr> {
    vec![Expr::Cmp { op: CMP_EQ, data }]
}

fn prefix(bridge: bool, off: u32, p: &Prefix) -> Vec<Expr> {
    let mut out = payload(bridge, off);
    out.push(Expr::Bitwise {
        mask: mask4(p.bits),
        xor: vec![0; 4],
    });
    out.extend(cmp(addr_bytes(&p.masked().addr)));
    out
}

fn host_byte(bridge: bool, b: u8) -> Vec<Expr> {
    let mut out = payload(bridge, 12);
    out.push(Expr::Bitwise {
        mask: vec![0, 0, 0, 0xff],
        xor: vec![0; 4],
    });
    out.extend(cmp(vec![0, 0, 0, b]));
    out
}

fn src_in(bridge: bool, set: &Set, invert: bool) -> Vec<Expr> {
    let mut out = payload(bridge, 12);
    out.push(Expr::Lookup {
        set: set.clone(),
        invert,
        map: false,
    });
    out
}

fn ifname(key: u32, name: &str, invert: bool) -> Vec<Expr> {
    let mut data = vec![0u8; 16];
    data[..name.len()].copy_from_slice(name.as_bytes());
    vec![
        Expr::Meta { key },
        Expr::Cmp {
            op: if invert { CMP_NEQ } else { CMP_EQ },
            data,
        },
    ]
}

fn l4(proto: u8) -> Vec<Expr> {
    vec![
        Expr::Meta { key: META_L4PROTO },
        Expr::Cmp {
            op: CMP_EQ,
            data: vec![proto],
        },
    ]
}

fn dport_payload() -> Expr {
    Expr::Payload {
        base: BASE_TRANSPORT,
        offset: 2,
        len: 2,
    }
}

fn dport(port: u16) -> Vec<Expr> {
    vec![
        dport_payload(),
        Expr::Cmp {
            op: CMP_EQ,
            data: port.to_be_bytes().to_vec(),
        },
    ]
}

fn dport_in(set: &Set) -> Vec<Expr> {
    vec![
        dport_payload(),
        Expr::Lookup {
            set: set.clone(),
            invert: false,
            map: false,
        },
    ]
}

fn bound_to_address() -> Vec<Expr> {
    vec![
        Expr::Socket {
            key: SOCKET_WILDCARD,
        },
        Expr::Cmp {
            op: CMP_EQ,
            data: vec![0],
        },
    ]
}

/// notNewConn: replies and related traffic of known connections. The mask
/// is in host order, as Go writes it.
fn not_new_conn() -> Vec<Expr> {
    vec![
        Expr::Ct { key: CT_STATE },
        Expr::Bitwise {
            mask: (CT_ESTABLISHED | CT_RELATED).to_ne_bytes().to_vec(),
            xor: vec![0; 4],
        },
        Expr::Cmp {
            op: CMP_NEQ,
            data: vec![0; 4],
        },
    ]
}

/// appNames: the names of an app's address set and chain.
pub fn app_names(app: &str) -> (String, String) {
    let h = Sha256::digest(app.as_bytes());
    let id: String = h[..8].iter().map(|b| format!("{b:02x}")).collect();
    (format!("a{id}"), format!("app{id}"))
}

fn addr_elems(addrs: &[Addr]) -> Vec<Elem> {
    addrs
        .iter()
        .map(|a| Elem {
            key: addr_bytes(a),
            jump: None,
        })
        .collect()
}

fn port_elems(ports: &[u16]) -> Vec<Elem> {
    ports
        .iter()
        .map(|p| Elem {
            key: p.to_be_bytes().to_vec(),
            jump: None,
        })
        .collect()
}

fn jump_elem(a: &Addr, chain: &str) -> Elem {
    Elem {
        key: addr_bytes(a),
        jump: Some(chain.to_string()),
    }
}

/// A chain hook: the hook number and priority.
struct Hook {
    num: u32,
    priority: i32,
}

impl Batch {
    /// An empty batch whose sets created get IDs from first_set_id up.
    pub fn new(first_set_id: u32) -> Batch {
        Batch {
            msgs: Vec::new(),
            next_set_id: first_set_id,
        }
    }

    fn push(&mut self, msg: u16, flags: u16, family: u8, data: Vec<u8>) {
        let mut d = gen_header(family, 0);
        d.extend_from_slice(&data);
        self.msgs.push(Msg {
            ty: nft_type(msg),
            flags,
            data: d,
        });
    }

    fn table_attrs() -> Vec<u8> {
        attrs(&[(1, &cstr(TABLE)), (2, &[0, 0, 0, 0])])
    }

    fn add_table(&mut self, family: u8) {
        let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
        self.push(NFT_MSG_NEWTABLE, flags, family, Self::table_attrs());
    }

    fn del_table(&mut self, family: u8) {
        let flags = NLM_F_REQUEST | NLM_F_ACK;
        self.push(NFT_MSG_DELTABLE, flags, family, Self::table_attrs());
    }

    fn add_chain(&mut self, family: u8, name: &str, base: Option<Hook>) {
        let mut d = attrs(&[(1, &cstr(TABLE)), (3, &cstr(name))]);
        if let Some(h) = base {
            let hook = attrs(&[(1, &be32(h.num)), (2, &be32(h.priority as u32))]);
            attr(&mut d, 4 | NLA_F_NESTED, &hook);
            attr(&mut d, 5, &be32(POLICY_ACCEPT));
            attr(&mut d, 7, &cstr("filter"));
        }
        let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
        self.push(NFT_MSG_NEWCHAIN, flags, family, d);
    }

    fn del_chain(&mut self, family: u8, name: &str) {
        let d = attrs(&[(1, &cstr(TABLE)), (3, &cstr(name))]);
        self.push(NFT_MSG_DELCHAIN, NLM_F_REQUEST | NLM_F_ACK, family, d);
    }

    fn flush_chain(&mut self, family: u8, name: &str) {
        let d = attrs(&[(1, &cstr(TABLE)), (2, &cstr(name))]);
        self.push(NFT_MSG_DELRULE, NLM_F_REQUEST | NLM_F_ACK, family, d);
    }

    fn add_rule(&mut self, family: u8, chain: &str, exprs: Vec<Expr>) {
        let mut list = Vec::new();
        for e in &exprs {
            attr(&mut list, 1 | NLA_F_NESTED, &e.encode());
        }
        let mut d = attrs(&[(1, &cstr(TABLE)), (2, &cstr(chain))]);
        attr(&mut d, 4 | NLA_F_NESTED, &list);
        let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_ECHO | NLM_F_APPEND;
        self.push(NFT_MSG_NEWRULE, flags, family, d);
    }

    /// AddSet: a set, or with map a verdict map, keyed by key (magic, length),
    /// with its first elements.
    fn add_set(
        &mut self,
        family: u8,
        name: &str,
        key: (u32, u32),
        map: bool,
        elems: &[Elem],
    ) -> Set {
        let id = self.next_set_id;
        self.next_set_id = self.next_set_id.wrapping_add(1);
        let mut d = attrs(&[
            (1, &cstr(TABLE)),
            (2, &cstr(name)),
            (3, &be32(if map { NFT_SET_MAP } else { 0 })),
            (4, &be32(key.0)),
            (5, &be32(key.1)),
            (10, &be32(id)),
        ]);
        if map {
            attr(&mut d, 6, &be32(NFT_DATA_VERDICT));
            attr(&mut d, 7, &be32(0));
        }
        let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
        self.push(NFT_MSG_NEWSET, flags, family, d);
        let set = Set {
            family,
            name: name.to_string(),
            id,
        };
        if !elems.is_empty() {
            self.elements(NFT_MSG_NEWSETELEM, &set, elems);
        }
        set
    }

    fn del_set(&mut self, family: u8, name: &str) {
        let d = attrs(&[(1, &cstr(TABLE)), (2, &cstr(name))]);
        self.push(NFT_MSG_DELSET, NLM_F_REQUEST | NLM_F_ACK, family, d);
    }

    /// makeElemList in a NEWSETELEM or DELSETELEM message.
    fn elements(&mut self, msg: u16, set: &Set, elems: &[Elem]) {
        let mut list = Vec::new();
        for (i, e) in elems.iter().enumerate() {
            let mut item = Vec::new();
            attr(&mut item, 1 | NLA_F_NESTED, &value(&e.key));
            if let Some(chain) = &e.jump {
                let mut v = value(&be32(VERDICT_JUMP as u32));
                attr(&mut v, 2, &cstr(chain));
                let verdict = attrs(&[(2 | NLA_F_NESTED, &v)]);
                attr(&mut item, 2 | NLA_F_NESTED, &verdict);
            }
            attr(&mut list, ((i + 1) as u16) | NLA_F_NESTED, &item);
        }
        let mut d = attrs(&[(2, &cstr(&set.name)), (4, &be32(set.id)), (1, &cstr(TABLE))]);
        attr(&mut d, 3 | NLA_F_NESTED, &list);
        let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
        self.push(msg, flags, set.family, d);
    }

    /// addAppChain: an app's address set and the chain that lets only
    /// those addresses reach it.
    fn add_app_chain(&mut self, family: u8, app: &str, members: &[Addr]) -> String {
        let bridge = family == FAMILY_BRIDGE;
        let (set_name, chain) = app_names(app);
        let set = self.add_set(family, &set_name, TYPE_IPADDR, false, &addr_elems(members));
        self.add_chain(family, &chain, None);
        let mut e = src_in(bridge, &set, false);
        e.extend(accept());
        self.add_rule(family, &chain, e);
        self.add_rule(family, &chain, drop());
        chain
    }

    /// buildTable.
    fn build_table(&mut self, family: u8, pol: &Policy) {
        let bridge = family == FAMILY_BRIDGE;
        let mut targets = Vec::new();
        for (app, members) in &pol.members {
            let chain = self.add_app_chain(family, app, members);
            targets.extend(members.iter().map(|a| jump_elem(a, &chain)));
        }
        let dst = self.add_set(family, "dst", TYPE_IPADDR, true, &targets);
        let priority = if bridge { -200 } else { 0 };
        self.add_chain(
            family,
            "forward",
            Some(Hook {
                num: HOOK_FORWARD,
                priority,
            }),
        );
        let fwd = |b: &mut Batch, parts: Vec<Vec<Expr>>| {
            b.add_rule(family, "forward", parts.into_iter().flatten().collect());
        };
        if bridge {
            fwd(self, vec![ifname(META_BRI_IIFNAME, BRIDGE, true), accept()]);
            fwd(self, vec![ether_type(ETH_P_ARP, false), accept()]);
            fwd(self, vec![ether_type(ETH_P_IP, true), drop()]);
        } else {
            fwd(self, vec![not_new_conn(), accept()]);
        }
        let in_cidr = || {
            let mut e = prefix(bridge, 12, &pol.cidr);
            e.extend(prefix(bridge, 16, &pol.cidr));
            e
        };
        for node in [0u8, 1] {
            fwd(self, vec![in_cidr(), host_byte(bridge, node), accept()]);
        }
        fwd(
            self,
            vec![
                in_cidr(),
                payload(bridge, 16),
                vec![Expr::Lookup {
                    set: dst.clone(),
                    invert: false,
                    map: true,
                }],
            ],
        );
        fwd(self, vec![in_cidr(), drop()]);
        if bridge {
            return;
        }

        let open = self.add_set(family, "open", TYPE_IPADDR, false, &addr_elems(&pol.open));
        let nodes = self.add_set(family, "nodes", TYPE_IPADDR, false, &addr_elems(&pol.nodes));
        let isolated = || {
            let mut e = prefix(false, 12, &pol.subnet);
            e.extend(src_in(false, &open, true));
            e
        };
        for (net, bits) in BLOCKED {
            let r = Prefix {
                addr: Addr::V4(net),
                bits,
            };
            fwd(self, vec![isolated(), prefix(false, 16, &r), drop()]);
        }
        fwd(
            self,
            vec![
                isolated(),
                payload(false, 16),
                vec![Expr::Lookup {
                    set: nodes.clone(),
                    invert: false,
                    map: false,
                }],
                drop(),
            ],
        );

        self.add_chain(
            family,
            "input",
            Some(Hook {
                num: HOOK_INPUT,
                priority: 0,
            }),
        );
        let input = |b: &mut Batch, parts: Vec<Vec<Expr>>| {
            b.add_rule(family, "input", parts.into_iter().flatten().collect());
        };
        input(self, vec![isolated(), not_new_conn(), accept()]);
        let gw = || {
            let mut e = payload(false, 16);
            e.extend(cmp(pol
                .gateway
                .as_ref()
                .map(addr_bytes)
                .unwrap_or_default()));
            e
        };
        input(
            self,
            vec![isolated(), gw(), l4(IPPROTO_UDP), dport(DNS_PORT), accept()],
        );
        input(
            self,
            vec![isolated(), gw(), l4(IPPROTO_TCP), dport(DNS_PORT), accept()],
        );
        input(
            self,
            vec![isolated(), l4(IPPROTO_TCP), dport(HTTP_PORT), accept()],
        );
        input(
            self,
            vec![isolated(), l4(IPPROTO_TCP), dport(HTTPS_PORT), accept()],
        );
        let tcp = self.add_set(
            family,
            "tcp",
            TYPE_INET_SERVICE,
            false,
            &port_elems(&pol.tcp_ports),
        );
        if !pol.tcp_ports.is_empty() {
            input(
                self,
                vec![
                    isolated(),
                    gw(),
                    l4(IPPROTO_TCP),
                    dport_in(&tcp),
                    bound_to_address(),
                    accept(),
                ],
            );
        }
        input(self, vec![isolated(), drop()]);
    }

    /// changeElements: make a set (created before this batch) hold want
    /// instead of have.
    fn change_elements(&mut self, set: &Set, have: &[Addr], want: &[Addr]) {
        let gone: Vec<Addr> = have.iter().filter(|a| !want.contains(a)).cloned().collect();
        let come: Vec<Addr> = want.iter().filter(|a| !have.contains(a)).cloned().collect();
        if !gone.is_empty() {
            self.elements(NFT_MSG_DELSETELEM, set, &addr_elems(&gone));
        }
        if !come.is_empty() {
            self.elements(NFT_MSG_NEWSETELEM, set, &addr_elems(&come));
        }
    }

    /// updateTable.
    fn update_table(&mut self, family: u8, old: &Policy, pol: &Policy) {
        let existing = |name: &str| Set {
            family,
            name: name.to_string(),
            id: 0,
        };
        let dst = existing("dst");
        let mut gone = Vec::new();
        for (app, members) in &old.members {
            let (_, chain) = app_names(app);
            let want = pol.members.get(app).map(Vec::as_slice).unwrap_or_default();
            for a in members {
                if !want.contains(a) {
                    gone.push(jump_elem(a, &chain));
                }
            }
        }
        if !gone.is_empty() {
            self.elements(NFT_MSG_DELSETELEM, &dst, &gone);
        }
        for app in old.members.keys() {
            if pol.members.contains_key(app) {
                continue;
            }
            let (set_name, chain) = app_names(app);
            self.flush_chain(family, &chain);
            self.del_chain(family, &chain);
            self.del_set(family, &set_name);
        }
        let mut come = Vec::new();
        for (app, want) in &pol.members {
            let (set_name, chain) = app_names(app);
            let had = old.members.get(app);
            match had {
                None => {
                    self.add_app_chain(family, app, want);
                }
                Some(have) => self.change_elements(&existing(&set_name), have, want),
            }
            let have = had.map(Vec::as_slice).unwrap_or_default();
            for a in want {
                if !have.contains(a) {
                    come.push(jump_elem(a, &chain));
                }
            }
        }
        if !come.is_empty() {
            self.elements(NFT_MSG_NEWSETELEM, &dst, &come);
        }
        if family == FAMILY_BRIDGE {
            return;
        }
        self.change_elements(&existing("open"), &old.open, &pol.open);
        let tcp = existing("tcp");
        let closed: Vec<u16> = old
            .tcp_ports
            .iter()
            .filter(|p| !pol.tcp_ports.contains(p))
            .copied()
            .collect();
        let opened: Vec<u16> = pol
            .tcp_ports
            .iter()
            .filter(|p| !old.tcp_ports.contains(p))
            .copied()
            .collect();
        if !closed.is_empty() {
            self.elements(NFT_MSG_DELSETELEM, &tcp, &port_elems(&closed));
        }
        if !opened.is_empty() {
            self.elements(NFT_MSG_NEWSETELEM, &tcp, &port_elems(&opened));
        }
    }

    /// The whole transaction: the queued messages between a batch begin
    /// and end, or nothing when none is queued (Go's Flush sends nothing
    /// then).
    pub fn transaction(&self) -> Vec<Msg> {
        if self.msgs.is_empty() {
            return Vec::new();
        }
        let edge = |ty| Msg {
            ty,
            flags: NLM_F_REQUEST,
            data: gen_header(0, NFNL_SUBSYS_NFTABLES),
        };
        let mut out = vec![edge(NFNL_MSG_BATCH_BEGIN)];
        out.extend(self.msgs.iter().cloned());
        out.push(edge(NFNL_MSG_BATCH_END));
        out
    }
}

/// isolate: replace the tables with ones built from pol.
pub fn isolate(pol: &Policy, first_set_id: u32) -> Batch {
    let mut b = Batch::new(first_set_id);
    for fam in FAMILIES {
        // Adding first makes the delete succeed when there is no table.
        b.add_table(fam);
        b.del_table(fam);
        b.add_table(fam);
        b.build_table(fam, pol);
    }
    b
}

/// updateIsolation: change the tables from old to pol in place.
pub fn update_isolation(old: &Policy, pol: &Policy, first_set_id: u32) -> Batch {
    let mut b = Batch::new(first_set_id);
    for fam in FAMILIES {
        b.update_table(fam, old, pol);
    }
    b
}

/// removeIsolation: delete the tables.
pub fn remove_isolation() -> Batch {
    let mut b = Batch::new(1);
    for fam in FAMILIES {
        b.add_table(fam);
        b.del_table(fam);
    }
    b
}

/// The message hasIsolation sends for a family: the table by name, which
/// the kernel answers with the table or an error.
pub fn get_table(family: u8) -> Msg {
    let mut data = gen_header(family, 0);
    data.extend(attrs(&[(1, &cstr(TABLE))]));
    Msg {
        ty: nft_type(NFT_MSG_GETTABLE),
        flags: NLM_F_REQUEST,
        data,
    }
}

/// sameFrame: two policies differ only in what updateIsolation changes in
/// place.
pub fn same_frame(a: &Policy, b: &Policy) -> bool {
    a.cidr == b.cidr
        && a.subnet == b.subnet
        && a.gateway == b.gateway
        && a.nodes == b.nodes
        && a.tcp_ports.is_empty() == b.tcp_ports.is_empty()
}

/// What Net.isolate does with a policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// The tables already hold it.
    Keep,
    /// Change them in place (rebuilding them when that fails).
    Update,
    /// Build them again.
    Rebuild,
}

impl Action {
    pub fn name(self) -> &'static str {
        match self {
            Action::Keep => "keep",
            Action::Update => "update",
            Action::Rebuild => "rebuild",
        }
    }
}

/// Net.isolate's choice for pol, given the policy last applied and whether
/// the tables exist (asked only when it matters: has is called at most
/// once).
pub fn decide(prev: Option<&Policy>, pol: &Policy, has: &mut dyn FnMut() -> bool) -> Action {
    let Some(prev) = prev else {
        return Action::Rebuild;
    };
    let mut known = None;
    let mut has = || *known.get_or_insert_with(&mut *has);
    if prev == pol && has() {
        return Action::Keep;
    }
    if same_frame(prev, pol) && has() {
        return Action::Update;
    }
    Action::Rebuild
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn a(s: &str) -> Addr {
        Addr::parse(s).unwrap()
    }

    fn policy() -> Policy {
        let mut members = BTreeMap::new();
        members.insert("web".to_string(), vec![a("10.120.0.5"), a("10.120.1.7")]);
        Policy {
            cidr: Prefix::parse("10.120.0.0/16").unwrap(),
            subnet: Prefix::parse("10.120.0.0/24").unwrap(),
            gateway: Some(a("10.120.0.1")),
            members,
            open: vec![a("10.120.0.5")],
            nodes: vec![a("10.0.0.1")],
            tcp_ports: vec![5432],
        }
    }

    #[test]
    fn attributes_pad_to_four_bytes() {
        let mut b = Vec::new();
        attr(&mut b, 1, b"abcde");
        assert_eq!(b.len(), 12);
        assert_eq!(&b[..2], &9u16.to_ne_bytes());
    }

    #[test]
    fn isolate_frames_a_transaction() {
        let tx = isolate(&policy(), 1).transaction();
        assert_eq!(tx.first().unwrap().ty, NFNL_MSG_BATCH_BEGIN);
        assert_eq!(tx.last().unwrap().ty, NFNL_MSG_BATCH_END);
        // add, delete, add the ip table first.
        assert_eq!(tx[1].ty, nft_type(NFT_MSG_NEWTABLE));
        assert_eq!(tx[2].ty, nft_type(NFT_MSG_DELTABLE));
        assert_eq!(tx[1].data[0], FAMILY_IPV4);
    }

    #[test]
    fn updates_nothing_for_the_same_policy() {
        assert!(
            update_isolation(&policy(), &policy(), 1)
                .transaction()
                .is_empty()
        );
    }

    #[test]
    fn decides_like_the_agent() {
        let pol = policy();
        let mut other = policy();
        other.open.clear();
        let mut asked = 0;
        let mut yes = || {
            asked += 1;
            true
        };
        assert_eq!(decide(None, &pol, &mut yes), Action::Rebuild);
        assert_eq!(decide(Some(&pol), &pol, &mut yes), Action::Keep);
        assert_eq!(decide(Some(&pol), &other, &mut yes), Action::Update);
        assert_eq!(asked, 2);
        assert_eq!(decide(Some(&pol), &pol, &mut || false), Action::Rebuild);
        other.tcp_ports.clear();
        assert_eq!(decide(Some(&pol), &other, &mut || true), Action::Rebuild);
    }

    #[test]
    fn app_names_hash_the_app() {
        let (set, chain) = app_names("web");
        assert_eq!(set.len(), 17);
        assert_eq!(chain, format!("app{}", &set[1..]));
    }
}
