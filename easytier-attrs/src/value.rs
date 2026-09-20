use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use crate::decl::{AttrDecl, AttrId};

#[derive(Debug, Clone)]
pub enum Value {
    Unknown,
    Flag(bool),
    Enum(u16),
    Int(i64),
    Float(f64),
    Bits(u64),
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Unknown, Value::Unknown) => true,
            (Value::Flag(a), Value::Flag(b)) => a == b,
            (Value::Enum(a), Value::Enum(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => a.to_bits() == b.to_bits(),
            (Value::Bits(a), Value::Bits(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Value {}

impl Hash for Value {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Value::Unknown => {}
            Value::Flag(b) => b.hash(state),
            Value::Enum(e) => e.hash(state),
            Value::Int(i) => i.hash(state),
            Value::Float(f) => f.to_bits().hash(state),
            Value::Bits(b) => b.hash(state),
        }
    }
}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Value {
    fn cmp(&self, other: &Self) -> Ordering {
        let disc_a = std::mem::discriminant(self);
        let disc_b = std::mem::discriminant(other);
        match (self, other) {
            (Value::Unknown, Value::Unknown) => Ordering::Equal,
            (Value::Flag(a), Value::Flag(b)) => a.cmp(b),
            (Value::Enum(a), Value::Enum(b)) => a.cmp(b),
            (Value::Int(a), Value::Int(b)) => a.cmp(b),
            (Value::Float(a), Value::Float(b)) => a.total_cmp(b),
            (Value::Bits(a), Value::Bits(b)) => a.cmp(b),
            _ => format!("{:?}", disc_a).cmp(&format!("{:?}", disc_b)),
        }
    }
}

impl Value {
    pub fn is_unknown(&self) -> bool {
        matches!(self, Value::Unknown)
    }

    pub fn as_flag(&self) -> Option<bool> {
        match self {
            Value::Flag(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_enum(&self) -> Option<u16> {
        match self {
            Value::Enum(e) => Some(*e),
            _ => None,
        }
    }

    pub fn as_bits(&self) -> Option<u64> {
        match self {
            Value::Bits(b) => Some(*b),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum TunnelKind {
    Unknown = 0,
    Tcp = 1,
    Udp = 2,
    Wg = 3,
    Quic = 4,
    Ring = 5,
    Unix = 6,
    Ws = 7,
    Wss = 8,
    FakeTcp = 9,
}

impl TunnelKind {
    pub const ALL: &'static [TunnelKind] = &[
        TunnelKind::Tcp,
        TunnelKind::Udp,
        TunnelKind::Wg,
        TunnelKind::Quic,
        TunnelKind::Ring,
        TunnelKind::Unix,
        TunnelKind::Ws,
        TunnelKind::Wss,
        TunnelKind::FakeTcp,
    ];

    pub const fn to_bit(&self) -> u32 {
        1u32 << (*self as u32)
    }

    pub const fn as_u16(&self) -> u16 {
        *self as u16
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TunnelKind::Unknown => "unknown",
            TunnelKind::Tcp => "tcp",
            TunnelKind::Udp => "udp",
            TunnelKind::Wg => "wg",
            TunnelKind::Quic => "quic",
            TunnelKind::Ring => "ring",
            TunnelKind::Unix => "unix",
            TunnelKind::Ws => "ws",
            TunnelKind::Wss => "wss",
            TunnelKind::FakeTcp => "faketcp",
        }
    }

    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => TunnelKind::Tcp,
            2 => TunnelKind::Udp,
            3 => TunnelKind::Wg,
            4 => TunnelKind::Quic,
            5 => TunnelKind::Ring,
            6 => TunnelKind::Unix,
            7 => TunnelKind::Ws,
            8 => TunnelKind::Wss,
            9 => TunnelKind::FakeTcp,
            _ => TunnelKind::Unknown,
        }
    }

    pub fn from_bits(bits: u32) -> Vec<TunnelKind> {
        let mut kinds = Vec::new();
        for &k in Self::ALL {
            if (bits & k.to_bit()) != 0 {
                kinds.push(k);
            }
        }
        kinds
    }

    pub fn to_bits(kinds: impl IntoIterator<Item = TunnelKind>) -> u32 {
        let mut bits = 0u32;
        for k in kinds {
            bits |= k.to_bit();
        }
        bits
    }

    pub fn from_scheme(raw: &str) -> Self {
        let s = if let Some((scheme, _)) = raw.split_once("://") {
            scheme
        } else {
            raw
        };
        let s = s.trim();

        // Extract base protocol (ignoring IPv6 suffix '6' or prefix like 'txt-')
        let clean = s.strip_suffix('6').unwrap_or(s);
        let clean = clean.rsplit('-').next().unwrap_or(clean);

        match clean {
            "tcp" => TunnelKind::Tcp,
            "udp" => TunnelKind::Udp,
            "wg" => TunnelKind::Wg,
            "quic" => TunnelKind::Quic,
            "ring" => TunnelKind::Ring,
            "unix" => TunnelKind::Unix,
            "ws" => TunnelKind::Ws,
            "wss" => TunnelKind::Wss,
            "faketcp" => TunnelKind::FakeTcp,
            _ => {
                if s.contains("tcp") {
                    TunnelKind::Tcp
                } else if s.contains("udp") {
                    TunnelKind::Udp
                } else if s.contains("wg") {
                    TunnelKind::Wg
                } else if s.contains("quic") {
                    TunnelKind::Quic
                } else {
                    TunnelKind::Unknown
                }
            }
        }
    }

    pub fn select_preferred_from_bits(bits: u32) -> Self {
        if (bits & TunnelKind::Tcp.to_bit()) != 0 {
            TunnelKind::Tcp
        } else if (bits & TunnelKind::Udp.to_bit()) != 0 {
            TunnelKind::Udp
        } else if (bits & TunnelKind::Wg.to_bit()) != 0 {
            TunnelKind::Wg
        } else if (bits & TunnelKind::Quic.to_bit()) != 0 {
            TunnelKind::Quic
        } else if (bits & TunnelKind::Ws.to_bit()) != 0 {
            TunnelKind::Ws
        } else if (bits & TunnelKind::Wss.to_bit()) != 0 {
            TunnelKind::Wss
        } else if (bits & TunnelKind::Ring.to_bit()) != 0 {
            TunnelKind::Ring
        } else if (bits & TunnelKind::Unix.to_bit()) != 0 {
            TunnelKind::Unix
        } else if (bits & TunnelKind::FakeTcp.to_bit()) != 0 {
            TunnelKind::FakeTcp
        } else {
            TunnelKind::Unknown
        }
    }
}

pub fn edge_attrs_from_tunnel_type_bits(bits: u32) -> crate::attr_set::AttrSet {
    let mut attrs = crate::attr_set::AttrSet::new();
    let kind = TunnelKind::select_preferred_from_bits(bits);
    if kind != TunnelKind::Unknown {
        attrs.set_decl(&crate::decl::TUNNEL_TYPE, Value::Enum(kind as u16));
    }
    attrs
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Constraint {
    pub attr_id: AttrId,
    pub value: Value,
}

impl Constraint {
    pub fn new(decl: &AttrDecl, value: Value) -> Self {
        Self {
            attr_id: decl.id,
            value,
        }
    }

    pub fn matches(&self, val: &Value) -> bool {
        &self.value == val
    }
}
