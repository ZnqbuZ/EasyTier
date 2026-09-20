use std::time::{Duration, Instant};

pub type AttrId = u16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ValueKind {
    Flag,
    Enum,
    Int,
    Float,
    Bits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Fold {
    Sum,
    Min,
    Max,
    Product,
    Intersect,
    Union,
    MustMatch,
    AllTrue,
    Count,
}

impl Fold {
    pub const fn is_monotonic_constraint(&self) -> bool {
        matches!(self, Fold::MustMatch | Fold::AllTrue | Fold::Intersect)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Order {
    LowerBetter,
    HigherBetter,
    Incomparable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    Metric,
    Constraint,
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scope {
    Node,
    Edge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Source {
    Measured,
    Advertised,
    Configured,
    Derived,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Stamp {
    pub at: Instant,
    pub source: Source,
}

impl Stamp {
    pub fn new(source: Source) -> Self {
        Self {
            at: Instant::now(),
            source,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrDecl {
    pub id: AttrId,
    pub name: &'static str,
    pub kind: ValueKind,
    pub fold: Fold,
    pub order: Order,
    pub role: Role,
    pub scope: Scope,
    pub stale_after: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidDeclError(pub &'static str);

impl std::fmt::Display for InvalidDeclError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid AttrDecl: {}", self.0)
    }
}

impl std::error::Error for InvalidDeclError {}

impl AttrDecl {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        id: AttrId,
        name: &'static str,
        kind: ValueKind,
        fold: Fold,
        order: Order,
        role: Role,
        scope: Scope,
        stale_after: Option<Duration>,
    ) -> Result<Self, InvalidDeclError> {
        if matches!(role, Role::Constraint) && !fold.is_monotonic_constraint() {
            return Err(InvalidDeclError(
                "constraint fold must be prefix-monotonic (MustMatch, AllTrue, Intersect)",
            ));
        }
        Ok(Self {
            id,
            name,
            kind,
            fold,
            order,
            role,
            scope,
            stale_after,
        })
    }

    pub const fn new_constraint(
        id: AttrId,
        name: &'static str,
        kind: ValueKind,
        fold: Fold,
        scope: Scope,
    ) -> Result<Self, InvalidDeclError> {
        Self::new(
            id,
            name,
            kind,
            fold,
            Order::Incomparable,
            Role::Constraint,
            scope,
            None,
        )
    }
}

pub const TUNNEL_TYPE_ID: AttrId = 1;
pub const GSO_CAPABLE_ID: AttrId = 2;

pub const TUNNEL_TYPE: AttrDecl = AttrDecl {
    id: TUNNEL_TYPE_ID,
    name: "tunnel_type",
    kind: ValueKind::Enum,
    fold: Fold::MustMatch,
    order: Order::Incomparable,
    role: Role::Constraint,
    scope: Scope::Edge,
    stale_after: None,
};

pub const GSO_CAPABLE: AttrDecl = AttrDecl {
    id: GSO_CAPABLE_ID,
    name: "gso",
    kind: ValueKind::Flag,
    fold: Fold::AllTrue,
    order: Order::HigherBetter,
    role: Role::Constraint,
    scope: Scope::Node,
    stale_after: None,
};
