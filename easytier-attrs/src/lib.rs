pub mod attr_set;
pub mod decl;
pub mod state;
pub mod value;
pub mod version;

pub use attr_set::AttrSet;
pub use decl::{
    AttrDecl, AttrId, Fold, GSO_CAPABLE, GSO_CAPABLE_ID, InvalidDeclError, Order, Role, Scope,
    Source, Stamp, TUNNEL_TYPE, TUNNEL_TYPE_ID, ValueKind,
};
pub use state::{ConstraintState, MAX_CONSTRAINT_STATES, fold_constraint_value, fold_into};
pub use value::{Constraint, TunnelKind, Value, edge_attrs_from_tunnel_type_bits};
pub use version::{Version, VersionCounter};

#[cfg(test)]
mod tests;
