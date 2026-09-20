use std::collections::BTreeMap;

use crate::attr_set::AttrSet;
use crate::decl::{AttrDecl, AttrId, Fold, Scope};
use crate::value::{Constraint, Value};

pub const MAX_CONSTRAINT_STATES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConstraintState {
    Unconstrained,
    Constrained(BTreeMap<AttrId, Value>),
}

impl ConstraintState {
    pub const fn unconstrained() -> Self {
        Self::Unconstrained
    }

    pub fn is_unconstrained(&self) -> bool {
        matches!(self, Self::Unconstrained)
    }

    pub fn initial(tracked: &[AttrDecl], start_node_attrs: &AttrSet) -> Option<Self> {
        let mut map = BTreeMap::new();
        for decl in tracked {
            if matches!(decl.scope, Scope::Node) {
                let v = start_node_attrs.get_or_unknown(decl.id);
                if v.is_unknown() {
                    return None;
                }
                let folded = fold_constraint_value(decl.fold, None, &v)?;
                map.insert(decl.id, folded);
            }
        }
        Some(Self::Constrained(map))
    }

    pub fn get(&self, id: AttrId) -> Option<&Value> {
        match self {
            Self::Unconstrained => None,
            Self::Constrained(map) => map.get(&id),
        }
    }

    pub fn satisfies_requirement(&self, require: &[Constraint]) -> bool {
        if require.is_empty() {
            return true;
        }
        match self {
            Self::Unconstrained => false,
            Self::Constrained(map) => {
                for c in require {
                    match map.get(&c.attr_id) {
                        Some(val) if val == &c.value => {}
                        _ => return false,
                    }
                }
                true
            }
        }
    }

    pub fn fold_into(
        &self,
        edge_attrs: &AttrSet,
        target_node_attrs: &AttrSet,
        tracked: &[AttrDecl],
    ) -> Option<Self> {
        match self {
            Self::Unconstrained => Some(Self::Unconstrained),
            Self::Constrained(map) => {
                let mut new_map = map.clone();
                for decl in tracked {
                    match decl.scope {
                        Scope::Edge => {
                            let v = edge_attrs.get_or_unknown(decl.id);
                            if v.is_unknown() {
                                return None;
                            }
                            let curr = new_map.get(&decl.id);
                            let next_val = fold_constraint_value(decl.fold, curr, &v)?;
                            new_map.insert(decl.id, next_val);
                        }
                        Scope::Node => {
                            let v = target_node_attrs.get_or_unknown(decl.id);
                            if v.is_unknown() {
                                return None;
                            }
                            let curr = new_map.get(&decl.id);
                            let next_val = fold_constraint_value(decl.fold, curr, &v)?;
                            new_map.insert(decl.id, next_val);
                        }
                    }
                }
                Some(Self::Constrained(new_map))
            }
        }
    }
}

pub fn fold_into(
    state: &ConstraintState,
    edge_attrs: &AttrSet,
    target_node_attrs: &AttrSet,
    tracked: &[AttrDecl],
) -> Option<ConstraintState> {
    state.fold_into(edge_attrs, target_node_attrs, tracked)
}

pub fn fold_constraint_value(
    fold: Fold,
    current: Option<&Value>,
    new_val: &Value,
) -> Option<Value> {
    if new_val.is_unknown() {
        return None;
    }

    match fold {
        Fold::MustMatch => match current {
            None => Some(new_val.clone()),
            Some(curr) => {
                if curr == new_val {
                    Some(curr.clone())
                } else {
                    None
                }
            }
        },
        Fold::AllTrue => match new_val {
            Value::Flag(true) => Some(Value::Flag(true)),
            _ => None,
        },
        Fold::Intersect => match current {
            None => match new_val {
                Value::Bits(b) if *b != 0 => Some(Value::Bits(*b)),
                _ => None,
            },
            Some(curr) => match (curr, new_val) {
                (Value::Bits(a), Value::Bits(b)) => {
                    let inter = a & b;
                    if inter == 0 {
                        None
                    } else {
                        Some(Value::Bits(inter))
                    }
                }
                _ => None,
            },
        },
        _ => None,
    }
}
