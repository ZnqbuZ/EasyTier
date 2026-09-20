use std::collections::BTreeMap;

use crate::decl::{AttrDecl, AttrId};
use crate::value::Value;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttrSet {
    attrs: BTreeMap<AttrId, Value>,
}

impl AttrSet {
    pub fn new() -> Self {
        Self {
            attrs: BTreeMap::new(),
        }
    }

    pub fn set(&mut self, id: AttrId, val: Value) {
        self.attrs.insert(id, val);
    }

    pub fn set_decl(&mut self, decl: &AttrDecl, val: Value) {
        self.attrs.insert(decl.id, val);
    }

    pub fn get(&self, id: AttrId) -> Option<&Value> {
        self.attrs.get(&id)
    }

    pub fn get_decl(&self, decl: &AttrDecl) -> Option<&Value> {
        self.attrs.get(&decl.id)
    }

    pub fn get_or_unknown(&self, id: AttrId) -> Value {
        self.attrs.get(&id).cloned().unwrap_or(Value::Unknown)
    }

    pub fn get_decl_or_unknown(&self, decl: &AttrDecl) -> Value {
        self.attrs.get(&decl.id).cloned().unwrap_or(Value::Unknown)
    }

    pub fn remove(&mut self, id: AttrId) -> Option<Value> {
        self.attrs.remove(&id)
    }

    pub fn len(&self) -> usize {
        self.attrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.attrs.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AttrId, &Value)> {
        self.attrs.iter()
    }
}
