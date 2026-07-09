use crate::{BatchOperation, Engine, Error, IndexUpdate, Result, MAX_KEY_SIZE};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Prefix shared by every stored document key. Exposed so the change log can
/// publish document mutations while hiding Vyrn's other internal keys.
pub(crate) const DOCUMENT_KEY_PREFIX: &[u8] = b"\0vyrn:doc:";
const DOCUMENT_PREFIX: &[u8] = DOCUMENT_KEY_PREFIX;
const INDEX_PREFIX: &[u8] = b"\0vyrn:doc-index:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexDefinition {
    pub field: String,
    pub unique: bool,
}

impl IndexDefinition {
    pub fn new(field: impl Into<String>, unique: bool) -> Self {
        Self {
            field: field.into(),
            unique,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Document {
    pub id: String,
    pub value: Map<String, Value>,
}

pub struct Collection<'a> {
    engine: &'a mut Engine,
    name: String,
    indexes: BTreeMap<String, bool>,
}

impl Engine {
    pub fn collection(
        &mut self,
        name: impl Into<String>,
        indexes: &[IndexDefinition],
    ) -> Result<Collection<'_>> {
        let name = name.into();
        validate_segment("collection", &name)?;
        let mut definitions = BTreeMap::new();
        for index in indexes {
            validate_segment("field", &index.field)?;
            if definitions
                .insert(index.field.clone(), index.unique)
                .is_some()
            {
                return Err(invalid_document("duplicate document index"));
            }
        }
        let stored = stored_indexes(self, &name)?;
        if !stored.is_empty() && stored != definitions {
            return Err(invalid_document(
                "document indexes do not match the stored collection definition",
            ));
        }
        if stored.is_empty() && !definitions.is_empty() {
            let prefix = collection_prefix(&name)?;
            let end = prefix_end(&prefix);
            if !self
                .scan_internal(Some(&prefix), end.as_deref(), 1)?
                .is_empty()
            {
                return Err(invalid_document(
                    "indexes cannot be added after a collection contains documents",
                ));
            }
            for (field, unique) in &definitions {
                self.create_index(index_name(&name, field)?, *unique)?;
            }
        }
        Ok(Collection {
            engine: self,
            name,
