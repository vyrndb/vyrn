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
            indexes: definitions,
        })
    }

    pub fn collection_indexes(&self, name: &str) -> Result<Vec<(String, bool)>> {
        validate_segment("collection", name)?;
        Ok(stored_indexes(self, name)?.into_iter().collect())
    }

    pub fn open_collection(&self, name: impl Into<String>) -> Result<CollectionView<'_>> {
        let name = name.into();
        validate_segment("collection", &name)?;
        let indexes = stored_indexes(self, &name)?;
        Ok(CollectionView {
            engine: self,
            name,
            indexes,
        })
    }
}

pub struct CollectionView<'a> {
    engine: &'a Engine,
    name: String,
    indexes: BTreeMap<String, bool>,
}

impl CollectionView<'_> {
    pub fn get(&self, id: &str) -> Result<Option<Document>> {
        get_document(self.engine, &self.name, id)
    }

    pub fn find(&self, field: &str, value: &Value, limit: usize) -> Result<Vec<Document>> {
        find_documents(self.engine, &self.name, &self.indexes, field, value, limit)
    }

    pub fn all(&self, limit: usize) -> Result<Vec<Document>> {
        all_documents(self.engine, &self.name, limit)
    }
}

impl Collection<'_> {
    pub fn get(&self, id: &str) -> Result<Option<Document>> {
        get_document(self.engine, &self.name, id)
    }

    pub fn put<T: Serialize>(&mut self, id: &str, value: &T) -> Result<()> {
        let value = serde_json::to_value(value)
            .map_err(|error| invalid_document(format!("document is not valid JSON: {error}")))?;
        let Value::Object(value) = value else {
            return Err(invalid_document("document must be a JSON object"));
        };
        self.put_object(id, value)
    }

    pub fn delete(&mut self, id: &str) -> Result<bool> {
        let key = document_key(&self.name, id)?;
        let Some(previous) = self.engine.get_internal(&key)? else {
            return Ok(false);
        };
        let previous = decode_object(&previous)?;
        let updates = self.index_updates(&key, Some(&previous), None)?;
        let results = self
            .engine
            .write_indexed_internal(vec![BatchOperation::Delete(key)], updates)?;
        Ok(matches!(
            results.first(),
            Some(crate::BatchResult::Delete { existed: true })
        ))
    }

    pub fn find(&self, field: &str, value: &Value, limit: usize) -> Result<Vec<Document>> {
        find_documents(self.engine, &self.name, &self.indexes, field, value, limit)
    }

    pub fn all(&self, limit: usize) -> Result<Vec<Document>> {
        all_documents(self.engine, &self.name, limit)
    }

    fn put_object(&mut self, id: &str, value: Map<String, Value>) -> Result<()> {
