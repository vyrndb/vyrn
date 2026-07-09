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
        let key = document_key(&self.name, id)?;
        let previous = self
            .engine
            .get_internal(&key)?
            .map(|bytes| decode_object(&bytes))
            .transpose()?;
        let updates = self.index_updates(&key, previous.as_ref(), Some(&value))?;
        let bytes = serde_json::to_vec(&Value::Object(value))
            .map_err(|error| invalid_document(format!("document encoding failed: {error}")))?;
        self.engine
            .write_indexed_internal(vec![BatchOperation::Put(key, bytes)], updates)?;
        Ok(())
    }

    fn index_updates(
        &self,
        primary_key: &[u8],
        old: Option<&Map<String, Value>>,
        new: Option<&Map<String, Value>>,
    ) -> Result<Vec<IndexUpdate>> {
        self.indexes
            .keys()
            .map(|field| {
                Ok(IndexUpdate {
                    index: index_name(&self.name, field)?,
                    primary_key: primary_key.to_vec(),
                    old_value: old
                        .and_then(|object| object.get(field))
                        .map(encode_index_value)
                        .transpose()?,
                    new_value: new
                        .and_then(|object| object.get(field))
                        .map(encode_index_value)
                        .transpose()?,
                })
            })
            .collect()
    }
}

pub fn collection_key_prefix(collection: &str) -> Result<Vec<u8>> {
    collection_prefix(collection)
}

pub fn document_change_key(collection: &str, id: &str) -> Result<Vec<u8>> {
    document_key(collection, id)
}

pub fn document_id_from_key(collection: &str, key: &[u8]) -> Result<String> {
    decode_document_id(collection, key)
}

/// Decodes a stored document key into its collection and ID.
///
/// Returns `None` for any key that is not a well-formed document key, so the
/// change log can fall back to publishing the raw key.
pub fn change_target(key: &[u8]) -> Option<crate::change_log::DocumentTarget> {
    target_from_key(key)
}

pub(crate) fn target_from_key(key: &[u8]) -> Option<crate::change_log::DocumentTarget> {
    let encoded = key.strip_prefix(DOCUMENT_KEY_PREFIX)?;
    let (collection, rest) = read_segment(encoded)?;
    let (id, rest) = read_segment(rest)?;
    if !rest.is_empty() {
        return None;
    }
    Some(crate::change_log::DocumentTarget { collection, id })
}

fn read_segment(encoded: &[u8]) -> Option<(String, &[u8])> {
    if encoded.len() < 2 {
        return None;
    }
    let length = u16::from_be_bytes([encoded[0], encoded[1]]) as usize;
    if length == 0 || encoded.len() < 2 + length {
        return None;
    }
    let value = String::from_utf8(encoded[2..2 + length].to_vec()).ok()?;
    Some((value, &encoded[2 + length..]))
}

fn get_document(engine: &Engine, collection: &str, id: &str) -> Result<Option<Document>> {
    let key = document_key(collection, id)?;
    engine
        .get_internal(&key)?
        .map(|bytes| decode_document(id.to_owned(), &bytes))
        .transpose()
}

fn find_documents(
    engine: &Engine,
    collection: &str,
    indexes: &BTreeMap<String, bool>,
    field: &str,
    value: &Value,
    limit: usize,
) -> Result<Vec<Document>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    if !indexes.contains_key(field) {
        return Err(Error::IndexNotFound);
    }
    let index = index_name(collection, field)?;
    let value = encode_index_value(value)?;
    engine
        .lookup_index(&index, &value, limit)?
        .into_iter()
        .map(|key| {
            let id = decode_document_id(collection, &key)?;
            let bytes = engine
                .get_internal(&key)?
                .ok_or_else(|| invalid_document("document index references a missing document"))?;
            decode_document(id, &bytes)
        })
        .collect()
}

fn all_documents(engine: &Engine, collection: &str, limit: usize) -> Result<Vec<Document>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let prefix = collection_prefix(collection)?;
    let end = prefix_end(&prefix);
    engine
        .scan_internal(Some(&prefix), end.as_deref(), limit)?
        .into_iter()
        .map(|(key, value)| {
            let id = decode_document_id(collection, &key)?;
            decode_document(id, &value)
        })
        .collect()
}

fn validate_segment(kind: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(invalid_document(format!("{kind} cannot be empty")));
    }
    if value.len() > u16::MAX as usize {
        return Err(Error::KeyTooLarge);
    }
    Ok(())
}

fn collection_prefix(collection: &str) -> Result<Vec<u8>> {
    validate_segment("collection", collection)?;
    let mut key = DOCUMENT_PREFIX.to_vec();
    append_segment(&mut key, collection)?;
    Ok(key)
}

fn document_key(collection: &str, id: &str) -> Result<Vec<u8>> {
    validate_segment("document ID", id)?;
    let mut key = collection_prefix(collection)?;
    append_segment(&mut key, id)?;
    if key.len() > MAX_KEY_SIZE {
        return Err(Error::KeyTooLarge);
    }
    Ok(key)
