//! Documents and their indexes, checked against a reference model.
//!
//! The plain key/value path already has an oracle in `model.rs`. The document
//! path did not, and it is the harder one: a document write touches the primary
//! key and every index entry derived from it, so the ways it can go wrong are
//! ways the primary and the index disagree — a stale index entry pointing at a
//! replaced document, a unique index that forgot a deletion and rejects a
//! legitimate reuse, an index that survives a crash the document did not.
//!
//! None of that is visible to a test that only reads documents back by ID, which
//! is how the export path shipped able to drop every document in a collection
//! and report success. So the model here tracks the index the way the engine is
//! supposed to maintain it, and every operation is followed by a comparison of
//! both the documents and every index query they imply.

use proptest::prelude::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use tempfile::tempdir;
use vyrn_core::{document::IndexDefinition, Engine};

/// Small domains on purpose: collisions are where index maintenance goes wrong,
/// so the generator has to produce the same role for many documents and force
/// unique-index conflicts and reuse-after-delete rather than wander a wide space.
const IDS: [&str; 6] = ["ada", "alan", "grace", "edsger", "barbara", "tony"];
const EMAILS: [&str; 4] = ["a@x", "b@x", "c@x", "d@x"];
const ROLES: [&str; 3] = ["admin", "user", "guest"];

fn indexes() -> Vec<IndexDefinition> {
    vec![
        IndexDefinition::new("email", true),
        IndexDefinition::new("role", false),
    ]
}

#[derive(Debug, Clone)]
enum Operation {
    Put {
        id: usize,
        email: usize,
        role: usize,
    },
    Delete(usize),
    Reopen,
    Checkpoint,
}

fn operation() -> impl Strategy<Value = Operation> {
    prop_oneof![
        8 => (0..IDS.len(), 0..EMAILS.len(), 0..ROLES.len())
            .prop_map(|(id, email, role)| Operation::Put { id, email, role }),
        4 => (0..IDS.len()).prop_map(Operation::Delete),
        1 => Just(Operation::Reopen),
        1 => Just(Operation::Checkpoint),
    ]
}

/// The reference model: which documents exist and what they hold. Every index
/// answer is derived from this rather than tracked alongside it, so the model
/// cannot drift the same way the engine might.
type Model = BTreeMap<String, (String, String)>;

fn model_document(model: &Model, id: &str) -> Option<Value> {
    model
        .get(id)
        .map(|(email, role)| json!({"email": email, "role": role}))
}

fn model_by_email<'a>(model: &'a Model, email: &str) -> Option<&'a String> {
    model
        .iter()
        .find(|(_, (stored, _))| stored == email)
        .map(|(id, _)| id)
}

fn model_by_role(model: &Model, role: &str) -> BTreeSet<String> {
    model
        .iter()
        .filter(|(_, (_, stored))| stored == role)
        .map(|(id, _)| id.clone())
        .collect()
}

/// Compares every document and every index query against the model.
///
/// Reading through a fresh `collection` handle each time is deliberate: the
/// handle caches index definitions, and a stale cache is exactly the kind of
/// bug that a long-lived handle would hide.
fn check(engine: &mut Engine, model: &Model) -> Result<(), TestCaseError> {
    let users = engine.collection("users", &indexes()).unwrap();

    for id in IDS {
        let actual = users.get(id).unwrap().map(
            |document| json!({"email": document.value["email"], "role": document.value["role"]}),
        );
        prop_assert_eq!(actual, model_document(model, id), "document {} differs", id);
    }

    // `all` must agree with the model as a set, so a document that is readable
    // by ID but missing from the collection listing is still caught.
    let listed: BTreeSet<String> = users
        .all(usize::MAX)
        .unwrap()
        .into_iter()
        .map(|document| document.id)
        .collect();
    let expected: BTreeSet<String> = model.keys().cloned().collect();
    prop_assert_eq!(listed, expected, "collection listing differs");

    for email in EMAILS {
        let found = users.find("email", &json!(email), usize::MAX).unwrap();
        prop_assert!(
            found.len() <= 1,
            "unique index {} returned {} documents",
            email,
            found.len()
        );
        let actual = found.first().map(|document| document.id.clone());
        prop_assert_eq!(
            actual.as_ref(),
            model_by_email(model, email),
            "unique index lookup for {} differs",
            email
        );
    }

    for role in ROLES {
        let actual: BTreeSet<String> = users
            .find("role", &json!(role), usize::MAX)
            .unwrap()
            .into_iter()
            .map(|document| document.id)
            .collect();
        prop_assert_eq!(
            actual,
            model_by_role(model, role),
            "index lookup for role {} differs",
            role
        );
    }

    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn documents_and_indexes_match_the_model(operations in prop::collection::vec(operation(), 1..40)) {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        let mut model = Model::new();

        for operation in operations {
            match operation {
                Operation::Put { id, email, role } => {
                    let (id, email, role) = (IDS[id], EMAILS[email], ROLES[role]);
                    // A unique index must reject a value another document holds,
                    // and must allow it once that document is gone or has moved
                    // on. The model decides which case this is, so a wrongly
                    // accepted or wrongly rejected write both fail here.
                    let holder = model_by_email(&model, email).cloned();
                    let conflict = holder.is_some_and(|holder| holder != id);
                    let mut users = engine.collection("users", &indexes()).unwrap();
                    let result = users.put(id, &json!({"email": email, "role": role}));
                    drop(users);
                    if conflict {
                        prop_assert!(
                            result.is_err(),
                            "unique index accepted a duplicate email {}",
                            email
                        );
                    } else {
                        result.unwrap();
                        model.insert(id.to_string(), (email.to_string(), role.to_string()));
                    }
                }
                Operation::Delete(id) => {
                    let id = IDS[id];
                    let mut users = engine.collection("users", &indexes()).unwrap();
                    let existed = users.delete(id).unwrap();
                    drop(users);
                    prop_assert_eq!(existed, model.remove(id).is_some(), "delete reported the wrong hit for {}", id);
                }
                Operation::Reopen => {
                    drop(engine);
                    engine = Engine::open(directory.path()).unwrap();
                }
                Operation::Checkpoint => {
                    engine.checkpoint().unwrap();
                }
            }
            check(&mut engine, &model)?;
        }

        // Whatever the history was, a dump of the final state has to reproduce it
        // exactly. This is the property the export path exists to provide, and the
        // one that silently failed: documents live under the reserved prefix, so
        // an exporter that filters them reports success and carries nothing.
        let dump_dir = tempdir().unwrap();
        let dump = dump_dir.path().join("dump.vyrnl");
        vyrn_core::portable::export(&engine, &dump).unwrap();
        let target_dir = tempdir().unwrap();
        let mut target = Engine::open(target_dir.path()).unwrap();
        // Indexes are derived state a dump does not carry, and they cannot be
        // declared on a collection that already holds documents, so they are
        // created on the empty target before the load. That ordering is the
        // documented import procedure, not a detail of this test.
        target.collection("users", &indexes()).unwrap();
        vyrn_core::portable::import(&mut target, &dump).unwrap();
        // A dump carries documents but not the index entries derived from them,
        // so an import leaves every document readable by ID and invisible to
        // `find` until the indexes are rebuilt. Skipping this step is a silent
        // wrong answer rather than an error, which is why the procedure includes
        // it and why the check below runs after it.
        vyrn_core::document::rebuild_indexes(&mut target, "users").unwrap();
        check(&mut target, &model)?;
    }
}
