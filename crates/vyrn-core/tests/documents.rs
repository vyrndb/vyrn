use serde_json::{json, Value};
use tempfile::tempdir;
use vyrn_core::{document::IndexDefinition, Engine, Error};

fn user_indexes() -> Vec<IndexDefinition> {
    vec![
        IndexDefinition::new("email", true),
        IndexDefinition::new("role", false),
    ]
}

#[test]
fn documents_persist_and_keep_collections_isolated() {
    let directory = tempdir().unwrap();
    {
        let mut engine = Engine::open(directory.path()).unwrap();
        let mut users = engine.collection("users", &user_indexes()).unwrap();
        users
            .put(
                "alica",
                &json!({"email": "alica@example.com", "role": "admin"}),
            )
            .unwrap();
    }

    let mut engine = Engine::open(directory.path()).unwrap();
    let users = engine.collection("users", &user_indexes()).unwrap();
    let user = users.get("alica").unwrap().unwrap();
    assert_eq!(user.id, "alica");
    assert_eq!(user.value["email"], "alica@example.com");
    assert_eq!(users.all(10).unwrap(), vec![user]);
    drop(users);

    let sessions = engine.collection("sessions", &[]).unwrap();
    assert!(sessions.get("alica").unwrap().is_none());
}

#[test]
fn indexed_queries_follow_replacements_and_deletes() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    let mut users = engine.collection("users", &user_indexes()).unwrap();
    users
        .put(
            "one",
            &json!({"email": "one@example.com", "role": "member"}),
        )
        .unwrap();
    users
        .put(
            "two",
            &json!({"email": "two@example.com", "role": "member"}),
        )
        .unwrap();

    let members = users
        .find("role", &Value::String("member".into()), 10)
        .unwrap();
    assert_eq!(
        members
            .iter()
            .map(|document| document.id.as_str())
            .collect::<Vec<_>>(),
        ["one", "two"]
    );

    users
        .put("one", &json!({"email": "new@example.com", "role": "admin"}))
        .unwrap();
    assert!(users
        .find("email", &Value::String("one@example.com".into()), 1)
        .unwrap()
        .is_empty());
    assert_eq!(
        users
            .find("email", &Value::String("new@example.com".into()), 1)
            .unwrap()[0]
            .id,
        "one"
    );

    assert!(users.delete("two").unwrap());
    assert!(!users.delete("two").unwrap());
    assert_eq!(
        users
            .find("role", &Value::String("member".into()), 10)
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn unique_violation_does_not_write_the_document() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    let mut users = engine.collection("users", &user_indexes()).unwrap();
    users
        .put(
            "one",
            &json!({"email": "same@example.com", "role": "member"}),
        )
        .unwrap();

    let error = users
        .put(
            "two",
            &json!({"email": "same@example.com", "role": "admin"}),
        )
        .unwrap_err();
    assert!(matches!(error, Error::UniqueViolation { .. }));
    assert!(users.get("two").unwrap().is_none());
    assert_eq!(
        users
            .find("email", &Value::String("same@example.com".into()), 10)
            .unwrap()[0]
            .id,
        "one"
    );
}

#[test]
fn rejects_non_object_documents_and_composite_index_values() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    let mut users = engine.collection("users", &user_indexes()).unwrap();

    assert!(matches!(
        users.put("one", &json!([1, 2, 3])),
        Err(Error::InvalidDocument(_))
    ));
    assert!(matches!(
        users.put("one", &json!({"email": {"address": "one@example.com"}})),
        Err(Error::InvalidDocument(_))
    ));
    assert!(users.get("one").unwrap().is_none());
}

#[test]
fn stored_index_definition_must_match_requested_schema() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    drop(
        engine
            .collection("users", &[IndexDefinition::new("email", true)])
            .unwrap(),
    );

    assert!(matches!(
        engine.collection("users", &[IndexDefinition::new("email", false)]),
        Err(Error::InvalidDocument(_))
    ));
    assert!(matches!(
        engine.collection("users", &[]),
        Err(Error::InvalidDocument(_))
    ));
}

#[test]
fn indexes_cannot_be_added_after_documents_exist() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    {
        let mut users = engine.collection("users", &[]).unwrap();
        users
            .put("one", &json!({"email": "one@example.com"}))
            .unwrap();
    }

    assert!(matches!(
        engine.collection("users", &[IndexDefinition::new("email", true)]),
        Err(Error::InvalidDocument(_))
    ));
}
