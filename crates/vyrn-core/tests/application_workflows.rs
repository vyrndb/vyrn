//! Whole application workflows against the document API.
//!
//! The property tests check one contract at a time over randomized inputs. An
//! application does something different: it strings several contracts together
//! and depends on the seam between them. A registration is a unique-index check
//! plus a document write plus an index update, and a failed one has to leave no
//! trace — not a reserved email, not a half-built index entry, not a document
//! nobody can reach.
//!
//! These are the sequences a real app performs, written out end to end, with the
//! database closed and reopened wherever a real deployment would restart. Every
//! case asserts through the query paths an app actually uses (`get`, `find`,
//! `all`) rather than by inspecting storage, because that is where a wrong answer
//! would actually reach a user.

use serde_json::{json, Value};
use tempfile::tempdir;
use vyrn_core::{document::IndexDefinition, Engine, Error, FailureInjector, FailurePoint};

/// Users are looked up by email at sign-in, so it is unique; role and status are
/// queried in bulk for admin screens, so they are not.
fn user_indexes() -> Vec<IndexDefinition> {
    vec![
        IndexDefinition::new("email", true),
        IndexDefinition::new("role", false),
        IndexDefinition::new("status", false),
    ]
}

fn user(email: &str, role: &str, status: &str) -> Value {
    json!({"email": email, "role": role, "status": status})
}

/// Registers a user, refusing an email that is already taken.
///
/// This is the shape the check has to take in an application: the unique index is
/// the authority, and the caller finds out by the write failing rather than by
/// asking first. Asking first would be a race in any concurrent deployment.
fn register(engine: &mut Engine, id: &str, email: &str) -> Result<(), Error> {
    let mut users = engine.collection("users", &user_indexes())?;
    users.put(id, &user(email, "member", "active"))
}

#[test]
fn a_registration_flow_enforces_unique_emails_across_restarts() {
    let directory = tempdir().unwrap();

    {
        let mut engine = Engine::open(directory.path()).unwrap();
        register(&mut engine, "alica", "alica@example.com").unwrap();
        register(&mut engine, "bleed", "bleed@example.com").unwrap();

        // A second registration on a taken email must fail, and must not disturb
        // the account that owns it.
        let error = register(&mut engine, "impostor", "alica@example.com").unwrap_err();
        assert!(
            matches!(error, Error::UniqueViolation { .. }),
            "got {error:?}"
        );
    }

    // The restart is the point: an in-memory uniqueness set would pass every
    // assertion above and then forget everything here.
    let mut engine = Engine::open(directory.path()).unwrap();
    let error = register(&mut engine, "impostor", "alica@example.com").unwrap_err();
    assert!(
        matches!(error, Error::UniqueViolation { .. }),
        "got {error:?}"
    );

    let users = engine.open_collection("users").unwrap();
    assert!(
        users.get("impostor").unwrap().is_none(),
        "a rejected registration left a document behind"
    );
    // The rejected write must not have taken the email hostage either: the
    // address still has to resolve to the account that registered it.
    let found = users
        .find("email", &json!("alica@example.com"), 10)
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, "alica");
    assert_eq!(
        users.all(100).unwrap().len(),
        2,
        "unexpected accounts exist"
    );
}

#[test]
fn changing_an_email_frees_the_old_address_for_reuse() {
    // The sequence that breaks a naive unique index: a user changes address, then
    // someone else claims the one they left. If the update only added the new
    // entry, the old address stays reserved forever and the second user is turned
    // away for no reason.
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    register(&mut engine, "alica", "old@example.com").unwrap();

    {
        let mut users = engine.collection("users", &user_indexes()).unwrap();
        users
            .put("alica", &user("new@example.com", "member", "active"))
            .unwrap();
    }

    {
        let users = engine.open_collection("users").unwrap();
        assert!(
            users
                .find("email", &json!("old@example.com"), 10)
                .unwrap()
                .is_empty(),
            "the previous address still resolves after a change"
        );
        let found = users.find("email", &json!("new@example.com"), 10).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "alica");
    }

    register(&mut engine, "newcomer", "old@example.com").unwrap();

    drop(engine);
    let engine = Engine::open(directory.path()).unwrap();
    let users = engine.open_collection("users").unwrap();
    let found = users.find("email", &json!("old@example.com"), 10).unwrap();
    assert_eq!(found.len(), 1, "the freed address resolves to one account");
    assert_eq!(found[0].id, "newcomer");
}

#[test]
fn deleting_an_account_releases_its_email_and_removes_it_from_listings() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    register(&mut engine, "alica", "alica@example.com").unwrap();
    register(&mut engine, "bleed", "bleed@example.com").unwrap();

    {
        let mut users = engine.collection("users", &user_indexes()).unwrap();
        assert!(users.delete("alica").unwrap());
        // Deleting twice is what a retried request does, and must not claim a
        // second success.
        assert!(!users.delete("alica").unwrap());
    }

    drop(engine);
    let mut engine = Engine::open(directory.path()).unwrap();
    {
        let users = engine.open_collection("users").unwrap();
        assert!(users.get("alica").unwrap().is_none());
        assert!(
            users
                .find("email", &json!("alica@example.com"), 10)
                .unwrap()
                .is_empty(),
            "a deleted account's email still resolves"
        );
        // The deleted account must be gone from bulk listings too, which is what
        // an admin screen reads.
        let members = users.find("role", &json!("member"), 100).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].id, "bleed");
    }

    // And the address is available again.
    register(&mut engine, "successor", "alica@example.com").unwrap();
    let users = engine.open_collection("users").unwrap();
    assert_eq!(
        users
            .find("email", &json!("alica@example.com"), 10)
            .unwrap()[0]
            .id,
        "successor"
    );
}

#[test]
fn a_non_unique_index_tracks_a_status_transition_in_bulk() {
    // The admin-screen query: everything with a given status. Suspending a user
    // has to move them between result sets, not add them to both.
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    for index in 0..6 {
        register(
            &mut engine,
            &format!("user{index}"),
            &format!("u{index}@example.com"),
        )
        .unwrap();
    }

    {
        let mut users = engine.collection("users", &user_indexes()).unwrap();
        for index in [1, 3, 5] {
            users
                .put(
                    &format!("user{index}"),
                    &user(&format!("u{index}@example.com"), "member", "suspended"),
                )
                .unwrap();
        }
    }

    drop(engine);
    let engine = Engine::open(directory.path()).unwrap();
    let users = engine.open_collection("users").unwrap();

    let mut active: Vec<_> = users
        .find("status", &json!("active"), 100)
        .unwrap()
        .into_iter()
        .map(|document| document.id)
        .collect();
    active.sort();
    assert_eq!(active, vec!["user0", "user2", "user4"]);

    let mut suspended: Vec<_> = users
        .find("status", &json!("suspended"), 100)
        .unwrap()
        .into_iter()
        .map(|document| document.id)
        .collect();
    suspended.sort();
    assert_eq!(suspended, vec!["user1", "user3", "user5"]);

    // Nobody was lost or duplicated by the transition.
    assert_eq!(users.all(100).unwrap().len(), 6);
}

#[test]
fn collections_do_not_leak_into_each_other() {
    // Two collections using the same field names and the same document IDs. An
    // index keyed without its collection would collide, and a session lookup
    // would start returning users.
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();

    {
        let mut users = engine.collection("users", &user_indexes()).unwrap();
        users
            .put("shared-id", &user("alica@example.com", "admin", "active"))
            .unwrap();
    }
    {
        let mut sessions = engine
            .collection("sessions", &[IndexDefinition::new("email", false)])
            .unwrap();
        sessions
            .put(
                "shared-id",
                &json!({"email": "alica@example.com", "token": "t1"}),
            )
            .unwrap();
        sessions
            .put(
                "other-id",
                &json!({"email": "alica@example.com", "token": "t2"}),
            )
            .unwrap();
    }

    drop(engine);
    let engine = Engine::open(directory.path()).unwrap();

    let users = engine.open_collection("users").unwrap();
    let sessions = engine.open_collection("sessions").unwrap();

    // The same email is unique among users and repeated among sessions, which is
    // only coherent if the indexes are genuinely separate.
    assert_eq!(
        users
            .find("email", &json!("alica@example.com"), 10)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        sessions
            .find("email", &json!("alica@example.com"), 10)
            .unwrap()
            .len(),
        2
    );

    // The shared ID resolves to a different document in each collection.
    assert_eq!(
        users.get("shared-id").unwrap().unwrap().value["role"],
        json!("admin")
    );
    assert_eq!(
        sessions.get("shared-id").unwrap().unwrap().value["token"],
        json!("t1")
    );
    assert_eq!(users.all(100).unwrap().len(), 1);
    assert_eq!(sessions.all(100).unwrap().len(), 2);
}

#[test]
fn a_crash_mid_registration_leaves_no_half_registered_account() {
    // The failure an application cannot recover from on its own: the process dies
    // between writing the document and writing its index entries. Either outcome
    // is acceptable — the account exists and is findable, or it does not exist at
    // all — but a document that exists and cannot be found by email would let the
    // address be claimed twice, and one that is findable but missing would break
    // every sign-in.
    for point in [
        FailurePoint::AfterWalWrite,
        FailurePoint::BeforeWalSync,
        FailurePoint::BeforePageSync,
        FailurePoint::AfterPageSync,
    ] {
        let directory = tempdir().unwrap();
        {
            let mut engine = Engine::open(directory.path()).unwrap();
            register(&mut engine, "existing", "existing@example.com").unwrap();
            engine.set_failure_injector(Some(FailureInjector::once(point)));
            // The write may fail or, depending on where the injected fault lands
            // relative to the durability barrier, succeed.
            let _ = register(&mut engine, "alica", "alica@example.com");
        }

        let engine = Engine::open(directory.path()).unwrap();
        let users = engine.open_collection("users").unwrap();

        // The account that was already there is untouched, whatever happened.
        assert_eq!(
            users
                .find("email", &json!("existing@example.com"), 10)
                .unwrap()
                .len(),
            1,
            "a failure at {point:?} disturbed an unrelated account"
        );

        let document = users.get("alica").unwrap();
        let by_email = users
            .find("email", &json!("alica@example.com"), 10)
            .unwrap();
        assert_eq!(
            document.is_some(),
            !by_email.is_empty(),
            "a failure at {point:?} left the document and its index disagreeing"
        );
        if document.is_some() {
            assert_eq!(by_email[0].id, "alica");
        }
        // Listings must agree with the same decision.
        let listed = users.all(100).unwrap().len();
        assert_eq!(listed, if document.is_some() { 2 } else { 1 });
    }
}

#[test]
fn an_export_and_import_carries_a_whole_application_dataset() {
    // The migration an operator performs on a format change, done the documented
    // way: export, create the collections on the fresh directory, import, rebuild
    // the indexes. Afterwards every query path an app uses has to answer exactly
    // as it did before, and uniqueness has to still be enforced.
    let source_dir = tempdir().unwrap();
    {
        let mut engine = Engine::open(source_dir.path()).unwrap();
        for index in 0..8 {
            register(
                &mut engine,
                &format!("user{index}"),
                &format!("u{index}@example.com"),
            )
            .unwrap();
        }
        {
            let mut users = engine.collection("users", &user_indexes()).unwrap();
            users
                .put("user2", &user("u2@example.com", "admin", "active"))
                .unwrap();
            assert!(users.delete("user7").unwrap());
        }
        let mut sessions = engine
            .collection("sessions", &[IndexDefinition::new("email", false)])
            .unwrap();
        sessions
            .put("s1", &json!({"email": "u0@example.com", "token": "t1"}))
            .unwrap();
    }

    let dump_dir = tempdir().unwrap();
    let dump = dump_dir.path().join("dump.vyrnl");
    {
        let engine = Engine::open(source_dir.path()).unwrap();
        vyrn_core::portable::export(&engine, &dump).unwrap();
    }

    let target_dir = tempdir().unwrap();
    let mut target = Engine::open(target_dir.path()).unwrap();
    target.collection("users", &user_indexes()).unwrap();
    target
        .collection("sessions", &[IndexDefinition::new("email", false)])
        .unwrap();
    vyrn_core::portable::import(&mut target, &dump).unwrap();
    assert_eq!(
        vyrn_core::document::rebuild_indexes(&mut target, "users").unwrap(),
        7,
        "the rebuild did not see every imported user"
    );
    vyrn_core::document::rebuild_indexes(&mut target, "sessions").unwrap();

    {
        let users = target.open_collection("users").unwrap();
        assert_eq!(
            users.all(100).unwrap().len(),
            7,
            "the deleted user came back"
        );
        assert!(users.get("user7").unwrap().is_none());
        assert_eq!(users.find("role", &json!("admin"), 100).unwrap().len(), 1);
        assert_eq!(users.find("role", &json!("member"), 100).unwrap().len(), 6);
        for index in [0, 1, 3, 4, 5, 6] {
            let found = users
                .find("email", &json!(format!("u{index}@example.com")), 10)
                .unwrap();
            assert_eq!(found.len(), 1, "u{index}@example.com did not survive");
            assert_eq!(found[0].id, format!("user{index}"));
        }
        let sessions = target.open_collection("sessions").unwrap();
        assert_eq!(
            sessions
                .find("email", &json!("u0@example.com"), 10)
                .unwrap()
                .len(),
            1
        );
    }

    // Uniqueness is live on the migrated copy, not merely reproduced.
    let error = register(&mut target, "impostor", "u0@example.com").unwrap_err();
    assert!(
        matches!(error, Error::UniqueViolation { .. }),
        "got {error:?}"
    );
    // And the freed address from the deleted account is genuinely available.
    register(&mut target, "recycled", "u7@example.com").unwrap();
}
