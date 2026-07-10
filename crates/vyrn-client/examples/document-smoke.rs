use serde_json::json;
use vyrn_client::{Client, CollectionIndex, Error};
use vyrn_protocol::ErrorCode;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("VYRN_URL")?;
    let mut client = Client::connect(&url).await?;

    client
        .create_collection(
            "smoke_users",
            &[
                CollectionIndex::new("email", true),
                CollectionIndex::new("role", false),
            ],
        )
        .await?;

    client.delete_document("smoke_users", "one").await?;
    client.delete_document("smoke_users", "two").await?;

    client
        .put_document(
            "smoke_users",
            "one",
            &json!({"email": "one@example.com", "role": "admin"}),
        )
        .await?;
    let document = client
        .get_document("smoke_users", "one")
        .await?
        .expect("document should exist");
    assert_eq!(document.value["email"], "one@example.com");

    let admins = client
        .query_documents("smoke_users", "role", &json!("admin"), Some(10))
        .await?;
    assert_eq!(admins.len(), 1);
    assert_eq!(admins[0].id, "one");

    client
        .put_document(
            "smoke_users",
            "two",
            &json!({"email": "one@example.com", "role": "member"}),
        )
        .await
        .expect_err("duplicate unique email must be rejected");
    assert!(client.get_document("smoke_users", "two").await?.is_none());

    client
        .put_document(
            "smoke_users",
            "one",
            &json!({"email": "moved@example.com", "role": "member"}),
        )
        .await?;
    assert!(client
        .query_documents("smoke_users", "email", &json!("one@example.com"), Some(10))
        .await?
        .is_empty());
    assert_eq!(
        client
            .query_documents(
                "smoke_users",
                "email",
                &json!("moved@example.com"),
                Some(10)
            )
            .await?
            .len(),
        1
    );

    assert_eq!(
        client.list_documents("smoke_users", Some(100)).await?.len(),
        1
    );

    let subscriber = Client::connect(&url).await?;
    let mut changes = subscriber.subscribe_collection("smoke_users").await?;
    let mut writer = Client::connect(&url).await?;
    writer
        .put_document(
            "smoke_users",
            "three",
            &json!({"email": "three@example.com"}),
        )
        .await?;
    let change = changes.next().await?.expect("change should arrive");
    assert_eq!(change.id, "three");
    assert_eq!(
        change.value.expect("document present")["email"],
        "three@example.com"
    );

    assert!(matches!(
        client
            .query_documents("smoke_users", "missing", &json!("x"), Some(10))
            .await,
        Err(Error::Server {
            code: ErrorCode::InvalidRequest,
            ..
        })
    ));

    assert!(client.delete_document("smoke_users", "one").await?);
    assert!(client.delete_document("smoke_users", "three").await?);
    println!("document smoke passed");
    Ok(())
}
