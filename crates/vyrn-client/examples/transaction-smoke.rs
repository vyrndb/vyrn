use vyrn_client::{Client, Error};
use vyrn_protocol::ErrorCode;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("VYRN_URL")?;
    let mut first = Client::connect(&url).await?;
    let mut second = Client::connect(&url).await?;

    first.put(b"conflict".to_vec(), b"old".to_vec()).await?;
    let mut first_transaction = first.transaction().await?;
    let mut second_transaction = second.transaction().await?;
    first_transaction
        .put(b"conflict".to_vec(), b"first".to_vec())
        .await?;
    first_transaction.commit().await?;
    assert_eq!(
        second_transaction.get(b"conflict".to_vec()).await?,
        Some(b"old".to_vec())
    );
    second_transaction
        .put(b"conflict".to_vec(), b"second".to_vec())
        .await?;
    assert!(matches!(
        second_transaction.commit().await,
        Err(Error::Server {
            code: ErrorCode::Conflict,
            ..
        })
    ));

    let mut transaction = first.transaction().await?;
    transaction.put(b"a".to_vec(), b"one".to_vec()).await?;
    transaction.put(b"b".to_vec(), b"two".to_vec()).await?;
    assert_eq!(transaction.scan(None, None, Some(100)).await?.len(), 3);
    transaction.rollback().await?;
    assert_eq!(first.get(b"a".to_vec()).await?, None);
    assert_eq!(first.get(b"b".to_vec()).await?, None);

    let mut transaction = first.transaction().await?;
    transaction.put(b"a".to_vec(), b"one".to_vec()).await?;
    transaction.put(b"b".to_vec(), b"two".to_vec()).await?;
    transaction.commit().await?;
    assert_eq!(second.get(b"a".to_vec()).await?, Some(b"one".to_vec()));
    assert_eq!(second.get(b"b".to_vec()).await?, Some(b"two".to_vec()));

    first.put(b"doctor/a".to_vec(), b"on".to_vec()).await?;
    first.put(b"doctor/b".to_vec(), b"on".to_vec()).await?;
    let mut first_transaction = first.transaction().await?;
    let mut second_transaction = second.transaction().await?;
    assert_eq!(
        first_transaction.get(b"doctor/b".to_vec()).await?,
        Some(b"on".to_vec())
    );
    assert_eq!(
        second_transaction.get(b"doctor/a".to_vec()).await?,
        Some(b"on".to_vec())
    );
    first_transaction
        .put(b"doctor/a".to_vec(), b"off".to_vec())
        .await?;
    second_transaction
        .put(b"doctor/b".to_vec(), b"off".to_vec())
        .await?;
    first_transaction.commit().await?;
    assert!(matches!(
        second_transaction.commit().await,
        Err(Error::Server {
            code: ErrorCode::Conflict,
            ..
        })
    ));

    let mut range_transaction = first.transaction().await?;
    assert!(range_transaction
        .scan(
            Some(b"users/".to_vec()),
            Some(b"users0".to_vec()),
            Some(100)
        )
        .await?
        .is_empty());
    second
        .put(b"users/new".to_vec(), b"online".to_vec())
        .await?;
    range_transaction
        .put(b"audit/range".to_vec(), b"checked".to_vec())
        .await?;
    assert!(matches!(
        range_transaction.commit().await,
        Err(Error::Server {
            code: ErrorCode::Conflict,
            ..
        })
    ));

    first.create_index(b"email".to_vec(), true).await?;
    let mut transaction = first.transaction().await?;
    transaction
        .put(b"indexed/1".to_vec(), b"alice".to_vec())
        .await?;
    transaction
        .update_index(
            b"email".to_vec(),
            b"indexed/1".to_vec(),
            None,
            Some(b"alice@example.com".to_vec()),
        )
        .await?;
    transaction.commit().await?;
    assert_eq!(
        second
            .lookup_index(b"email".to_vec(), b"alice@example.com".to_vec(), Some(10),)
            .await?,
        vec![b"indexed/1".to_vec()]
    );
    let mut transaction = second.transaction().await?;
    transaction
        .put(b"indexed/2".to_vec(), b"other".to_vec())
        .await?;
    transaction
        .update_index(
            b"email".to_vec(),
            b"indexed/2".to_vec(),
            None,
            Some(b"alice@example.com".to_vec()),
        )
        .await?;
    assert!(matches!(
        transaction.commit().await,
        Err(Error::Server {
            code: ErrorCode::Storage | ErrorCode::Conflict,
            ..
        })
    ));
    first.drop_index(b"email".to_vec()).await?;
    println!("transaction smoke passed");
    Ok(())
}
