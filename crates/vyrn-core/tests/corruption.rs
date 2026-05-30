use std::fs;
use tempfile::tempdir;
use vyrn_core::{BatchOperation, Engine};

#[test]
fn every_single_byte_truncation_recovers_or_fails_closed() {
    let source = tempdir().unwrap();
    {
        let mut engine = Engine::open(source.path()).unwrap();
        for index in 0..8_u32 {
            engine
                .put(format!("key-{index}").into_bytes(), vec![index as u8; 64])
                .unwrap();
        }
    }
    let wal = source.path().join("wal/00000000000000000001.vwal");
    let original = fs::read(&wal).unwrap();
    for length in 0..original.len() {
        let case = tempdir().unwrap();
        copy_database(source.path(), case.path());
        fs::write(
            case.path().join("wal/00000000000000000001.vwal"),
            &original[..length],
        )
        .unwrap();
        let result = Engine::open(case.path());
        if let Ok(engine) = result {
            let rows = engine.scan(None, None, usize::MAX).unwrap();
            assert!(rows.windows(2).all(|pair| pair[0].0 < pair[1].0));
        }
    }
}

#[test]
fn every_batch_truncation_recovers_all_or_none() {
    let source = tempdir().unwrap();
    {
        let mut engine = Engine::open(source.path()).unwrap();
        engine.put(b"before".to_vec(), b"present".to_vec()).unwrap();
        engine
            .write_batch(vec![
                BatchOperation::Put(b"a".to_vec(), b"one".to_vec()),
                BatchOperation::Put(b"b".to_vec(), b"two".to_vec()),
                BatchOperation::Delete(b"before".to_vec()),
            ])
            .unwrap();
    }
    let wal = source.path().join("wal/00000000000000000001.vwal");
    let original = fs::read(&wal).unwrap();
    for length in 32..original.len() {
        let case = tempdir().unwrap();
        copy_database(source.path(), case.path());
        fs::write(
            case.path().join("wal/00000000000000000001.vwal"),
            &original[..length],
        )
        .unwrap();
        if let Ok(engine) = Engine::open(case.path()) {
            let a = engine.get(b"a").unwrap();
            let b = engine.get(b"b").unwrap();
            let before = engine.get(b"before").unwrap();
            assert!(
                (a.is_none() && b.is_none())
                    || (a == Some(b"one".to_vec())
                        && b == Some(b"two".to_vec())
                        && before.is_none()),
                "batch was partially recovered at WAL length {length}: a={a:?}, b={b:?}, before={before:?}"
            );
        }
    }
}

#[test]
fn every_record_bit_flip_fails_closed_or_remains_structurally_valid() {
    let source = tempdir().unwrap();
    {
        let mut engine = Engine::open(source.path()).unwrap();
        engine.put(b"key".to_vec(), b"value".to_vec()).unwrap();
    }
    let wal = source.path().join("wal/00000000000000000001.vwal");
    let original = fs::read(&wal).unwrap();
    for index in 32..original.len() {
        let case = tempdir().unwrap();
        copy_database(source.path(), case.path());
        let mut changed = original.clone();
        changed[index] ^= 1;
        fs::write(case.path().join("wal/00000000000000000001.vwal"), changed).unwrap();
        if let Ok(engine) = Engine::open(case.path()) {
            let _ = engine.scan(None, None, usize::MAX).unwrap();
        }
    }
}

fn copy_database(source: &std::path::Path, target: &std::path::Path) {
    fs::create_dir_all(target.join("wal")).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name() == "LOCK" || entry.file_name() == "wal" {
            continue;
        }
        fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
    }
    for entry in fs::read_dir(source.join("wal")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), target.join("wal").join(entry.file_name())).unwrap();
    }
}
