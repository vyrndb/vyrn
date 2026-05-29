use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
};
use tempfile::tempdir;
use vyrn_core::Engine;

#[test]
fn force_kill_preserves_every_acknowledged_write() {
    let directory = tempdir().unwrap();
    let actor = env!("CARGO_BIN_EXE_vyrn-crash-actor");
    let mut child = Command::new(actor)
        .arg(directory.path())
        .arg("1000")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut acknowledged = Vec::new();
    for line in BufReader::new(stdout).lines() {
        let line = line.unwrap();
        if let Some(index) = line.strip_prefix("ACK ") {
            acknowledged.push(index.parse::<u32>().unwrap());
            if acknowledged.len() == 25 {
                child.kill().unwrap();
                break;
            }
        }
    }
    let _ = child.wait();

    let engine = Engine::open(directory.path()).unwrap();
    for index in acknowledged {
        for suffix in ['a', 'b'] {
            assert_eq!(
                engine
                    .get(format!("crash/{index:08}/{suffix}").as_bytes())
                    .unwrap(),
                Some(format!("value-{index}-{suffix}").into_bytes()),
                "acknowledged transaction {index} was incomplete"
            );
        }
    }
}
