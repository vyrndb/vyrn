use std::{
    env,
    io::{self, Write},
    path::PathBuf,
    thread,
    time::Duration,
};
use vyrn_core::{BatchOperation, Engine};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(env::args_os().nth(1).ok_or("missing database path")?);
    let count: u32 = env::args().nth(2).ok_or("missing write count")?.parse()?;
    let mut engine = Engine::open(path)?;
    for index in 0..count {
        engine.write_batch(vec![
            BatchOperation::Put(
                format!("crash/{index:08}/a").into_bytes(),
                format!("value-{index}-a").into_bytes(),
            ),
            BatchOperation::Put(
                format!("crash/{index:08}/b").into_bytes(),
                format!("value-{index}-b").into_bytes(),
            ),
        ])?;
        println!("ACK {index}");
        io::stdout().flush()?;
        thread::sleep(Duration::from_millis(2));
    }
    Ok(())
}
