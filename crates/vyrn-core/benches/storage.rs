use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use tempfile::tempdir;
use vyrn_core::{BatchOperation, Engine};

fn durable_put(c: &mut Criterion) {
    c.bench_function("durable_put_128b", |bench| {
        bench.iter_batched(
            || {
                let directory = tempdir().unwrap();
                let engine = Engine::open(directory.path()).unwrap();
                (directory, engine)
            },
            |(_directory, mut engine)| {
                for index in 0..32_u64 {
                    engine
                        .put(index.to_be_bytes().to_vec(), vec![7; 128])
                        .unwrap();
                }
            },
            BatchSize::SmallInput,
        )
    });
}

fn durable_batch(c: &mut Criterion) {
    c.bench_function("durable_batch_32x128b", |bench| {
        bench.iter_batched(
            || {
                let directory = tempdir().unwrap();
                let engine = Engine::open(directory.path()).unwrap();
                (directory, engine)
            },
            |(_directory, mut engine)| {
                let operations = (0..32_u64)
                    .map(|index| BatchOperation::Put(index.to_be_bytes().to_vec(), vec![7; 128]))
                    .collect();
                engine.write_batch(operations).unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

fn cached_get(c: &mut Criterion) {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    for index in 0..1_000_u64 {
        engine
            .put(index.to_be_bytes().to_vec(), vec![7; 128])
            .unwrap();
    }
    c.bench_function("cached_get_128b", |bench| {
        let mut index = 0_u64;
        bench.iter(|| {
            let value = engine.get(&(index % 1_000).to_be_bytes()).unwrap();
            index += 1;
            std::hint::black_box(value)
        })
    });
}

criterion_group!(benches, durable_put, durable_batch, cached_get);
criterion_main!(benches);
