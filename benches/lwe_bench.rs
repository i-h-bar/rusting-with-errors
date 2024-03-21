use std::fs;

use criterion::{Bencher, Criterion, criterion_group, criterion_main};

use lwe::keys::{public::Public, secret::Secret};

fn bench(c: &mut Criterion) {
    let secret = Secret::new(63);
    let public = Public::from(&secret);

    let message = fs::read_to_string("test.txt").expect("Test file not found");

    let encrypted = public.encrypt(&message);

    c.bench_function(
        "Encryption",
        |b: &mut Bencher| b.iter(|| public.encrypt(&message)),
    );

    c.bench_function(
        "Decryption",
        |b: &mut Bencher| b.iter(|| secret.decrypt(&encrypted)),
    );
}


criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = bench
}

criterion_main!(benches);
