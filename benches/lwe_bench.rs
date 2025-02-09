use std::fs;

use criterion::{criterion_group, criterion_main, Bencher, Criterion};

use lwe::keys::secret::Secret16;

fn bench(c: &mut Criterion) {
    let secret = Secret16::new();
    let public = secret.generate_public_key();

    let message = fs::read_to_string("test.txt").expect("Test file not found");

    let encrypted = public.encrypt(&message);

    // c.bench_function("Secret Creation", |b: &mut Bencher| {
    //     b.iter(|| Secret16::new())
    // });
    //
    // c.bench_function("Pub Creation", |b: &mut Bencher| {
    //     b.iter(|| secret.generate_public_key())
    // });
    //
    c.bench_function("Encryption", |b: &mut Bencher| {
        b.iter(|| public.encrypt(&message))
    });

    c.bench_function("Decryption", |b: &mut Bencher| {
        b.iter(|| secret.decrypt(&encrypted))
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = bench
}

criterion_main!(benches);
