#[allow(unused_must_use)]
use vrf_dalek::vrf10::{SecretKey10, PublicKey10, VrfProof10};
use rand_chacha::ChaCha20Rng;
use rand_core::{SeedableRng, RngCore};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use vrf_dalek::vrf10_batchcompat::VrfProof10BatchCompat;
use std::time::Duration;

fn vrf10(c: &mut Criterion) {
    let mut group = c.benchmark_group("VRF10");
    let alpha_string = [0u8; 23];
    let secret_key = SecretKey10::generate(&mut ChaCha20Rng::from_seed([0u8; 32]));
    let public_key = PublicKey10::from(&secret_key);

    let vrf_proof = VrfProof10::generate(&public_key, &secret_key, &alpha_string);
    group.bench_function("Generation", |b| b.iter(|| {VrfProof10::generate(&public_key, &secret_key, &alpha_string);}));
    group.bench_function("Verification", |b| b.iter(|| { vrf_proof.verify(&public_key, &alpha_string); }));
}

static SIZE_BATCHES: [usize; 6] = [2, 4, 8, 16, 32, 64];//, 128, 256, 512, 1024];
fn vrf10_batchcompat(c: &mut Criterion) {
    let mut group = c.benchmark_group("VRF10 Batch Compat");
    let nr_proofs = *SIZE_BATCHES.last().unwrap();
    let mut alpha = vec![0u8; 32];
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    let mut sks = Vec::with_capacity(nr_proofs);
    let mut pks = Vec::with_capacity(nr_proofs);
    let mut alphas = Vec::with_capacity(nr_proofs);
    let mut proofs = Vec::with_capacity(nr_proofs);
    let mut outputs = Vec::with_capacity(nr_proofs);

    // We generate `nr_proofs` valid proofs.
    for _ in 0..nr_proofs {
        rng.fill_bytes(&mut alpha);
        alphas.push(alpha.clone());
        let secret_key = SecretKey10::generate(&mut ChaCha20Rng::from_seed([0u8; 32]));
        let public_key = PublicKey10::from(&secret_key);

        let vrf_proof = VrfProof10BatchCompat::generate(&public_key, &secret_key, &alpha);
        sks.push(secret_key);
        pks.push(public_key);
        outputs.push(vrf_proof.proof_to_hash());
        proofs.push(vrf_proof);
    }
    group.bench_function("Generation", |b| b.iter(|| { VrfProof10BatchCompat::generate(&pks[0], &sks[0], &alphas[0]); }));
    group.bench_function("Single Verification", |b| b.iter(|| { proofs[0].verify(&pks[0], &alphas[0]); }));

    for size in SIZE_BATCHES {
        group.bench_with_input(BenchmarkId::new("Batch Verification", size), &size, |b, &i| {
            b.iter(|| VrfProof10BatchCompat::batch_verify(&proofs[..i], &pks[..i], &alphas[..i].to_vec(), &outputs[..i]))
        });
    }
}

criterion_group!(name = benches;
                 config = Criterion::default().measurement_time(Duration::new(5, 0));
                 targets = vrf10_batchcompat);
criterion_main!(benches);
