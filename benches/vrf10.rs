use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::time::Duration;
#[allow(unused_must_use)]
use vrf_dalek::vrf10::{PublicKey10, SecretKey10, VrfProof10};
use vrf_dalek::vrf10_batchcompat::{VrfProof10BatchCompat, BatchVerifier, BatchItem};

fn vrf10(c: &mut Criterion) {
    let mut group = c.benchmark_group("VRF10");
    let alpha_string = [0u8; 23];
    let secret_key = SecretKey10::generate(&mut ChaCha20Rng::from_seed([0u8; 32]));
    let public_key = PublicKey10::from(&secret_key);

    let vrf_proof = VrfProof10::generate(&public_key, &secret_key, &alpha_string);
    group.bench_function("Generation", |b| {
        b.iter(|| {
            VrfProof10::generate(&public_key, &secret_key, &alpha_string);
        })
    });
    group.bench_function("Verification", |b| {
        b.iter(|| {
            vrf_proof.verify(&public_key, &alpha_string);
        })
    });
}

static SIZE_BATCHES: [usize; 1] = [256]; //[2, 4, 8, 16, 32, 64]; //, 128, 256, 512, 1024];
fn vrf10_batchcompat(c: &mut Criterion) {
    let mut group = c.benchmark_group("VRF10 Batch Compat");
    let nr_proofs = *SIZE_BATCHES.last().unwrap();
    let mut alpha = vec![0u8; 32];
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let mut batch_verifier = BatchVerifier::new();

    let secret_key = SecretKey10::generate(&mut rng);
    let public_key = PublicKey10::from(&secret_key);

    let vrf_proof = VrfProof10BatchCompat::generate(&public_key, &secret_key, &alpha);

    group.bench_function("Generation", |b| {
        b.iter(|| {
            VrfProof10BatchCompat::generate(&public_key, &secret_key, &alpha);
        })
    });
    group.bench_function("Single Verification", |b| {
        b.iter(|| {
            vrf_proof.verify(&public_key, &alpha);
        })
    });

    let mut alphas = Vec::with_capacity(nr_proofs);
    let mut pks = Vec::with_capacity(nr_proofs);
    let mut proofs = Vec::with_capacity(nr_proofs);
    // We generate `nr_proofs` valid proofs.
    for _ in 0..nr_proofs {
        rng.fill_bytes(&mut alpha);
        alphas.push(alpha.clone());
        let secret_key = SecretKey10::generate(&mut rng);
        let public_key = PublicKey10::from(&secret_key);
        pks.push(public_key);

        let vrf_proof = VrfProof10BatchCompat::generate(&public_key, &secret_key, &alpha);
        proofs.push(vrf_proof);
    }

    for size in SIZE_BATCHES {
        group.bench_with_input(
            BenchmarkId::new("Batch Verification", size),
            &size,
            |b, &i| {
                b.iter(|| {
                    let mut batch_verifier = BatchVerifier::new();

                    for index in 0..size {
                        batch_verifier.insert(BatchItem{
                            output: proofs[index].proof_to_hash(),
                            proof: proofs[index].clone(),
                            key: pks[index],
                            msg: alphas[index].clone(),
                        }).expect("Should not fail");
                    }
                    batch_verifier.verify().expect("Should pass");
                })
            },
        );
    }
}

criterion_group!(name = benches;
                 config = Criterion::default().measurement_time(Duration::new(10, 0));
                 targets = vrf10_batchcompat);
criterion_main!(benches);