use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use entlib_native_helper::secure_buffer::SecureBuffer;
use entlib_native_rng::base_rng::next_generate;
use entlib_native_sha3::api::*;
use std::hint::black_box;

fn sha3_benchmark(c: &mut Criterion) {
    // 메모리 할당 및 진난수 주입은 함수 진입점에서 단 1회만 수행하여 오버헤드를 차단합니다.
    let mut data = SecureBuffer {
        inner: vec![0u8; 1024],
    };
    next_generate(&mut data).expect("hardware rng failure");
    let data_slice = data.inner.as_slice();

    // 단일 벤치마크 그룹 생성
    let mut group = c.benchmark_group("throughput/sha3");

    //
    // SHA3-224 Benchmarks
    //
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("SHA3-224 16KiB", |b| {
        b.iter(|| {
            let mut hasher = SHA3_224::new();
            for _ in 0..16 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize());
        })
    });

    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("SHA3-224 1MiB", |b| {
        b.iter(|| {
            let mut hasher = SHA3_224::new();
            for _ in 0..1024 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize());
        })
    });

    //
    // SHA3-256 Benchmarks
    //
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("SHA3-256 16KiB", |b| {
        b.iter(|| {
            let mut hasher = SHA3_256::new();
            for _ in 0..16 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize());
        })
    });

    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("SHA3-256 1MiB", |b| {
        b.iter(|| {
            let mut hasher = SHA3_256::new();
            for _ in 0..1024 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize());
        })
    });

    //
    // SHA3-384 Benchmarks
    //
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("SHA3-384 16KiB", |b| {
        b.iter(|| {
            let mut hasher = SHA3_384::new();
            for _ in 0..16 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize());
        })
    });

    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("SHA3-384 1MiB", |b| {
        b.iter(|| {
            let mut hasher = SHA3_384::new();
            for _ in 0..1024 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize());
        })
    });

    //
    // SHA3-512 Benchmarks
    //
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("SHA3-512 16KiB", |b| {
        b.iter(|| {
            let mut hasher = SHA3_512::new();
            for _ in 0..16 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize());
        })
    });

    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("SHA3-512 1MiB", |b| {
        b.iter(|| {
            let mut hasher = SHA3_512::new();
            for _ in 0..1024 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize());
        })
    });

    //
    // SHAKE128 Benchmarks (32바이트 출력)
    //
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("SHAKE128 16KiB", |b| {
        b.iter(|| {
            let mut hasher = SHAKE128::new();
            for _ in 0..16 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize(32));
        })
    });

    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("SHAKE128 1MiB", |b| {
        b.iter(|| {
            let mut hasher = SHAKE128::new();
            for _ in 0..1024 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize(32));
        })
    });

    //
    // SHAKE256 Benchmarks (64바이트 출력)
    //
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("SHAKE256 16KiB", |b| {
        b.iter(|| {
            let mut hasher = SHAKE256::new();
            for _ in 0..16 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize(64));
        })
    });

    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("SHAKE256 1MiB", |b| {
        b.iter(|| {
            let mut hasher = SHAKE256::new();
            for _ in 0..1024 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize(64));
        })
    });

    group.finish();
}

criterion_group!(benches, sha3_benchmark);
criterion_main!(benches);
