use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use entlib_native_core_secure::secure_buffer::SecureBuffer;
use entlib_native_rng::base_rng::next_generate;
use entlib_native_sha2::api::*;
use std::hint::black_box;

fn sha2_benchmark(c: &mut Criterion) {
    // 메모리 할당 및 진난수 주입은 함수 진입점에서 단 1회만 수행하여 오버헤드를 차단합니다.
    let mut data = SecureBuffer {
        inner: vec![0u8; 1024],
    };
    next_generate(&mut data).expect("hardware rng failure");
    let data_slice = data.inner.as_slice();

    // 단일 벤치마크 그룹 생성
    let mut group = c.benchmark_group("throughput/sha2");

    //
    // SHA224 Benchmarks
    //
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("SHA224 16KiB", |b| {
        b.iter(|| {
            let mut hasher = SHA224::new();
            for _ in 0..16 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize());
        })
    });

    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("SHA224 1MiB", |b| {
        b.iter(|| {
            let mut hasher = SHA224::new();
            for _ in 0..1024 {
                // 1MiB 페이로드 처리
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize());
        })
    });

    //
    // SHA256 Benchmarks
    //
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("SHA256 16KiB", |b| {
        b.iter(|| {
            let mut hasher = SHA256::new();
            for _ in 0..16 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize());
        })
    });

    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("SHA256 1MiB", |b| {
        b.iter(|| {
            let mut hasher = SHA256::new();
            for _ in 0..1024 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize());
        })
    });

    //
    // SHA384 Benchmarks
    //
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("SHA384 16KiB", |b| {
        b.iter(|| {
            let mut hasher = SHA384::new();
            for _ in 0..16 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize());
        })
    });

    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("SHA384 1MiB", |b| {
        b.iter(|| {
            let mut hasher = SHA384::new();
            for _ in 0..1024 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize());
        })
    });

    //
    // SHA512 Benchmarks
    //
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("SHA512 16KiB", |b| {
        b.iter(|| {
            let mut hasher = SHA512::new();
            for _ in 0..16 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize());
        })
    });

    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("SHA512 1MiB", |b| {
        b.iter(|| {
            let mut hasher = SHA512::new();
            for _ in 0..1024 {
                hasher.update(black_box(data_slice));
            }
            black_box(hasher.finalize());
        })
    });

    group.finish();
}

criterion_group!(benches, sha2_benchmark);
criterion_main!(benches);
