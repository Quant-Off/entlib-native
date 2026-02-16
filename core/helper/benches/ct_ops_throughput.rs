use criterion::{Criterion, Throughput, criterion_group, criterion_main};

use entlib_native_helper::constant_time::ConstantTimeOps;

const BATCH: u64 = 4096;

//
// ct_eq 처리량 — u8 ~ usize 전체 타입
//

fn ct_eq_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput/ct_eq");
    group.throughput(Throughput::Elements(BATCH));

    macro_rules! bench_eq {
        ($($ty:ty),+) => {$(
            group.bench_function(stringify!($ty), |b| {
                let pairs: Vec<($ty, $ty)> = (0..BATCH as usize)
                    .map(|i| (i as $ty, i.wrapping_add(1) as $ty))
                    .collect();
                b.iter(|| {
                    for &(a, other) in &pairs {
                        std::hint::black_box(a.ct_eq(other));
                    }
                })
            });
        )+};
    }

    bench_eq!(u8, u16, u32, u64, u128, usize);
    group.finish();
}

//
// ct_is_zero 처리량 — u32, u64
//

fn ct_is_zero_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput/ct_is_zero");
    group.throughput(Throughput::Elements(BATCH));

    group.bench_function("u32", |b| {
        let vals: Vec<u32> = (0..BATCH as u32).collect();
        b.iter(|| {
            for &v in &vals {
                std::hint::black_box(v.ct_is_zero());
            }
        })
    });

    group.bench_function("u64", |b| {
        let vals: Vec<u64> = (0..BATCH).collect();
        b.iter(|| {
            for &v in &vals {
                std::hint::black_box(v.ct_is_zero());
            }
        })
    });

    group.finish();
}

//
// ct_is_negative 처리량 — u32, u64
//

fn ct_is_negative_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput/ct_is_negative");
    group.throughput(Throughput::Elements(BATCH));

    group.bench_function("u32", |b| {
        let vals: Vec<u32> = (0..BATCH as u32).collect();
        b.iter(|| {
            for &v in &vals {
                std::hint::black_box(v.ct_is_negative());
            }
        })
    });

    group.bench_function("u64", |b| {
        let vals: Vec<u64> = (0..BATCH).collect();
        b.iter(|| {
            for &v in &vals {
                std::hint::black_box(v.ct_is_negative());
            }
        })
    });

    group.finish();
}

//
// ct_select 처리량 — u64
//

fn ct_select_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput/ct_select");
    group.throughput(Throughput::Elements(BATCH));

    group.bench_function("u64", |b| {
        let triples: Vec<(u64, u64, u64)> = (0..BATCH)
            .map(|i| (i, i.wrapping_mul(7), if i % 2 == 0 { !0u64 } else { 0u64 }))
            .collect();
        b.iter(|| {
            for &(a, other, mask) in &triples {
                std::hint::black_box(a.ct_select(other, mask));
            }
        })
    });

    group.finish();
}

//
// 티어 비교 — ct_eq: u32(Tier1) vs u8(Tier2) vs u128(Tier2)
//

fn ct_eq_tier_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("tier_comparison/ct_eq");
    group.throughput(Throughput::Elements(BATCH));

    group.bench_function("u32_tier1", |b| {
        let pairs: Vec<(u32, u32)> = (0..BATCH as usize)
            .map(|i| (i as u32, i.wrapping_add(1) as u32))
            .collect();
        b.iter(|| {
            for &(a, other) in &pairs {
                std::hint::black_box(a.ct_eq(other));
            }
        })
    });

    group.bench_function("u8_tier2", |b| {
        let pairs: Vec<(u8, u8)> = (0..BATCH as usize)
            .map(|i| (i as u8, i.wrapping_add(1) as u8))
            .collect();
        b.iter(|| {
            for &(a, other) in &pairs {
                std::hint::black_box(a.ct_eq(other));
            }
        })
    });

    group.bench_function("u128_tier2", |b| {
        let pairs: Vec<(u128, u128)> = (0..BATCH as usize)
            .map(|i| (i as u128, i.wrapping_add(1) as u128))
            .collect();
        b.iter(|| {
            for &(a, other) in &pairs {
                std::hint::black_box(a.ct_eq(other));
            }
        })
    });

    group.finish();
}

//
// Criterion 설정
//

criterion_group!(
    benches,
    ct_eq_throughput,
    ct_is_zero_throughput,
    ct_is_negative_throughput,
    ct_select_throughput,
    ct_eq_tier_comparison,
);
criterion_main!(benches);
