use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use entlib_native_ffi::secure_buffer::entanglement_secure_wipe;

const SIZES: &[usize] = &[64, 256, 1_024, 4_096, 65_536, 1_048_576];

//
// 처리량 — secure wipe (각 반복마다 0xAA 재충전으로 반복 zero-wipe 최적화 방지)
//

fn ffi_wipe_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput/ffi_secure_wipe");

    for &size in SIZES {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut buffer = vec![0xAAu8; size];
            b.iter(|| {
                // 0xAA로 재충전 — 반복 zero-wipe 최적화 방지
                buffer.fill(0xAA);
                unsafe {
                    entanglement_secure_wipe(buffer.as_mut_ptr(), buffer.len());
                }
            })
        });
    }

    group.finish();
}

//
// Criterion 설정
//

criterion_group!(benches, ffi_wipe_throughput);
criterion_main!(benches);
