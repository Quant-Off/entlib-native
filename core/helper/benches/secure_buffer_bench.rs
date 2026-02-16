use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use entlib_native_helper::secure_buffer::SecureBuffer;

const SIZES: &[usize] = &[64, 256, 1_024, 4_096, 65_536, 1_048_576];

//
// SecureBuffer drop(wipe) 처리량
//

fn secure_buffer_wipe_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput/secure_buffer_wipe");

    for &size in SIZES {
        group.throughput(Throughput::Bytes(size as u64));

        let batch_size = if size >= 65_536 {
            BatchSize::LargeInput
        } else {
            BatchSize::SmallInput
        };

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter_batched(
                || SecureBuffer {
                    inner: vec![0xAA; size],
                },
                drop, // |buf| drop(buf)
                batch_size,
            )
        });
    }

    group.finish();
}

//
// Criterion 설정
//

criterion_group!(benches, secure_buffer_wipe_throughput);
criterion_main!(benches);
