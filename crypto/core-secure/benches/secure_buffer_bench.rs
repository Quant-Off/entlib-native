/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use entlib_native_core_secure::secure_buffer::SecureBuffer;

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
