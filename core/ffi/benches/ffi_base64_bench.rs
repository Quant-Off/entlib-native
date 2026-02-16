use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::time::Duration;

use entlib_native_ffi::base64_ffi::{
    entlib_b64_decode_secure, entlib_b64_encode_secure, entlib_free_secure_buffer,
    entlib_secure_buffer_get_ptr,
};

const ENCODE_SIZES: &[usize] = &[3, 32, 256, 1_024, 4_096, 65_536, 1_048_576];

//
// 처리량 — encode: 입력 크기별 전체 lifecycle (encode → get_ptr → free)
//

fn ffi_encode_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput/ffi_b64_encode");

    for &size in ENCODE_SIZES {
        let input = vec![0x42u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &input, |b, input| {
            b.iter(|| {
                let mut out_len: usize = 0;
                let ptr =
                    unsafe { entlib_b64_encode_secure(input.as_ptr(), input.len(), &mut out_len) };
                let _ = unsafe { entlib_secure_buffer_get_ptr(ptr) };
                entlib_free_secure_buffer(ptr);
            })
        });
    }

    group.finish();
}

//
// 처리량 — decode: 사전 인코딩된 입력으로 decode lifecycle
//

fn ffi_decode_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput/ffi_b64_decode");

    for &size in ENCODE_SIZES {
        // 사전 인코딩: 원본 크기 size → Base64 인코딩된 데이터 생성
        let plain = vec![0x42u8; size];
        let mut enc_len: usize = 0;
        let enc_ptr =
            unsafe { entlib_b64_encode_secure(plain.as_ptr(), plain.len(), &mut enc_len) };
        let enc_data_ptr = unsafe { entlib_secure_buffer_get_ptr(enc_ptr) };
        let encoded: Vec<u8> =
            unsafe { std::slice::from_raw_parts(enc_data_ptr, enc_len) }.to_vec();
        entlib_free_secure_buffer(enc_ptr);

        group.throughput(Throughput::Bytes(encoded.len() as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &encoded, |b, encoded| {
            b.iter(|| {
                let mut out_len: usize = 0;
                let mut err_flag: u8 = 0;
                let ptr = unsafe {
                    entlib_b64_decode_secure(
                        encoded.as_ptr(),
                        encoded.len(),
                        &mut out_len,
                        &mut err_flag,
                    )
                };
                entlib_free_secure_buffer(ptr);
            })
        });
    }

    group.finish();
}

//
// 보안성 — decode: 유효 입력 vs 무효 문자 주입 (1KB)
//

fn ffi_decode_security(c: &mut Criterion) {
    let mut group = c.benchmark_group("security/ffi_b64_decode");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    // 유효 입력: 1KB 평문을 인코딩한 결과
    let valid_plain = vec![0x42u8; 1024];
    let mut enc_len: usize = 0;
    let enc_ptr =
        unsafe { entlib_b64_encode_secure(valid_plain.as_ptr(), valid_plain.len(), &mut enc_len) };
    let enc_data_ptr = unsafe { entlib_secure_buffer_get_ptr(enc_ptr) };
    let valid_encoded: Vec<u8> =
        unsafe { std::slice::from_raw_parts(enc_data_ptr, enc_len) }.to_vec();
    entlib_free_secure_buffer(enc_ptr);

    // 무효 입력: 같은 길이의 데이터에 무효 문자(0x00) 주입
    let mut invalid_encoded = valid_encoded.clone();
    for i in (0..invalid_encoded.len()).step_by(4) {
        invalid_encoded[i] = 0x00; // 무효 바이트 주입 (매 4번째)
    }

    group.bench_with_input(
        BenchmarkId::new("valid_1kb", ""),
        &valid_encoded,
        |b, input| {
            b.iter(|| {
                let mut out_len: usize = 0;
                let mut err_flag: u8 = 0;
                let ptr = unsafe {
                    entlib_b64_decode_secure(
                        input.as_ptr(),
                        input.len(),
                        &mut out_len,
                        &mut err_flag,
                    )
                };
                entlib_free_secure_buffer(ptr);
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("invalid_1kb", ""),
        &invalid_encoded,
        |b, input| {
            b.iter(|| {
                let mut out_len: usize = 0;
                let mut err_flag: u8 = 0;
                let ptr = unsafe {
                    entlib_b64_decode_secure(
                        input.as_ptr(),
                        input.len(),
                        &mut out_len,
                        &mut err_flag,
                    )
                };
                entlib_free_secure_buffer(ptr);
            })
        },
    );

    group.finish();
}

//
// Criterion 설정
//

criterion_group!(
    benches,
    ffi_encode_throughput,
    ffi_decode_throughput,
    ffi_decode_security,
);
criterion_main!(benches);
