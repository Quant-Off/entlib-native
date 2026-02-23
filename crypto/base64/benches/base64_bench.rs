use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::time::Duration;

use entlib_native_base64::base64::{ct_b64_to_bin_u8, ct_bin_to_b64_u8};

//
// 보안성 — encode: 문자 클래스별 타이밍 비교
//

fn b64_encode_security(c: &mut Criterion) {
    let mut group = c.benchmark_group("security/b64_encode");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    // 대문자 범위 (0-25 → 'A'-'Z')
    let uppercase: Vec<u8> = (0..26).collect();
    // 소문자 범위 (26-51 → 'a'-'z')
    let lowercase: Vec<u8> = (26..52).collect();
    // 숫자 범위 (52-61 → '0'-'9')
    let digits: Vec<u8> = (52..62).collect();
    // 특수 문자 (62 → '+', 63 → '/')
    let special: Vec<u8> = vec![62, 63];
    // 전범위 (0-63)
    let full_range: Vec<u8> = (0..64).collect();

    for (name, inputs) in [
        ("uppercase", &uppercase),
        ("lowercase", &lowercase),
        ("digits", &digits),
        ("special", &special),
        ("full_range", &full_range),
    ] {
        group.bench_with_input(BenchmarkId::new(name, ""), inputs, |b, inputs| {
            b.iter(|| {
                for &byte in inputs {
                    std::hint::black_box(ct_bin_to_b64_u8(std::hint::black_box(byte)));
                }
            })
        });
    }

    group.finish();
}

//
// 보안성 — decode: 입력 클래스별 타이밍 비교
//

fn b64_decode_security(c: &mut Criterion) {
    let mut group = c.benchmark_group("security/b64_decode");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    // 유효 대문자 ('A'-'Z')
    let valid_upper: Vec<u8> = (b'A'..=b'Z').collect();
    // 유효 소문자 ('a'-'z')
    let valid_lower: Vec<u8> = (b'a'..=b'z').collect();
    // 유효 숫자 ('0'-'9')
    let valid_digit: Vec<u8> = (b'0'..=b'9').collect();
    // 무효 문자 (ASCII 제어 문자 + 비표준)
    let invalid: Vec<u8> = vec![0x00, 0x01, 0x7F, b'@', b'[', b'`', b'{', b'~', b'!', b'#'];
    // 공백 문자
    let whitespace: Vec<u8> = vec![b' ', b'\t', b'\r', b'\n'];

    for (name, inputs) in [
        ("valid_upper", &valid_upper),
        ("valid_lower", &valid_lower),
        ("valid_digit", &valid_digit),
        ("invalid", &invalid),
        ("whitespace", &whitespace),
    ] {
        group.bench_with_input(BenchmarkId::new(name, ""), inputs, |b, inputs| {
            b.iter(|| {
                for &byte in inputs {
                    std::hint::black_box(ct_b64_to_bin_u8(std::hint::black_box(byte)));
                }
            })
        });
    }

    group.finish();
}

//
// 처리량 — encode 전범위 (0..64), decode 전범위 (0..255)
//

fn b64_encode_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput/b64_encode");
    let inputs: Vec<u8> = (0..64).collect();
    group.throughput(Throughput::Elements(inputs.len() as u64));

    group.bench_function("0..64", |b| {
        b.iter(|| {
            for &byte in &inputs {
                std::hint::black_box(ct_bin_to_b64_u8(std::hint::black_box(byte)));
            }
        })
    });

    group.finish();
}

fn b64_decode_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput/b64_decode");
    let inputs: Vec<u8> = (0..=255).collect();
    group.throughput(Throughput::Elements(inputs.len() as u64));

    group.bench_function("0..255", |b| {
        b.iter(|| {
            for &byte in &inputs {
                std::hint::black_box(ct_b64_to_bin_u8(std::hint::black_box(byte)));
            }
        })
    });

    group.finish();
}

fn b64_encode_16kib_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput/b64_16kib_encode");

    // 16KiB (16384 bytes) 크기의 바이너리 입력 데이터 생성
    // 데이터 캐싱 최적화를 방지하기 위해 0~255 값을 순환 배정
    let inputs: Vec<u8> = (0..16384).map(|i| (i % 256) as u8).collect();

    // Throughput 단위를 Elements에서 Bytes로 변경하여 정확한 대역폭(MB/s) 산출
    group.throughput(Throughput::Bytes(inputs.len() as u64));

    group.bench_function("16KiB", |b| {
        b.iter(|| {
            for &byte in &inputs {
                std::hint::black_box(ct_bin_to_b64_u8(std::hint::black_box(byte)));
            }
        })
    });

    group.finish();
}

fn b64_decode_16kib_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput/b64_16kib_decode");

    // 유효한 base64 문자 집합을 순환하여 16KiB 데이터 구성
    // 디코딩 시 유효하지 않은 문자로 인한 조기 반환(early exit) 분기 예측을 방지
    let b64_chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let inputs: Vec<u8> = (0..16384).map(|i| b64_chars[i % 64]).collect();

    group.throughput(Throughput::Bytes(inputs.len() as u64));

    group.bench_function("16KiB", |b| {
        b.iter(|| {
            for &byte in &inputs {
                std::hint::black_box(ct_b64_to_bin_u8(std::hint::black_box(byte)));
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
    b64_encode_security,
    b64_decode_security,
    b64_encode_throughput,
    b64_decode_throughput,
    b64_encode_16kib_throughput,
    b64_decode_16kib_throughput
);
criterion_main!(benches);
