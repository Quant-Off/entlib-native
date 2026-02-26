use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

// 프로젝트 구조에 맞게 경로를 수정하여 사용하십시오.
use entlib_native_chacha20::chacha20::{chacha20_poly1305_decrypt, chacha20_poly1305_encrypt};
use entlib_native_chacha20::chacha20_state::process_chacha20;

/// 순수 ChaCha20 블록 암호화 처리량 (Throughput) 벤치마크
/// 다양한 페이로드 크기(64B ~ 64KB)에 대한 스트림 암호화 성능을 측정합니다.
fn bench_chacha20_pure(c: &mut Criterion) {
    let mut group = c.benchmark_group("ChaCha20_Pure_Throughput");
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let counter = 1;

    for size in [64, 1024, 8192, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &s| {
            let data = vec![0u8; s];
            b.iter(|| {
                // black_box를 통해 컴파일러의 Dead Code Elimination 최적화 방지
                let _ = process_chacha20(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(counter),
                    black_box(&data),
                );
            });
        });
    }
    group.finish();
}

/// ChaCha20-Poly1305 AEAD 암호화 처리량 벤치마크
/// MAC 계산 및 메모리 복사 오버헤드가 포함된 실제 프로토콜 레벨의 암호화 성능을 측정합니다.
fn bench_aead_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("ChaCha20_Poly1305_Encrypt");
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = [0u8; 16]; // 일반적인 프로토콜 헤더 사이즈 가정

    for size in [64, 1024, 8192, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &s| {
            let pt = vec![0u8; s];
            b.iter(|| {
                let _ = chacha20_poly1305_encrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&aad),
                    black_box(&pt),
                );
            });
        });
    }
    group.finish();
}

/// 보안성 검증: 상수-시간(Constant-Time) 복호화 타이밍 벤치마크
/// 가장 중요한 보안 벤치마크입니다. 조작된 MAC이 입력되었을 때 Early-Return 하지 않고
/// 항상 동일한 복호화 연산을 수행하는지(Zero-Trust, 분기 완전 제거) 측정합니다.
/// 두 함수의 실행 시간 그래프가 완전히 일치(Overlapping)해야 안전한 구현입니다.
fn bench_aead_decrypt_constant_time(c: &mut Criterion) {
    let mut group = c.benchmark_group("ChaCha20_Poly1305_Decrypt_Security_Test");
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = [0u8; 16];

    // 8KB 페이로드 기준 테스트
    let pt_size = 8192;
    let pt = vec![0u8; pt_size];

    // 정상적인 암호문 및 태그 생성
    let valid_ct_buf = chacha20_poly1305_encrypt(&key, &nonce, &aad, &pt);
    let valid_ct = valid_ct_buf.inner.clone();

    // 조작된 태그를 가진 암호문 (마지막 바이트 1비트 반전)
    let mut invalid_ct = valid_ct.clone();
    let last_idx = invalid_ct.len() - 1;
    invalid_ct[last_idx] ^= 1;

    group.throughput(Throughput::Bytes(pt_size as u64));

    // Case 1: 인증에 성공하는 정상 트래픽
    group.bench_function("Valid_MAC_Traffic", |b| {
        b.iter(|| {
            let _ = chacha20_poly1305_decrypt(
                black_box(&key),
                black_box(&nonce),
                black_box(&aad),
                black_box(&valid_ct),
            );
        });
    });

    // Case 2: 인증에 실패하는 공격 트래픽
    // 정상 트래픽과 처리 시간/CPU 사이클이 동일해야 타이밍 공격에 안전합니다.
    group.bench_function("Invalid_MAC_Attack_Traffic", |b| {
        b.iter(|| {
            let _ = chacha20_poly1305_decrypt(
                black_box(&key),
                black_box(&nonce),
                black_box(&aad),
                black_box(&invalid_ct),
            );
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_chacha20_pure,
    bench_aead_encrypt,
    bench_aead_decrypt_constant_time
);
criterion_main!(benches);
