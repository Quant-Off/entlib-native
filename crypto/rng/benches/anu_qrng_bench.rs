//! 베이스가 TLS 통신 처리라 기본적으로 그닥 성능이 좋지 못함
//! 하지만 난수가 Java로 전달되기 전의 지연율 상한성을 파악할 수 있어서
//! 혼합 rng 모듈이 양자 난수를 최초 1회만 받아야 하는 수학적 근거가 됌.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use entlib_native_rng::anu_qrng::AnuQrngClient;
use std::hint::black_box; // Q. T. Felix NOTE: std::hint blackbox
use std::time::Duration;

/// 섀넌 엔트로피(shannon entropy) 계산 함수
///
/// 주어진 바이트 시퀀스의 정보량을 측정합니다.
/// 대규모 및 군사급 보안 시스템에서는 난수 스트림의 엔트로피가 8.0에 수렴하는지 실시간으로
/// 평가(security evaluation)해야해서  해당 연산의 처리량(throughput) 측정은 필수적입니다.
fn compute_shannon_entropy(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let mut entropy = 0.0;
    let len = data.len() as f64;

    for &count in &counts {
        if count > 0 {
            let probability = count as f64 / len;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

/// 양자 난수 추출 처리량(throughput) 벤치마크
///
/// 외부 네트워크(curl) 호출 및 무의존성(zero-dependency) json 파서의 병목을 분석합니다.
fn bench_qrng_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("QRNG_Throughput");

    // 네트워크 지연(network latency)으로 인한 벤치마크 타임아웃을 방지하기 위해
    // 샘플 크기(sample size)를 축소하고 측정 시간을 연장합니다.
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    // 전략 패턴(strategy pattern)의 초기 상태 구성에 필요한 32바이트(키) 및 최대 허용치 1024바이트
    let lengths = [32usize, 256, 1024];

    for &len in &lengths {
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(
            BenchmarkId::new("fetch_secure_bytes", len),
            &len,
            |b, &size| {
                b.iter(|| {
                    // black_box를 통해 컴파일러의 데드 코드 제거(dead code elimination) 최적화 방지
                    let result = AnuQrngClient::fetch_secure_bytes(black_box(size));

                    // 네트워크 실패 시 벤치마크 패닉을 방지하고 에러 코드를 반환하도록 처리
                    if let Ok(buffer) = result {
                        black_box(buffer);
                    }
                });
            },
        );
    }

    group.finish();
}

/// 실시간 보안성 평가(security evaluation) 연산 오버헤드 벤치마크
fn bench_qrng_security_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("QRNG_Security_Evaluation");

    let sizes = [32usize, 256, 1024];

    for &size in &sizes {
        // 실제 API 호출로 인한 네트워크 병목을 배제하고, 순수 엔트로피 연산의
        // CPU 처리량(cpu throughput)만을 정밀하게 평가하기 위해 더미(dummy) 데이터를 구성합니다.
        let mock_data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("shannon_entropy", size), &size, |b, _| {
            b.iter(|| {
                let entropy = compute_shannon_entropy(black_box(&mock_data));
                black_box(entropy);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_qrng_throughput,
    bench_qrng_security_evaluation
);
criterion_main!(benches);
