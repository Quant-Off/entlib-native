#[cfg(test)]
mod tests {
    use entlib_native_rng::base_rng::RngError;
    use entlib_native_rng::mixed::{EntropyStrategy, MixedRng};

    /// 등록된 모든 엔트로피 전략(entropy strategy)에 대해 동일한 테스트를 수행하기 위한 헬퍼 함수입니다.
    fn run_with_strategies<F>(test_logic: F)
    where
        F: Fn(EntropyStrategy, &str),
    {
        // 로컬 프로세서 하드웨어 난수 기반(trng)
        test_logic(EntropyStrategy::LocalHardware, "LocalHardware");
        // 외부 양자 난수 네트워크 통신 기반(qrng)
        test_logic(EntropyStrategy::QuantumNetwork, "QuantumNetwork");
    }

    #[test]
    fn test_mixed_rng_initialization() {
        // MixedRng 초기화 및 의존성 주입 테스트
        run_with_strategies(|strategy, strategy_name| {
            match MixedRng::new(strategy) {
                Ok(mut rng) => {
                    // 초기화 성공 시, 32바이트(byte) 난수 생성을 통한 내부 상태 무결성 확인
                    let result = rng.generate(32);
                    assert!(
                        result.is_ok(),
                        "[{}] Failed to generate random bytes after initialization",
                        strategy_name
                    );
                }
                Err(RngError::UnsupportedHardware) => {
                    println!(
                        "[{}] Skipping initialization test: Hardware RNG not supported",
                        strategy_name
                    );
                }
                Err(RngError::NetworkFailure) | Err(RngError::ParseError) => {
                    // 오프라인 환경 또는 방화벽에 의한 네트워크 차단 시 테스트 우회(skip)
                    println!(
                        "[{}] Skipping initialization test: Network or parsing unavailable",
                        strategy_name
                    );
                }
                Err(e) => {
                    panic!("[{}] Failed to initialize MixedRng: {:?}", strategy_name, e);
                }
            }
        });
    }

    #[test]
    fn test_mixed_rng_generation_length() {
        // 다양한 길이의 블록(block) 및 잔여 바이트 생성 테스트
        let lengths = [0, 1, 16, 64, 128, 1024];

        run_with_strategies(|strategy, strategy_name| match MixedRng::new(strategy) {
            Ok(mut rng) => {
                for &len in &lengths {
                    match rng.generate(len) {
                        Ok(buffer) => {
                            assert_eq!(
                                buffer.inner.len(),
                                len,
                                "[{}] Buffer length mismatch for requested length: {}",
                                strategy_name,
                                len
                            );
                        }
                        Err(e) => {
                            panic!(
                                "[{}] Failed to generate random bytes for length {}: {:?}",
                                strategy_name, len, e
                            );
                        }
                    }
                }
            }
            Err(RngError::UnsupportedHardware)
            | Err(RngError::NetworkFailure)
            | Err(RngError::ParseError) => {
                println!(
                    "[{}] Skipping length test: Dependency unavailable",
                    strategy_name
                );
            }
            Err(e) => {
                panic!("[{}] Failed to initialize MixedRng: {:?}", strategy_name, e);
            }
        });
    }

    #[test]
    fn test_mixed_rng_randomness() {
        // 생성된 난수 스트림(random stream)의 멱등성(idempotence) 및 중복 검사
        run_with_strategies(|strategy, strategy_name| {
            match MixedRng::new(strategy) {
                Ok(mut rng) => {
                    let len = 32;
                    let buf1 = rng.generate(len).expect("First generation failed");
                    let buf2 = rng.generate(len).expect("Second generation failed");

                    // 연속 호출 시 동일한 값이 출력되지 않음을 증명(내부 상태가 정상 갱신됨을 의미)
                    assert_ne!(
                        buf1.inner, buf2.inner,
                        "[{}] Two consecutive random generations produced identical output",
                        strategy_name
                    );
                }
                Err(RngError::UnsupportedHardware)
                | Err(RngError::NetworkFailure)
                | Err(RngError::ParseError) => {
                    println!(
                        "[{}] Skipping randomness test: Dependency unavailable",
                        strategy_name
                    );
                }
                Err(e) => {
                    panic!("[{}] Failed to initialize MixedRng: {:?}", strategy_name, e);
                }
            }
        });
    }

    #[test]
    fn test_mixed_rng_block_counter_increment() {
        // chacha20 코어(core) 블록 카운터(block counter) 증가에 따른 출력 전이 검증
        run_with_strategies(|strategy, strategy_name| {
            match MixedRng::new(strategy) {
                Ok(mut rng) => {
                    // 128바이트 생성 (64바이트 단위 2개 블록)
                    let len = 128;
                    let buffer = rng.generate(len).expect("Generation failed");

                    let (first_block, second_block) = buffer.inner.split_at(64);

                    // 블록 카운터가 올바르게 증가햇다면 두 블록의 암호학적 출력은 독립적이어야 함
                    assert_ne!(
                        first_block, second_block,
                        "[{}] Consecutive blocks are identical, counter might not be incrementing",
                        strategy_name
                    );
                }
                Err(RngError::UnsupportedHardware)
                | Err(RngError::NetworkFailure)
                | Err(RngError::ParseError) => {
                    println!(
                        "[{}] Skipping block counter test: Dependency unavailable",
                        strategy_name
                    );
                }
                Err(e) => {
                    panic!("[{}] Failed to initialize MixedRng: {:?}", strategy_name, e);
                }
            }
        });
    }
}
