#[cfg(test)]
mod tests {
    use entlib_native_rng::base_rng::RngError;
    use entlib_native_rng::mixed::MixedRng;

    #[test]
    fn test_mixed_rng_initialization() {
        // MixedRng 초기화 테스트
        match MixedRng::new() {
            Ok(rng) => {
                // 초기화 성공 시, 내부 상태가 0이 아닌지 확인 (간접적 확인)
                // state 필드는 private이므로 직접 접근 불가하지만,
                // generate 호출을 통해 동작 여부 확인 가능
                let mut rng = rng;
                let result = rng.generate(32);
                assert!(
                    result.is_ok(),
                    "Failed to generate random bytes after initialization"
                );
            }
            Err(RngError::UnsupportedHardware) => {
                println!("Skipping initialization test: Hardware RNG not supported");
            }
            Err(e) => {
                panic!("Failed to initialize MixedRng: {:?}", e);
            }
        }
    }

    #[test]
    fn test_mixed_rng_generation_length() {
        // 다양한 길이의 난수 생성 테스트
        let lengths = [0, 1, 16, 64, 128, 1024];

        match MixedRng::new() {
            Ok(mut rng) => {
                for &len in &lengths {
                    match rng.generate(len) {
                        Ok(buffer) => {
                            assert_eq!(
                                buffer.inner.len(),
                                len,
                                "Buffer length mismatch for requested length: {}",
                                len
                            );
                        }
                        Err(e) => {
                            panic!(
                                "Failed to generate random bytes for length {}: {:?}",
                                len, e
                            );
                        }
                    }
                }
            }
            Err(RngError::UnsupportedHardware) => {
                println!("Skipping length test: Hardware RNG not supported");
            }
            Err(e) => {
                panic!("Failed to initialize MixedRng: {:?}", e);
            }
        }
    }

    #[test]
    fn test_mixed_rng_randomness() {
        // 생성된 난수의 무작위성 (기본적인 중복 검사)
        match MixedRng::new() {
            Ok(mut rng) => {
                let len = 32;
                let buf1 = rng.generate(len).expect("First generation failed");
                let buf2 = rng.generate(len).expect("Second generation failed");

                // 연속 호출 시 동일한 값이 나오지 않는지 확인
                assert_ne!(
                    buf1.inner, buf2.inner,
                    "Two consecutive random generations produced identical output"
                );
            }
            Err(RngError::UnsupportedHardware) => {
                println!("Skipping randomness test: Hardware RNG not supported");
            }
            Err(e) => {
                panic!("Failed to initialize MixedRng: {:?}", e);
            }
        }
    }

    #[test]
    fn test_mixed_rng_block_counter_increment() {
        // 블록 카운터 증가에 따른 출력 변화 확인
        // 64바이트(1블록) 이상 생성 시 내부 카운터가 증가하여 다음 블록이 생성되어야 함
        match MixedRng::new() {
            Ok(mut rng) => {
                // 128바이트 생성 (2개 블록)
                let len = 128;
                let buffer = rng.generate(len).expect("Generation failed");

                let (first_block, second_block) = buffer.inner.split_at(64);

                // 첫 번째 블록과 두 번째 블록이 달라야 함
                assert_ne!(
                    first_block, second_block,
                    "Consecutive blocks are identical, counter might not be incrementing"
                );
            }
            Err(RngError::UnsupportedHardware) => {
                println!("Skipping block counter test: Hardware RNG not supported");
            }
            Err(e) => {
                panic!("Failed to initialize MixedRng: {:?}", e);
            }
        }
    }
}
