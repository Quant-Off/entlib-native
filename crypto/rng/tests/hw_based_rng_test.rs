#[cfg(test)]
mod tests {
    use entlib_native_helper::secure_buffer::SecureBuffer;
    use entlib_native_rng::base_rng::{RngError, generate_hardware_random_bytes, next_generate};

    #[test]
    fn test_standard_next_generate_random_bytes() {
        let mut buffer = SecureBuffer {
            inner: vec![0u8; 1024],
        };
        match next_generate(&mut buffer) {
            Ok(_r) => {
                let res: String = buffer
                    .inner
                    .to_vec()
                    .iter()
                    .map(|b| format!("{:X?}", b))
                    .collect();
                println!("{}", res);
            }
            Err(_e) => {
                panic!("Failed");
            }
        }
    }

    #[test]
    fn test_generate_hardware_random_bytes_length() {
        // 다양한 길이의 난수 생성 요청 테스트
        let lengths = [0, 1, 8, 16, 32, 1024];

        for &len in &lengths {
            match generate_hardware_random_bytes(len) {
                Ok(buffer) => {
                    // 생성된 버퍼의 길이가 요청한 길이와 일치하는지 확인
                    assert_eq!(
                        buffer.inner.len(),
                        len,
                        "Buffer length mismatch for requested length: {}",
                        len
                    );
                }
                Err(RngError::UnsupportedHardware) => {
                    // 하드웨어 미지원 환경에서는 테스트 스킵 (CI 환경 등)
                    println!(
                        "Skipping test for length {}: Hardware RNG not supported",
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

    #[test]
    fn test_generate_hardware_random_bytes_randomness() {
        // 생성된 난수의 무작위성 (기본적인 중복 검사)
        // NOTE: 엄밀한 통계적 검증은 아니며, 연속 호출 시 동일한 값이 나오지 않는지 확인하는겁니다
        let len = 32;

        let buf1 = match generate_hardware_random_bytes(len) {
            Ok(b) => b,
            Err(RngError::UnsupportedHardware) => return, // 하드웨어 미지원 시 스킵
            Err(e) => panic!("First generation failed: {:?}", e),
        };

        let buf2 = match generate_hardware_random_bytes(len) {
            Ok(b) => b,
            Err(RngError::UnsupportedHardware) => return, // 하드웨어 미지원 시 스킵
            Err(e) => panic!("Second generation failed: {:?}", e),
        };

        // 두 번의 호출 결과가 완전히 동일할 확률은 극히 낮음
        assert_ne!(
            buf1.inner, buf2.inner,
            "Two consecutive random generations produced identical output"
        );
    }

    #[test]
    fn test_generate_hardware_random_bytes_non_zero() {
        // 생성된 난수가 모두 0이 아닌지 확인 (하드웨어 오류 감지)
        let len = 1024;
        match generate_hardware_random_bytes(len) {
            Ok(buffer) => {
                let is_all_zero = buffer.inner.iter().all(|&x| x == 0);
                assert!(
                    !is_all_zero,
                    "Generated random bytes are all zero, possible hardware failure"
                );
            }
            Err(RngError::UnsupportedHardware) => {
                println!("Skipping non-zero test: Hardware RNG not supported");
            }
            Err(e) => {
                panic!("Failed to generate random bytes: {:?}", e);
            }
        }
    }
}
