#[cfg(test)]
mod tests {
    use entlib_native_rng::anu_qrng::*;
    use entlib_native_rng::base_rng::RngError;
    use std::collections::HashSet;

    #[tokio::test]
    async fn test_fetch_secure_bytes_valid() {
        // 정상적인 길이의 난수 요청이 보안 버퍼(secure buffer)에 올바르게 적재되는지 검증
        let target_length = 32;

        match AnuQrngClient::fetch_secure_bytes(target_length).await {
            Ok(buffer) => {
                assert_eq!(
                    buffer.inner.len(),
                    target_length,
                    "요청한 길이와 반환된 버퍼의 크기가 일치하지 않습니다."
                );
            }
            Err(RngError::NetworkFailure(_)) | Err(RngError::ParseError) => {
                // 폐쇄망 환경이거나 ANU 서버의 정책 변경으로 인한 통신 불가 시 테스트를 안전하게 우회
                println!(
                    "Skipping network test: ANU QRNG service is currently unreachable or format changed."
                );
            }
            Err(e) => {
                panic!(
                    "예기치 않은 보안 모듈 에러(unexpected security module error): {:?}",
                    e
                );
            }
        }
    }

    #[tokio::test]
    async fn test_fetch_secure_bytes_invalid_bounds() {
        // 버퍼 오버플로 및 비정상적 메모리 할당을 방지하기 위한 경계값 검증
        // api가 허용하는 1~1024 범위를 벗어난 요청 시 명시적 에러반환
        assert!(AnuQrngClient::fetch_secure_bytes(0).await.is_err());
        assert!(AnuQrngClient::fetch_secure_bytes(1025).await.is_err());
    }

    #[test]
    fn test_parse_json_data_stability() {
        // 외부 라이브러리 없이 구현된 슬라이싱(slicing) 기반 파서의 정상 작동 검증
        let mock_json =
            r#"{"type":"uint8","length":5,"data":[12, 255, 0, 128, 42],"success":true}"#;
        let result = AnuQrngClient::parse_json_data(mock_json);

        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes, vec![12, 255, 0, 128, 42]);
    }

    #[test]
    fn test_parse_json_data_malformed() {
        // 손상된 페이로드(malformed payload) 주입 시 시스템이 패닉(panic)에 빠지지 않고
        // 안전하게 에러(error)를 반환하는지 검증
        let missing_data_json = r#"{"type":"uint8","length":5,"success":true}"#;
        assert!(AnuQrngClient::parse_json_data(missing_data_json).is_err());

        let unclosed_bracket_json = r#"{"type":"uint8","length":5,"data":[12, 255, 0"#;
        assert!(AnuQrngClient::parse_json_data(unclosed_bracket_json).is_err());

        let invalid_type_json = r#"{"type":"uint8","length":1,"data":[NaN],"success":false}"#;
        assert!(AnuQrngClient::parse_json_data(invalid_type_json).is_err());
    }

    #[tokio::test]
    async fn test_randomness_basic_entropy() {
        // 생성된 양자 난수(quantum random number)의 기본적인 무작위성(randomness)을 평가
        // 추출된 바이트 시퀀스 내의 고유값(unique values) 개수를 확인하여, 통신 오류로 인해
        // 0으로만 채워진 배열(zeroed array)이 반환되는 치명적 보안 결함을 방지함
        let len = 100;
        if let Ok(buffer) = AnuQrngClient::fetch_secure_bytes(len).await {
            let mut unique_values = HashSet::new();
            for &byte in &buffer.inner {
                unique_values.insert(byte);
            }

            // 100바이트 표본에서 이론적 엔트로피 $H(X)$가 0에 수렴하는 경우(동일한 값만 반복)를 실패로 간주합니다.
            assert!(
                unique_values.len() > 10,
                "추출된 난수의 엔트로피가 보안 요구사항을 충족하지 못합니다."
            );
        }
    }
}
