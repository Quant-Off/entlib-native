#[cfg(test)]
mod tests {
    use entlib_native_hkdf::api::KdfSha256;

    /// 16진수 문자열을 Vec<u8>로 변환하는 헬퍼 함수
    fn decode_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("Hex string decoding failed"))
            .collect()
    }

    #[test]
    fn test_sp800_56c_api_consistency() {
        // API 구조 및 Extract + Expand 분할 호출과 Oneshot 호출의 결과가 일치하는지 검증
        let z = b"shared_secret_from_key_exchange_123456";
        let salt = b"random_salt_value_for_extraction";
        let label = b"KDF_Label_MasterKey";
        let context = b"KDF_Context_Session_A";
        let expected_len = 64; // SHA-256 출력(32바이트)보다 긴 64바이트 요청 (카운터 2회전)

        // 단계별 호출 (Extract -> Expand)
        let k_mc = KdfSha256::extract(Some(salt), z);
        let okm_step =
            KdfSha256::expand(&k_mc.inner, label, context, expected_len).expect("Expand failed");

        assert_eq!(
            okm_step.inner.len(),
            expected_len,
            "Step-by-step OKM length mismatch"
        );

        // 단일 호출 (Oneshot)
        let okm_oneshot = KdfSha256::oneshot(Some(salt), z, label, context, expected_len)
            .expect("Oneshot failed");

        assert_eq!(
            okm_oneshot.inner.len(),
            expected_len,
            "Oneshot OKM length mismatch"
        );

        // 정합성 검증
        assert_eq!(
            okm_step.inner, okm_oneshot.inner,
            "Consistency Error: Oneshot result does not match Step-by-step result"
        );
    }

    #[test]
    fn test_sp800_56c_empty_salt_handling() {
        // SP 800-56C Rev 2 규격에 따라 Salt가 제공되지 않았을 때
        // 해시 블록 사이즈(SHA-256의 경우 64바이트) 길이의 Zero 배열이 정상적으로 적용되는지 검증
        let z = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let label = decode_hex("f0f1f2");
        let context = decode_hex("f3f4f5");
        let expected_len = 32;

        // Salt가 None일 때 패닉 없이 정상적으로 K_mc 추출 및 확장이 이루어지는지 확인
        let okm = KdfSha256::oneshot(None, &z, &label, &context, expected_len);
        assert!(okm.is_ok(), "Oneshot failed with None salt");
        assert_eq!(okm.unwrap().inner.len(), expected_len);
    }

    #[test]
    fn test_sp800_108_counter_mode_large_output() {
        // 해시 출력 길이(32바이트)의 배수가 아닌 매우 긴 데이터(예: 100바이트)를 요청했을 때,
        // 카운터 루프가 정상적으로 동작하고 마지막 블록이 안전하게 잘려서(truncate 없이) 복사되는지 검증
        let z = b"ephemeral_shared_secret";
        let salt = b"salt";
        let label = b"enc_key_and_mac_key";
        let context = b"client_to_server";
        let expected_len = 100; // 100 bytes = 32 * 3 + 4 (총 4번의 카운터 루프 실행 필요)

        let okm = KdfSha256::oneshot(Some(salt), z, label, context, expected_len)
            .expect("Expand failed for large output");

        assert_eq!(
            okm.inner.len(),
            expected_len,
            "Failed to generate exact large output length"
        );
    }

    #[test]
    fn test_sp800_108_length_boundary_rejection() {
        // 잘못된 길이(0)를 요청했을 때 정상적으로 Err를 반환하는지 검증
        let z = b"secret";
        let label = b"label";
        let context = b"context";

        let result = KdfSha256::oneshot(None, z, label, context, 0);
        assert!(
            result.is_err(),
            "KDF should reject 0 length expansion request"
        );
    }
}
