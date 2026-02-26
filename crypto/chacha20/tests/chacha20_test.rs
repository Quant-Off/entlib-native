#[cfg(test)]
mod tests {
    use entlib_native_chacha20::chacha20::{chacha20_poly1305_decrypt, chacha20_poly1305_encrypt};

    /// RFC 8439 Section 2.8.2. ChaCha20-Poly1305 Test Vector
    #[test]
    fn test_rfc8439_aead_vector() {
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let expected_ciphertext: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        // 암호화 검증
        let ct_secure = chacha20_poly1305_encrypt(&key, &nonce, &aad, plaintext);
        let ct_len = ct_secure.inner.len();

        assert_eq!(
            ct_len,
            expected_ciphertext.len() + 16,
            "Ciphertext length mismatch"
        );
        assert_eq!(
            &ct_secure.inner[..ct_len - 16],
            &expected_ciphertext[..],
            "Ciphertext data mismatch"
        );
        assert_eq!(
            &ct_secure.inner[ct_len - 16..],
            &expected_tag[..],
            "MAC tag mismatch"
        );

        // 복호화 검증
        let pt_secure_opt = chacha20_poly1305_decrypt(&key, &nonce, &aad, &ct_secure.inner);
        assert!(
            pt_secure_opt.is_some(),
            "Decryption failed for valid RFC 8439 vector"
        );

        let pt_secure = pt_secure_opt.unwrap();
        assert_eq!(
            &pt_secure.inner[..],
            plaintext,
            "Decrypted plaintext mismatch"
        );
    }

    /// 조작된 암호문(Ciphertext)이 입력될 경우 Fail-fast (None 반환) 처리되는지 검증합니다.
    #[test]
    fn test_aead_tampered_ciphertext() {
        let key = [0xAA; 32];
        let nonce = [0xBB; 12];
        let aad = b"header_data";
        let plaintext = b"secret_message";

        let valid_ct = chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext);

        // 1바이트 변조 (가장 첫 번째 암호문 바이트)
        let mut invalid_ct = valid_ct.inner.clone();
        invalid_ct[0] ^= 0x01;

        let result = chacha20_poly1305_decrypt(&key, &nonce, aad, &invalid_ct);
        assert!(
            result.is_none(),
            "Tampered ciphertext should NOT decrypt successfully"
        );
    }

    /// 조작된 연관 데이터(AAD)가 입력될 경우 Fail-fast (None 반환) 처리되는지 검증합니다.
    #[test]
    fn test_aead_tampered_aad() {
        let key = [0x11; 32];
        let nonce = [0x22; 12];
        let aad = b"protocol_v1";
        let plaintext = b"login_request";

        let valid_ct = chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext);

        // AAD 변조 (버전 정보 조작 시도)
        let tampered_aad = b"protocol_v2";

        let result = chacha20_poly1305_decrypt(&key, &nonce, tampered_aad, &valid_ct.inner);
        assert!(
            result.is_none(),
            "Tampered AAD should NOT decrypt successfully"
        );
    }

    /// 0-byte 평문 충돌 결함이 해결되었는지 검증합니다.
    /// 빈 평문을 암호화하고 정상적으로 복호화되는지 확인합니다.
    #[test]
    fn test_aead_empty_plaintext() {
        let key = [0x33; 32];
        let nonce = [0x44; 12];
        let aad = b"empty_payload_test";
        let plaintext: &[u8] = b"";

        let ct_secure = chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext);

        // 암호문은 순수하게 16바이트의 MAC Tag로만 구성되어야 함
        assert_eq!(ct_secure.inner.len(), 16);

        let pt_secure_opt = chacha20_poly1305_decrypt(&key, &nonce, aad, &ct_secure.inner);
        assert!(
            pt_secure_opt.is_some(),
            "0-byte plaintext should decrypt successfully"
        );

        let pt_secure = pt_secure_opt.unwrap();
        assert_eq!(
            pt_secure.inner.len(),
            0,
            "Decrypted plaintext should be empty"
        );
    }

    /// 입력 길이가 16바이트(MAC 크기) 미만인 악의적인 패킷에 대한 검증 로직 테스트
    #[test]
    fn test_aead_too_short_ciphertext() {
        let key = [0x55; 32];
        let nonce = [0x66; 12];
        let aad = b"";
        let short_ct = [0u8; 15]; // MAC 16바이트보다 짧은 데이터

        let result = chacha20_poly1305_decrypt(&key, &nonce, aad, &short_ct);
        assert!(
            result.is_none(),
            "Ciphertext shorter than 16 bytes must return None"
        );
    }
}
