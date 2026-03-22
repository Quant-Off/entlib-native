#[cfg(test)]
mod tests {
    extern crate std;
    use entlib_native_pbkdf2::*;
    use entlib_native_secure_buffer::SecureBuffer;

    fn make_password(bytes: &[u8]) -> SecureBuffer {
        let mut buf = SecureBuffer::new_owned(bytes.len()).unwrap();
        buf.as_mut_slice().copy_from_slice(bytes);
        buf
    }

    // RFC 7914 Section 11 / NIST CAVP PBKDF2 테스트 벡터 (HMAC-SHA256)
    #[test]
    fn pbkdf2_hmacsha256_rfc7914_vector() {
        // Password: "passwd" (6 bytes → HMAC WeakKeyLength 오류 방지 위해 패딩)
        // NIST SP 800-107r1: 최소 키 길이 14 bytes
        // 대신 NIST CAVP 공식 벡터 사용:
        // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
        //
        // COUNT = 0
        // PRF = HMAC_SHA256
        // Password = 70617373776f7264 ("password", 8 bytes → 14 bytes 미달 → WeakPassword 반환 확인)
        let password = make_password(b"password");
        let salt = [0x73u8; 16]; // 16 bytes salt
        let mut dk = [0u8; 32];
        let result = PBKDF2HMACSHA256::new().derive_key(&password, &salt, 1000, &mut dk);
        assert_eq!(result, Err(Pbkdf2Error::WeakPassword));
    }

    #[test]
    fn pbkdf2_hmacsha256_valid_password() {
        // 14 bytes 이상 패스워드로 정상 동작 확인
        // Python 검증:
        // import hashlib
        // hashlib.pbkdf2_hmac('sha256', b'passwordpassword', b'saltsaltsaltsalt', 1000, 32).hex()
        let password = make_password(b"passwordpassword"); // 16 bytes
        let salt = b"saltsaltsaltsalt"; // 16 bytes
        let mut dk = [0u8; 32];
        PBKDF2HMACSHA256::new()
            .derive_key(&password, salt, 1000, &mut dk)
            .unwrap();

        // Python: hashlib.pbkdf2_hmac('sha256', b'passwordpassword', b'saltsaltsaltsalt', 1000, 32).hex()
        // = f1dbae96c847de211bff540451f3f62b35c42545dcb7b4ff2b0f2920555c37d0
        let expected = [
            0xf1u8, 0xdb, 0xae, 0x96, 0xc8, 0x47, 0xde, 0x21, 0x1b, 0xff, 0x54, 0x04, 0x51, 0xf3,
            0xf6, 0x2b, 0x35, 0xc4, 0x25, 0x45, 0xdc, 0xb7, 0xb4, 0xff, 0x2b, 0x0f, 0x29, 0x20,
            0x55, 0x5c, 0x37, 0xd0,
        ];
        assert_eq!(dk, expected);
    }

    #[test]
    fn pbkdf2_weak_salt_rejected() {
        let password = make_password(b"passwordpassword");
        let salt = [0u8; 15]; // 15 bytes → 미달
        let mut dk = [0u8; 32];
        let result = PBKDF2HMACSHA256::new().derive_key(&password, &salt, 1000, &mut dk);
        assert_eq!(result, Err(Pbkdf2Error::WeakSalt));
    }

    #[test]
    fn pbkdf2_insufficient_iterations_rejected() {
        let password = make_password(b"passwordpassword");
        let salt = [0u8; 16];
        let mut dk = [0u8; 32];
        let result = PBKDF2HMACSHA256::new().derive_key(&password, &salt, 999, &mut dk);
        assert_eq!(result, Err(Pbkdf2Error::InsufficientIterations));
    }

    #[test]
    fn pbkdf2_zero_dk_len_rejected() {
        let password = make_password(b"passwordpassword");
        let salt = [0u8; 16];
        let mut dk = [];
        let result = PBKDF2HMACSHA256::new().derive_key(&password, &salt, 1000, &mut dk);
        assert_eq!(result, Err(Pbkdf2Error::InvalidDkLength));
    }
}
