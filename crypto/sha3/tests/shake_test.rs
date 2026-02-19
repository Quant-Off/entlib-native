use entlib_native_sha3::api::*;

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_xof {
        ($type:ty, $update:expr, $output_len:expr, $expected:expr) => {{
            let mut hasher = <$type>::new();
            hasher.update($update);
            assert_eq!(hasher.finalize($output_len), $expected);
        }};
    }

    #[test]
    fn shake128_nist_vectors() {
        test_xof!(SHAKE128, b"", 32, b"\x7f\x9c\x2b\xa4\xe8\x8f\x82\x7d\x61\x60\x45\x50\x76\x05\x85\x3e\xd7\x3b\x80\x93\xf6\xef\xbc\x88\xeb\x1a\x6e\xac\xfa\x66\xef\x26");
    }

    #[test]
    fn shake256_nist_vectors() {
        test_xof!(SHAKE256, b"", 32, b"\x46\xb9\xdd\x2b\x0b\xa8\x8d\x13\x23\x3b\x3f\xeb\x74\x3e\xeb\x24\x3f\xcd\x52\xea\x62\xb8\x1b\x82\xb5\x0c\x27\x64\x6e\xd5\x76\x2f");
        test_xof!(SHAKE256, b"", 64, b"\x46\xb9\xdd\x2b\x0b\xa8\x8d\x13\x23\x3b\x3f\xeb\x74\x3e\xeb\x24\x3f\xcd\x52\xea\x62\xb8\x1b\x82\xb5\x0c\x27\x64\x6e\xd5\x76\x2f\xd7\x5d\xc4\xdd\xd8\xc0\xf2\x00\xcb\x05\x01\x9d\x67\xb5\x92\xf6\xfc\x82\x1c\x49\x47\x9a\xb4\x86\x40\x29\x2e\xac\xb3\xb7\xc4\xbe");
    }

    #[test]
    fn test_chunked_updates() {
        // 데이터를 분할하여 주입할 때의 상태 전이 무결성 검증
        // SHAKE128
        let mut hasher_chunked = SHAKE128::new();
        hasher_chunked.update(b"a");
        hasher_chunked.update(b"b");
        hasher_chunked.update(b"c");
        let digest_chunked = hasher_chunked.finalize(32);

        let mut hasher_single = SHAKE128::new();
        hasher_single.update(b"abc");
        let digest_single = hasher_single.finalize(32);
        assert_eq!(digest_chunked, digest_single);

        // SHAKE256
        let mut hasher_chunked = SHAKE256::new();
        hasher_chunked.update(b"a");
        hasher_chunked.update(b"b");
        hasher_chunked.update(b"c");
        let digest_chunked = hasher_chunked.finalize(64);

        let mut hasher_single = SHAKE256::new();
        hasher_single.update(b"abc");
        let digest_single = hasher_single.finalize(64);
        assert_eq!(digest_chunked, digest_single);
    }

    #[test]
    fn test_xof_prefix_consistency() {
        // 동일 입력에 대해 짧은 출력은 긴 출력의 접두사(prefix)임을 검증
        // SHAKE128
        let mut hasher_short = SHAKE128::new();
        hasher_short.update(b"test");
        let short = hasher_short.finalize(16);

        let mut hasher_long = SHAKE128::new();
        hasher_long.update(b"test");
        let long = hasher_long.finalize(32);
        assert_eq!(&long[..16], &short[..]);

        // SHAKE256
        let mut hasher_short = SHAKE256::new();
        hasher_short.update(b"test");
        let short = hasher_short.finalize(32);

        let mut hasher_long = SHAKE256::new();
        hasher_long.update(b"test");
        let long = hasher_long.finalize(64);
        assert_eq!(&long[..32], &short[..]);
    }
}
