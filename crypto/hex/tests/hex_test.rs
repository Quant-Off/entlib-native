mod tests {
    use entlib_native_hex::hex::{
        HexError, decode_secure, decode_to_slice_ct, encode_secure, encode_to_slice_ct,
    };

    //
    // 피호출자(Callee) 패턴 테스트: SecureBuffer 반환 API
    //

    #[test]
    fn test_encode_secure() {
        let data = b"entlib-native";
        let secure_buf = encode_secure(data);

        // SecureBuffer 내부에 올바른 인코딩 결과가 들어있는지 확인
        assert_eq!(secure_buf.inner, b"656e746c69622d6e6174697665".to_vec());
    }

    #[test]
    fn test_decode_secure_valid() {
        let expected = b"entlib-native";

        // 소문자 Hex 디코딩
        let secure_buf_lower = decode_secure("656e746c69622d6e6174697665").unwrap();
        assert_eq!(secure_buf_lower.inner, expected);

        // 대문자 Hex 디코딩
        let secure_buf_upper = decode_secure("656E746C69622D6E6174697665").unwrap();
        assert_eq!(secure_buf_upper.inner, expected);
    }

    #[test]
    fn test_decode_secure_invalid_length() {
        // 홀수 길이 입력
        let res = decode_secure("656e746c69622d6e617469766");

        assert!(matches!(res, Err(HexError::InvalidLength)));
    }

    #[test]
    fn test_decode_secure_invalid_data() {
        // 유효하지 않은 문자 'g' 포함
        let res = decode_secure("656e746c69622d6e6174697g65");

        // 타이밍 공격 방어를 위해 InvalidData가 정상적으로 반환되는지 확인
        assert!(matches!(res, Err(HexError::InvalidData)));
    }

    //
    // 호출자(Caller) 패턴 테스트: 외부 버퍼(Slice) 직접 작성 API
    //

    #[test]
    fn test_encode_to_slice_ct_valid() {
        let data = b"quant";
        let mut out = vec![0u8; 10]; // "quant"는 5바이트 -> 10바이트 Hex 필요

        encode_to_slice_ct(data, &mut out).unwrap();
        assert_eq!(out, b"7175616e74");
    }

    #[test]
    fn test_encode_to_slice_ct_buffer_too_small() {
        let data = b"quant";
        let mut out = vec![0u8; 8]; // 공간 부족 (10바이트 필요)

        let res = encode_to_slice_ct(data, &mut out);
        assert_eq!(res.unwrap_err(), HexError::BufferTooSmall);
    }

    #[test]
    fn test_decode_to_slice_ct_valid() {
        let hex_str = "7175616e74"; // "quant"
        let mut out = vec![0u8; 5];

        let len = decode_to_slice_ct(hex_str, &mut out).unwrap();
        assert_eq!(len, 5);
        assert_eq!(out, b"quant");
    }

    #[test]
    fn test_decode_to_slice_ct_buffer_too_small() {
        let hex_str = "7175616e74";
        let mut out = vec![0u8; 4]; // 공간 부족 (5바이트 필요)

        let res = decode_to_slice_ct(hex_str, &mut out);
        assert_eq!(res.unwrap_err(), HexError::BufferTooSmall);
    }

    #[test]
    fn test_decode_to_slice_ct_invalid_data_zeroing() {
        let hex_str = "7175616x74"; // 'x'가 포함된 잘못된 Hex 문자열
        let mut out = vec![0xFF; 5]; // 초기 버퍼 상태를 0xFF로 세팅

        let res = decode_to_slice_ct(hex_str, &mut out);

        // 잘못된 데이터 에러를 반환해야 함
        assert_eq!(res.unwrap_err(), HexError::InvalidData);

        // [중요 보안 검증] 연산 실패 시 버퍼에 씌어졌던 가비지 데이터가 즉시 0으로 소거(Zeroing)되어야 함
        assert_eq!(out, vec![0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    //
    // 엣지 케이스
    //

    #[test]
    fn test_empty_inputs() {
        // 빈 바이트 배열 인코딩
        let secure_buf = encode_secure(b"");
        assert!(secure_buf.inner.is_empty());

        let mut out_enc = vec![];
        encode_to_slice_ct(b"", &mut out_enc).unwrap();

        // 빈 문자열 디코딩
        let secure_dec = decode_secure("").unwrap();
        assert!(secure_dec.inner.is_empty());

        let mut out_dec = vec![];
        let len = decode_to_slice_ct("", &mut out_dec).unwrap();
        assert_eq!(len, 0);
    }
}
