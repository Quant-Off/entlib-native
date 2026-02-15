use entlib_native_helper::base64::{ct_b64_to_bin_u8, ct_bin_to_b64_u8};

#[cfg(test)]
mod base64_constant_time_tests {
    use super::*;

    /// 인코딩
    #[test]
    fn test_ct_bin_to_b64_u8_exhaustive() {
        // 대문자 매핑 검증 (0 ~ 25 -> 'A' ~ 'Z')
        println!("Uppercase Encode");
        for i in 0..=25 {
            let encoded = ct_bin_to_b64_u8(i);
            println!("{}", encoded as char);
            assert_eq!(encoded, i + 65, "Failed at upper case index: {}", i);
        }

        // 소문자 매핑 검증 (26 ~ 51 -> 'a' ~ 'z')
        println!("Lowercase Encode");
        for i in 26..=51 {
            let encoded = ct_bin_to_b64_u8(i);
            println!("{}", encoded as char);
            assert_eq!(encoded, (i - 26) + 97, "Failed at lower case index: {}", i);
        }

        // 숫자 매핑 검증 (52 ~ 61 -> '0' ~ '9')
        println!("Number Encode");
        for i in 52..=61 {
            let encoded = ct_bin_to_b64_u8(i);
            println!("{}", encoded);
            assert_eq!(encoded, (i - 52) + 48, "Failed at digit index: {}", i);
        }

        // 특수 기호 매핑 검증
        assert_eq!(ct_bin_to_b64_u8(62), b'+', "Failed at '+' mapping");
        assert_eq!(ct_bin_to_b64_u8(63), b'/', "Failed at '/' mapping");
    }

    /// 디코딩
    #[test]
    fn test_ct_b64_to_bin_u8_exhaustive() {
        // 대문자 디코딩 검증 ('A' ~ 'Z' -> 0 ~ 25)
        println!("Uppercase Decode");
        for b in b'A'..=b'Z' {
            let decoded = ct_b64_to_bin_u8(b);
            println!("{}", decoded);
            assert_eq!(decoded, b - 65, "Failed decode at char: {}", b as char);
        }

        // 소문자 디코딩 검증 ('a' ~ 'z' -> 26 ~ 51)
        println!("Lowercase Decode");
        for b in b'a'..=b'z' {
            let decoded = ct_b64_to_bin_u8(b);
            println!("{}", decoded);
            assert_eq!(decoded, b - 97 + 26, "Failed decode at char: {}", b as char);
        }

        // 숫자 디코딩 검증 ('0' ~ '9' -> 52 ~ 61)
        println!("Number Decode");
        for b in b'0'..=b'9' {
            let decoded = ct_b64_to_bin_u8(b);
            println!("{}", decoded);
            assert_eq!(decoded, b - 48 + 52, "Failed decode at char: {}", b as char);
        }

        // 특수 기호 및 패딩, 공백 디코딩 검증
        assert_eq!(ct_b64_to_bin_u8(b'+'), 62, "Failed decode at '+'");
        assert_eq!(ct_b64_to_bin_u8(b'/'), 63, "Failed decode at '/'");
        assert_eq!(
            ct_b64_to_bin_u8(b'='),
            0x81,
            "Failed decode at '=' (padding)"
        );

        let whitespaces = [b' ', b'\t', b'\r', b'\n'];
        for ws in whitespaces.iter() {
            assert_eq!(ct_b64_to_bin_u8(*ws), 0x80, "Failed decode at whitespace");
        }

        // 유효하지 않은 문자열(invalid character) 디코딩 검증 (0xFF 반환 기대)
        let invalid_chars = [b'!', b'@', b'-', b'_', 0x00, 0x7F, 0xFF];
        for inv in invalid_chars.iter() {
            assert_eq!(
                ct_b64_to_bin_u8(*inv),
                0xFF,
                "Failed decode at invalid char: {}",
                inv
            );
        }
    }
}
