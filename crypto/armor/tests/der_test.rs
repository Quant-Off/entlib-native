#[cfg(test)]
mod tests {
    extern crate std;
    use entlib_native_armor::ArmorError::{ASN1, DER};
    use entlib_native_armor::asn1::{ASN1Error, Oid};
    use entlib_native_armor::der::{DerError, DerReader, DerWriter, MAX_DEPTH};
    use std::vec;

    //
    // 길이 인코딩
    //

    #[test]
    fn length_short_form_roundtrip() {
        let mut w = DerWriter::new();
        w.write_null().unwrap();
        // NULL = 05 00 (길이 0 → 단형식 0x00)
        assert_eq!(w.finish(), &[0x05, 0x00]);
    }

    #[test]
    fn length_long_form_roundtrip() {
        // 길이 128짜리 OCTET STRING: 04 81 80 [128 bytes of 0xAB]
        let data = vec![0xABu8; 128];
        let mut w = DerWriter::new();
        w.write_octet_string(&data).unwrap();
        let encoded = w.finish();
        assert_eq!(&encoded[..3], &[0x04, 0x81, 0x80]);

        let mut r = DerReader::new(&encoded).unwrap();
        let decoded = r.read_octet_string().unwrap();
        assert_eq!(decoded, data.as_slice());
        r.expect_empty().unwrap();
    }

    #[test]
    fn reject_indefinite_length() {
        // 0x30 0x80 ... (SEQUENCE with indefinite length)
        let input = [0x30u8, 0x80, 0x00, 0x00];
        let mut depth = MAX_DEPTH;
        let mut r = DerReader::new(&input).unwrap();
        let err = r.read_sequence(&mut depth).unwrap_err();
        assert_eq!(err, DER(DerError::IndefiniteLength));
    }

    #[test]
    fn reject_non_minimal_length() {
        // 길이 1을 장형식(0x81 0x01)으로 표현 — DER 위반
        let input = [0x04u8, 0x81, 0x01, 0xAA];
        let mut r = DerReader::new(&input).unwrap();
        let err = r.read_octet_string().unwrap_err();
        assert_eq!(err, DER(DerError::NonMinimalLength));
    }

    #[test]
    fn reject_length_leading_zero() {
        // 장형식 길이 앞에 0x00 (0x82 0x00 0x80)
        let input = [0x04u8, 0x82, 0x00, 0x80];
        let mut r = DerReader::new(&input).unwrap();
        let err = r.read_octet_string().unwrap_err();
        assert_eq!(err, DER(DerError::NonMinimalLength));
    }

    //
    // 태그 거부
    //

    #[test]
    fn reject_long_form_tag() {
        // 0x1F = 장형식 태그 시작 마커 → 거부
        let input = [0x1Fu8, 0x01, 0x01, 0x00];
        let mut r = DerReader::new(&input).unwrap();
        let err = r.read_tlv().unwrap_err();
        assert_eq!(err, DER(DerError::InvalidTag));
    }

    #[test]
    fn reject_eoc_tag() {
        let input = [0x00u8, 0x00];
        let mut r = DerReader::new(&input).unwrap();
        let err = r.read_tlv().unwrap_err();
        assert_eq!(err, DER(DerError::InvalidTag));
    }

    //
    // NULL
    //

    #[test]
    fn null_roundtrip() {
        let mut w = DerWriter::new();
        w.write_null().unwrap();
        let enc = w.finish();
        assert_eq!(enc, &[0x05, 0x00]);

        let mut r = DerReader::new(&enc).unwrap();
        r.read_null().unwrap();
        r.expect_empty().unwrap();
    }

    #[test]
    fn reject_null_with_content() {
        // NULL이 0 이외의 길이를 가지면 거부
        let input = [0x05u8, 0x01, 0x00];
        let mut r = DerReader::new(&input).unwrap();
        let err = r.read_null().unwrap_err();
        assert_eq!(err, DER(DerError::InvalidLength));
    }

    //
    // BOOLEAN
    //

    #[test]
    fn boolean_roundtrip() {
        for &val in &[true, false] {
            let mut w = DerWriter::new();
            w.write_boolean(val).unwrap();
            let enc = w.finish();
            let mut r = DerReader::new(&enc).unwrap();
            assert_eq!(r.read_boolean().unwrap(), val);
        }
    }

    #[test]
    fn reject_ber_boolean() {
        // BER true는 0x01이지만 DER에서는 0xFF만 허용
        let input = [0x01u8, 0x01, 0x01];
        let mut r = DerReader::new(&input).unwrap();
        let err = r.read_boolean().unwrap_err();
        assert_eq!(err, DER(DerError::InvalidBooleanEncoding));
    }

    //
    // INTEGER
    //

    #[test]
    fn integer_zero_roundtrip() {
        let mut w = DerWriter::new();
        w.write_integer_unsigned(&[]).unwrap();
        let enc = w.finish();
        // INTEGER 0 = 02 01 00
        assert_eq!(enc, &[0x02, 0x01, 0x00]);

        let mut r = DerReader::new(&enc).unwrap();
        let bytes = r.read_integer_bytes().unwrap();
        assert_eq!(bytes, &[0x00]);
    }

    #[test]
    fn integer_positive_with_high_bit() {
        // 값 0x80 → 부호 바이트 필요: 02 02 00 80
        let mut w = DerWriter::new();
        w.write_integer_unsigned(&[0x80]).unwrap();
        let enc = w.finish();
        assert_eq!(enc, &[0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn integer_strips_leading_zeros() {
        // [0x00, 0x00, 0x01] → 값 1 → 02 01 01
        let mut w = DerWriter::new();
        w.write_integer_unsigned(&[0x00, 0x00, 0x01]).unwrap();
        let enc = w.finish();
        assert_eq!(enc, &[0x02, 0x01, 0x01]);
    }

    #[test]
    fn reject_non_minimal_integer() {
        // 02 03 00 00 01 → 선행 0x00 뒤의 바이트 MSB = 0 → 비최소
        let input = [0x02u8, 0x03, 0x00, 0x00, 0x01];
        let mut r = DerReader::new(&input).unwrap();
        let err = r.read_integer_bytes().unwrap_err();
        assert_eq!(err, DER(DerError::NonMinimalInteger));
    }

    #[test]
    fn reject_non_minimal_integer_neg() {
        // 02 03 FF FF 80 → 선행 0xFF 뒤의 바이트 MSB = 1 → 비최소
        let input = [0x02u8, 0x03, 0xFF, 0xFF, 0x80];
        let mut r = DerReader::new(&input).unwrap();
        let err = r.read_integer_bytes().unwrap_err();
        assert_eq!(err, DER(DerError::NonMinimalInteger));
    }

    //
    // OCTET STRING
    //

    #[test]
    fn octet_string_roundtrip() {
        let data = b"hello DER";
        let mut w = DerWriter::new();
        w.write_octet_string(data).unwrap();
        let enc = w.finish();

        let mut r = DerReader::new(&enc).unwrap();
        assert_eq!(r.read_octet_string().unwrap(), data);
        r.expect_empty().unwrap();
    }

    //
    // BIT STRING
    //

    #[test]
    fn bit_string_roundtrip() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut w = DerWriter::new();
        w.write_bit_string(&data, 0).unwrap();
        let enc = w.finish();

        let mut r = DerReader::new(&enc).unwrap();
        let (decoded, unused) = r.read_bit_string().unwrap();
        assert_eq!(decoded, &data);
        assert_eq!(unused, 0);
    }

    #[test]
    fn reject_bit_string_invalid_unused_bits() {
        // unused_bits = 8 → 범위 초과
        let input = [0x03u8, 0x02, 0x08, 0x00];
        let mut r = DerReader::new(&input).unwrap();
        let err = r.read_bit_string().unwrap_err();
        assert_eq!(err, DER(DerError::InvalidBitString));
    }

    // OID

    // ML-DSA-44: 2.16.840.1.101.3.4.3.17 (18: 65)
    // ML-DSA-87: .....................19
    // 수동 인코딩 (44) >>>
    //   first_sub = 40*2+16 = 96 = 0x60 → [0x60]
    //   840 = 6*128+72 → [0x86, 0x48]
    //   1   → [0x01]
    //   101 → [0x65]
    //   3   → [0x03]
    //   4   → [0x04]
    //   3   → [0x03]
    //   17  → [0x11]
    // 값 바이트: 60 86 48 01 65 03 04 03 11 (9 bytes)
    // TLV: 06 09 60 86 48 01 65 03 04 03 11
    const MLDSA44_DER: [u8; 11] = [
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
        0x11,
        // 바이트 맞는데?바이트 맞는데?바이트 맞는데?바이트 맞는데?바이트 맞는데?바이트 맞는데?바이트 맞는데?
        //바이트 맞는데?바이트 맞는데?바이트 맞는데?바이트 맞는데?바이트 맞는데?바이트 맞는데?바이트 맞는데?
    ];

    #[test]
    fn oid_decode_mldsa44() {
        let expected = Oid::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 3, 17]).unwrap();
        let mut r = DerReader::new(&MLDSA44_DER).unwrap();
        let oid = r.read_oid().unwrap();
        assert!(oid.ct_eq(&expected));
    }

    #[test]
    fn oid_encode_mldsa44() {
        let oid = Oid::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 3, 17]).unwrap();
        let mut w = DerWriter::new();
        w.write_oid(&oid).unwrap();
        assert_eq!(w.finish().as_slice(), &MLDSA44_DER);
    }

    #[test]
    fn oid_ct_eq_distinguishes_different_oids() {
        let a = Oid::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 3, 17]).unwrap();
        let b = Oid::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 3, 18]).unwrap(); // 65
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn oid_reject_invalid_first_arc() {
        let err = Oid::from_arcs(&[3, 0]).unwrap_err();
        assert_eq!(err, ASN1(ASN1Error::InvalidOid));
    }

    #[test]
    fn oid_reject_second_arc_out_of_range() {
        // 첫 아크 0이면 두 번째는 0–39
        let err = Oid::from_arcs(&[0, 40]).unwrap_err();
        assert_eq!(err, ASN1(ASN1Error::InvalidOid));
    }

    #[test]
    fn oid_roundtrip_rsaencryption() {
        // rsaEncryption: 1.2.840.113549.1.1.1
        let oid = Oid::from_arcs(&[1, 2, 840, 113549, 1, 1, 1]).unwrap();
        let mut w = DerWriter::new();
        w.write_oid(&oid).unwrap();
        let enc = w.finish();

        let mut r = DerReader::new(&enc).unwrap();
        let decoded = r.read_oid().unwrap();
        assert!(decoded.ct_eq(&oid));
    }

    //
    // SEQUENCE
    //

    #[test]
    fn sequence_roundtrip() {
        let oid = Oid::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 3, 17]).unwrap();
        let data = b"test payload";

        let mut inner = DerWriter::new();
        inner.write_oid(&oid).unwrap();
        inner.write_octet_string(data).unwrap();

        let mut outer = DerWriter::new();
        outer.write_sequence(&inner.finish()).unwrap();
        let enc = outer.finish();

        let mut depth = MAX_DEPTH;
        let mut r = DerReader::new(&enc).unwrap();
        let mut seq = r.read_sequence(&mut depth).unwrap();
        let decoded_oid = seq.read_oid().unwrap();
        let decoded_data = seq.read_octet_string().unwrap();
        seq.expect_empty().unwrap();
        r.expect_empty().unwrap();

        assert!(decoded_oid.ct_eq(&oid));
        assert_eq!(decoded_data, data);
    }

    #[test]
    fn nested_sequence_depth_tracking() {
        // SEQUENCE { SEQUENCE { NULL } } — 깊이 2 소비
        let mut level2 = DerWriter::new();
        level2.write_null().unwrap();

        let mut level1 = DerWriter::new();
        level1.write_sequence(&level2.finish()).unwrap();

        let mut outer = DerWriter::new();
        outer.write_sequence(&level1.finish()).unwrap();
        let enc = outer.finish();

        let mut depth = MAX_DEPTH;
        let mut r = DerReader::new(&enc).unwrap();
        let mut s1 = r.read_sequence(&mut depth).unwrap();
        assert_eq!(depth, MAX_DEPTH - 1);
        let mut s2 = s1.read_sequence(&mut depth).unwrap();
        assert_eq!(depth, MAX_DEPTH - 2);
        s2.read_null().unwrap();
        s2.expect_empty().unwrap();
        s1.expect_empty().unwrap();
        r.expect_empty().unwrap();
    }

    #[test]
    fn reject_excessive_depth() {
        // 최대 깊이 초과 시도
        let mut inner = DerWriter::new();
        inner.write_null().unwrap();
        let mut outer = DerWriter::new();
        outer.write_sequence(&inner.finish()).unwrap();
        let enc = outer.finish();

        // depth = 0으로 강제 설정
        let mut depth = 0u8;
        let mut r = DerReader::new(&enc).unwrap();
        let err = r.read_sequence(&mut depth).unwrap_err();
        assert_eq!(err, DER(DerError::MaxDepthExceeded));
    }

    //
    // 버퍼 오버리드 방어
    //

    #[test]
    fn reject_truncated_tlv() {
        // 길이 16이라고 주장하지만 실제 데이터 1바이트만 있음
        let input = [0x04u8, 0x10, 0xAA];
        let mut r = DerReader::new(&input).unwrap();
        let err = r.read_octet_string().unwrap_err();
        assert_eq!(err, DER(DerError::UnexpectedEof));
    }

    #[test]
    fn reject_truncated_length() {
        // 장형식 길이를 주장하지만 길이 바이트가 없음 (0x81 후 EOF)
        let input = [0x04u8, 0x81];
        let mut r = DerReader::new(&input).unwrap();
        let err = r.read_octet_string().unwrap_err();
        assert_eq!(err, DER(DerError::UnexpectedEof));
    }

    #[test]
    fn reject_trailing_data() {
        let mut w = DerWriter::new();
        w.write_null().unwrap();
        let mut enc = w.finish();
        enc.push(0x00); // 잔여 바이트 추가

        let mut r = DerReader::new(&enc).unwrap();
        r.read_null().unwrap();
        let err = r.expect_empty().unwrap_err();
        assert_eq!(err, DER(DerError::TrailingData));
    }

    //
    // EXPLICIT / IMPLICIT 컨텍스트 태그
    //

    #[test]
    fn explicit_tag_roundtrip() {
        let data = b"wrapped";
        let mut inner = DerWriter::new();
        inner.write_octet_string(data).unwrap();

        let mut w = DerWriter::new();
        w.write_explicit_tag(0, &inner.finish()).unwrap();
        let enc = w.finish();

        let mut depth = MAX_DEPTH;
        let mut r = DerReader::new(&enc).unwrap();
        let mut tagged = r.read_explicit_tag(0, &mut depth).unwrap();
        assert_eq!(tagged.read_octet_string().unwrap(), data);
        tagged.expect_empty().unwrap();
        r.expect_empty().unwrap();
    }

    #[test]
    fn implicit_tag_roundtrip() {
        let data = b"implicit";
        let mut w = DerWriter::new();
        w.write_implicit_tag(1, data).unwrap();
        let enc = w.finish();

        let mut r = DerReader::new(&enc).unwrap();
        let value = r.read_implicit_value(1).unwrap();
        assert_eq!(value, data);
        r.expect_empty().unwrap();
    }

    //
    // SecureBuffer
    //

    #[test]
    fn integer_secure_roundtrip() {
        let key_bytes = [0x01u8, 0x23, 0x45, 0x67];
        let mut w = DerWriter::new();
        w.write_integer_unsigned(&key_bytes).unwrap();
        let enc = w.finish();

        let mut r = DerReader::new(&enc).unwrap();
        let secure = r.read_integer_secure().unwrap();
        assert_eq!(secure.as_slice(), &key_bytes);
    }
}
