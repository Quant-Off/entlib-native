use entlib_native_hmac::{HMACSHA256, HMACSHA512, HmacError, MacResult};

//
// 헬퍼
//

fn hmac256(key: &[u8], chunks: &[&[u8]]) -> [u8; 32] {
    let mut h = HMACSHA256::new(key).expect("HMACSHA256 초기화 실패");
    for c in chunks {
        h.update(c);
    }
    h.finalize().expect("HMACSHA256 finalize 실패").0
}

fn hmac512(key: &[u8], chunks: &[&[u8]]) -> [u8; 64] {
    let mut h = HMACSHA512::new(key).expect("HMACSHA512 초기화 실패");
    for c in chunks {
        h.update(c);
    }
    h.finalize().expect("HMACSHA512 finalize 실패").0
}

//
// RFC 4231 HMAC-SHA-256
//

/// TC1 — Key: 0x0b×20 / Data: "Hi There"
#[test]
fn sha256_tc1() {
    assert_eq!(
        hmac256(&[0x0bu8; 20], &[b"Hi There"]),
        [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ]
    );
}

/// TC3 — Key: 0xaa×20 / Data: 0xdd×50
#[test]
fn sha256_tc3() {
    assert_eq!(
        hmac256(&[0xaau8; 20], &[&[0xddu8; 50]]),
        [
            0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91,
            0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14,
            0xce, 0xd5, 0x65, 0xfe,
        ]
    );
}

/// TC4 — Key: 0x01..0x19 (25 bytes) / Data: 0xcd×50
#[test]
fn sha256_tc4() {
    let key: [u8; 25] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    ];
    assert_eq!(
        hmac256(&key, &[&[0xcdu8; 50]]),
        [
            0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2,
            0x08, 0x3a, 0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07, 0x7a, 0x2e, 0x3f, 0xf4,
            0x67, 0x29, 0x66, 0x5b,
        ]
    );
}

/// TC6 — Key: 0xaa×131 (블록 초과) / 키를 SHA-256으로 해싱 후 사용
#[test]
fn sha256_tc6_key_longer_than_block() {
    assert_eq!(
        hmac256(
            &[0xaau8; 131],
            &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
        ),
        [
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
            0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
            0x0e, 0xe3, 0x7f, 0x54,
        ]
    );
}

/// TC7 — Key: 0xaa×131 / 데이터도 블록 초과
#[test]
fn sha256_tc7_key_and_data_longer_than_block() {
    let data = b"This is a test using a larger than block-size key and a larger \
                 than block-size data. The key needs to be hashed before being \
                 used by the HMAC algorithm.";
    assert_eq!(
        hmac256(&[0xaau8; 131], &[data]),
        [
            0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb, 0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0,
            0xe9, 0x44, 0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93, 0x8a, 0x7f, 0x51, 0x53,
            0x5c, 0x3a, 0x35, 0xe2,
        ]
    );
}

//
// RFC 4231 HMAC-SHA-512
//

/// TC1 — Key: 0x0b×20 / Data: "Hi There"
#[test]
fn sha512_tc1() {
    assert_eq!(
        hmac512(&[0x0bu8; 20], &[b"Hi There"]),
        [
            0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d,
            0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05,
            0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b,
            0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70,
            0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54,
        ]
    );
}

/// TC3 — Key: 0xaa×20 / Data: 0xdd×50
#[test]
fn sha512_tc3() {
    assert_eq!(
        hmac512(&[0xaau8; 20], &[&[0xddu8; 50]]),
        [
            0xfa, 0x73, 0xb0, 0x08, 0x9d, 0x56, 0xa2, 0x84, 0xef, 0xb0, 0xf0, 0x75, 0x6c, 0x89,
            0x0b, 0xe9, 0xb1, 0xb5, 0xdb, 0xdd, 0x8e, 0xe8, 0x1a, 0x36, 0x55, 0xf8, 0x3e, 0x33,
            0xb2, 0x27, 0x9d, 0x39, 0xbf, 0x3e, 0x84, 0x82, 0x79, 0xa7, 0x22, 0xc8, 0x06, 0xb4,
            0x85, 0xa4, 0x7e, 0x67, 0xc8, 0x07, 0xb9, 0x46, 0xa3, 0x37, 0xbe, 0xe8, 0x94, 0x26,
            0x74, 0x27, 0x88, 0x59, 0xe1, 0x32, 0x92, 0xfb,
        ]
    );
}

/// TC4 — Key: 0x01..0x19 (25 bytes) / Data: 0xcd×50
#[test]
fn sha512_tc4() {
    let key: [u8; 25] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    ];
    assert_eq!(
        hmac512(&key, &[&[0xcdu8; 50]]),
        [
            0xb0, 0xba, 0x46, 0x56, 0x37, 0x45, 0x8c, 0x69, 0x90, 0xe5, 0xa8, 0xc5, 0xf6, 0x1d,
            0x4a, 0xf7, 0xe5, 0x76, 0xd9, 0x7f, 0xf9, 0x4b, 0x87, 0x2d, 0xe7, 0x6f, 0x80, 0x50,
            0x36, 0x1e, 0xe3, 0xdb, 0xa9, 0x1c, 0xa5, 0xc1, 0x1a, 0xa2, 0x5e, 0xb4, 0xd6, 0x79,
            0x27, 0x5c, 0xc5, 0x78, 0x80, 0x63, 0xa5, 0xf1, 0x97, 0x41, 0x12, 0x0c, 0x4f, 0x2d,
            0xe2, 0xad, 0xeb, 0xeb, 0x10, 0xa2, 0x98, 0xdd,
        ]
    );
}

/// TC6 — Key: 0xaa×131 (블록 128B 초과) / 키를 SHA-512로 해싱 후 사용
#[test]
fn sha512_tc6_key_longer_than_block() {
    assert_eq!(
        hmac512(
            &[0xaau8; 131],
            &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
        ),
        [
            0x80, 0xb2, 0x42, 0x63, 0xc7, 0xc1, 0xa3, 0xeb, 0xb7, 0x14, 0x93, 0xc1, 0xdd, 0x7b,
            0xe8, 0xb4, 0x9b, 0x46, 0xd1, 0xf4, 0x1b, 0x4a, 0xee, 0xc1, 0x12, 0x1b, 0x01, 0x37,
            0x83, 0xf8, 0xf3, 0x52, 0x6b, 0x56, 0xd0, 0x37, 0xe0, 0x5f, 0x25, 0x98, 0xbd, 0x0f,
            0xd2, 0x21, 0x5d, 0x6a, 0x1e, 0x52, 0x95, 0xe6, 0x4f, 0x73, 0xf6, 0x3f, 0x0a, 0xec,
            0x8b, 0x91, 0x5a, 0x98, 0x5d, 0x78, 0x65, 0x98,
        ]
    );
}

/// TC7 — Key: 0xaa×131 / 데이터도 블록 초과
#[test]
fn sha512_tc7_key_and_data_longer_than_block() {
    let data = b"This is a test using a larger than block-size key and a larger \
                 than block-size data. The key needs to be hashed before being \
                 used by the HMAC algorithm.";
    assert_eq!(
        hmac512(&[0xaau8; 131], &[data]),
        [
            0xe3, 0x7b, 0x6a, 0x77, 0x5d, 0xc8, 0x7d, 0xba, 0xa4, 0xdf, 0xa9, 0xf9, 0x6e, 0x5e,
            0x3f, 0xfd, 0xde, 0xbd, 0x71, 0xf8, 0x86, 0x72, 0x89, 0x86, 0x5d, 0xf5, 0xa3, 0x2d,
            0x20, 0xcd, 0xc9, 0x44, 0xb6, 0x02, 0x2c, 0xac, 0x3c, 0x49, 0x82, 0xb1, 0x0d, 0x5e,
            0xeb, 0x55, 0xc3, 0xe4, 0xde, 0x15, 0x13, 0x46, 0x76, 0xfb, 0x6d, 0xe0, 0x44, 0x60,
            0x65, 0xc9, 0x74, 0x40, 0xfa, 0x8c, 0x6a, 0x58,
        ]
    );
}

//
// 보안 정책 (NIST SP 800-107r1)
//

/// 112비트(14바이트) 미만 키: 두 알고리즘 모두 반드시 거부
#[test]
fn rejects_weak_key_sha256() {
    match HMACSHA256::new(&[0x42u8; 13]) {
        Err(HmacError::WeakKeyLength) => {}
        _ => panic!("HMACSHA256: 취약 키가 수락됨"),
    }
}

#[test]
fn rejects_weak_key_sha512() {
    match HMACSHA512::new(&[0x42u8; 13]) {
        Err(HmacError::WeakKeyLength) => {}
        _ => panic!("HMACSHA512: 취약 키가 수락됨"),
    }
}

/// 빈 키: 두 알고리즘 모두 거부
#[test]
fn rejects_empty_key_sha256() {
    assert!(matches!(
        HMACSHA256::new(&[]),
        Err(HmacError::WeakKeyLength)
    ));
}

#[test]
fn rejects_empty_key_sha512() {
    assert!(matches!(
        HMACSHA512::new(&[]),
        Err(HmacError::WeakKeyLength)
    ));
}

/// 경계값 — 정확히 14바이트(112비트): 두 알고리즘 모두 수락
#[test]
fn accepts_minimum_key_sha256() {
    assert!(HMACSHA256::new(&[0xabu8; 14]).is_ok());
}

#[test]
fn accepts_minimum_key_sha512() {
    assert!(HMACSHA512::new(&[0xabu8; 14]).is_ok());
}

//
// 스트리밍 무결성
//

/// 분할 update는 단일 update와 동일한 MAC을 생성해야 함 (SHA-256)
#[test]
fn sha256_streaming_matches_single() {
    let key = [0x0bu8; 20];
    let single = hmac256(&key, &[b"Hi There"]);
    let chunked = hmac256(&key, &[b"Hi", b" ", b"There"]);
    assert_eq!(single, chunked);
}

/// 분할 update는 단일 update와 동일한 MAC을 생성해야 함 (SHA-512)
#[test]
fn sha512_streaming_matches_single() {
    let key = [0x0bu8; 20];
    let single = hmac512(&key, &[b"Hi There"]);
    let chunked = hmac512(&key, &[b"Hi", b" ", b"There"]);
    assert_eq!(single, chunked);
}

/// SHA-256 블록 경계(64B) 전후 분할도 동일
#[test]
fn sha256_streaming_across_block_boundary() {
    let key = [0x0bu8; 20];
    let data = [0x61u8; 200];
    let base = hmac256(&key, &[&data]);
    for split in [63, 64, 65, 128] {
        assert_eq!(
            base,
            hmac256(&key, &[&data[..split], &data[split..]]),
            "SHA-256: {split}/{} 분할 불일치",
            200 - split
        );
    }
}

/// SHA-512 블록 경계(128B) 전후 분할도 동일
#[test]
fn sha512_streaming_across_block_boundary() {
    let key = [0x0bu8; 20];
    let data = [0x61u8; 400];
    let base = hmac512(&key, &[&data]);
    for split in [127, 128, 129, 256] {
        assert_eq!(
            base,
            hmac512(&key, &[&data[..split], &data[split..]]),
            "SHA-512: {split}/{} 분할 불일치",
            400 - split
        );
    }
}

//
// 상수-시간 비교(MacResult)
//

/// 동일 MAC끼리 CT 비교: true (SHA-256)
#[test]
fn sha256_mac_ct_eq_same() {
    let mac1 = HMACSHA256::new(&[0x0bu8; 20]).unwrap().finalize().unwrap();
    let mac2 = HMACSHA256::new(&[0x0bu8; 20]).unwrap().finalize().unwrap();
    assert!(mac1 == mac2);
}

/// 동일 MAC끼리 CT 비교: true (SHA-512)
#[test]
fn sha512_mac_ct_eq_same() {
    let mac1 = HMACSHA512::new(&[0x0bu8; 20]).unwrap().finalize().unwrap();
    let mac2 = HMACSHA512::new(&[0x0bu8; 20]).unwrap().finalize().unwrap();
    assert!(mac1 == mac2);
}

/// 다른 MAC CT 비교: false (SHA-256)
#[test]
fn sha256_mac_ct_ne_different() {
    let key = [0x0bu8; 20];
    let mut h1 = HMACSHA256::new(&key).unwrap();
    h1.update(b"a");
    let m1 = h1.finalize().unwrap();
    let mut h2 = HMACSHA256::new(&key).unwrap();
    h2.update(b"b");
    let m2 = h2.finalize().unwrap();
    assert!(m1 != m2);
}

/// 다른 MAC CT 비교: false (SHA-512)
#[test]
fn sha512_mac_ct_ne_different() {
    let key = [0x0bu8; 20];
    let mut h1 = HMACSHA512::new(&key).unwrap();
    h1.update(b"a");
    let m1 = h1.finalize().unwrap();
    let mut h2 = HMACSHA512::new(&key).unwrap();
    h2.update(b"b");
    let m2 = h2.finalize().unwrap();
    assert!(m1 != m2);
}

/// 1바이트 비트플립 탐지 (SHA-256)
#[test]
fn sha256_mac_single_bit_flip_detected() {
    let real = HMACSHA256::new(&[0x0bu8; 20]).unwrap().finalize().unwrap();
    let mut tampered = real.0;
    tampered[31] ^= 0x01;
    assert!(MacResult::<32>(real.0) != MacResult::<32>(tampered));
}

/// 1바이트 비트플립 탐지 (SHA-512)
#[test]
fn sha512_mac_single_bit_flip_detected() {
    let real = HMACSHA512::new(&[0x0bu8; 20]).unwrap().finalize().unwrap();
    let mut tampered = real.0;
    tampered[63] ^= 0x01;
    assert!(MacResult::<64>(real.0) != MacResult::<64>(tampered));
}

//
// 결정론적 특성
//

/// 동일 입력 → 동일 MAC (두 알고리즘 모두)
#[test]
fn macs_are_deterministic() {
    let key = [0x5au8; 20];
    let data = b"deterministic test vector";
    assert_eq!(hmac256(&key, &[data]), hmac256(&key, &[data]));
    assert_eq!(hmac512(&key, &[data]), hmac512(&key, &[data]));
}

/// 키가 다르면 다른 MAC (두 알고리즘 모두)
#[test]
fn different_keys_different_macs() {
    let data = b"same data";
    assert_ne!(
        hmac256(&[0x01u8; 20], &[data]),
        hmac256(&[0x02u8; 20], &[data])
    );
    assert_ne!(
        hmac512(&[0x01u8; 20], &[data]),
        hmac512(&[0x02u8; 20], &[data])
    );
}

/// 데이터가 다르면 다른 MAC (두 알고리즘 모두)
#[test]
fn different_data_different_macs() {
    let key = [0x0bu8; 20];
    assert_ne!(hmac256(&key, &[b"msg_a"]), hmac256(&key, &[b"msg_b"]));
    assert_ne!(hmac512(&key, &[b"msg_a"]), hmac512(&key, &[b"msg_b"]));
}
