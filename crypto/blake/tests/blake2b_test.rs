use entlib_native_blake::{Blake2b, blake2b_long};

//
// RFC 7693 Appendix A 테스트 벡터
//

#[test]
fn blake2b_512_empty() {
    let h = Blake2b::new(64);
    let d = h.finalize().unwrap();
    let expected = [
        0x78, 0x6a, 0x02, 0xf7, 0x42, 0x01, 0x59, 0x03,
        0xc6, 0xc6, 0xfd, 0x85, 0x25, 0x52, 0xd2, 0x72,
        0x91, 0x2f, 0x47, 0x40, 0xe1, 0x58, 0x47, 0x61,
        0x8a, 0x86, 0xe2, 0x17, 0xf7, 0x1f, 0x54, 0x19,
        0xd2, 0x5e, 0x10, 0x31, 0xaf, 0xee, 0x58, 0x53,
        0x13, 0x89, 0x64, 0x44, 0x93, 0x4e, 0xb0, 0x4b,
        0x90, 0x3a, 0x68, 0x5b, 0x14, 0x48, 0xb7, 0x55,
        0xd5, 0x6f, 0x70, 0x1a, 0xfe, 0x9b, 0xe2, 0xce,
    ];
    assert_eq!(d.as_slice(), &expected);
}

#[test]
fn blake2b_512_abc() {
    let mut h = Blake2b::new(64);
    h.update(b"abc");
    let d = h.finalize().unwrap();
    let expected = [
        0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d,
        0x6a, 0x27, 0x97, 0xb6, 0x9f, 0x12, 0xf6, 0xe9,
        0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a, 0xc4, 0xb7,
        0x4b, 0x12, 0xbb, 0x6f, 0xdb, 0xff, 0xa2, 0xd1,
        0x7d, 0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d,
        0xc2, 0x52, 0xd5, 0xde, 0x45, 0x33, 0xcc, 0x95,
        0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92, 0x5a,
        0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23,
    ];
    assert_eq!(d.as_slice(), &expected);
}

// BLAKE2b-256("abc") — hash_len=32 파라미터 블록 적용
#[test]
fn blake2b_256_abc() {
    let mut h = Blake2b::new(32);
    h.update(b"abc");
    let d = h.finalize().unwrap();
    let expected = [
        0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72,
        0x31, 0x71, 0xef, 0x3f, 0xee, 0x98, 0x57, 0x9b,
        0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42,
        0x72, 0x62, 0xc8, 0xc0, 0x68, 0xd5, 0x23, 0x19,
    ];
    assert_eq!(d.as_slice(), &expected);
}

// 멀티-청크: 128바이트 경계를 넘는 입력
#[test]
fn blake2b_multi_block() {
    let input = vec![0x61u8; 200]; // 'a' × 200
    let mut h1 = Blake2b::new(32);
    h1.update(&input);
    let d1 = h1.finalize().unwrap();

    // 동일 입력을 청크로 나눠 공급한 결과와 동일해야 함
    let mut h2 = Blake2b::new(32);
    h2.update(&input[..100]);
    h2.update(&input[100..]);
    let d2 = h2.finalize().unwrap();

    assert_eq!(d1.as_slice(), d2.as_slice());
}

// 블록 경계(128바이트)에서의 정확성
#[test]
fn blake2b_exact_block_boundary() {
    let input = vec![0x00u8; 128];
    let mut h = Blake2b::new(32);
    h.update(&input);
    let d = h.finalize().unwrap();
    assert_eq!(d.as_slice().len(), 32);
}

// 키드 모드: 동일 키+입력은 동일 출력
#[test]
fn blake2b_keyed_deterministic() {
    let key = vec![0x42u8; 32];
    let mut h1 = Blake2b::new_keyed(32, &key);
    h1.update(b"message");
    let d1 = h1.finalize().unwrap();

    let mut h2 = Blake2b::new_keyed(32, &key);
    h2.update(b"message");
    let d2 = h2.finalize().unwrap();

    assert_eq!(d1.as_slice(), d2.as_slice());
}

// 키드 모드: 키가 다르면 출력이 달라야 함
#[test]
fn blake2b_keyed_different_keys() {
    let key1 = vec![0x01u8; 32];
    let key2 = vec![0x02u8; 32];

    let mut h1 = Blake2b::new_keyed(32, &key1);
    h1.update(b"message");
    let d1 = h1.finalize().unwrap();

    let mut h2 = Blake2b::new_keyed(32, &key2);
    h2.update(b"message");
    let d2 = h2.finalize().unwrap();

    assert_ne!(d1.as_slice(), d2.as_slice());
}

// 키드 모드와 일반 모드의 출력이 달라야 함
#[test]
fn blake2b_keyed_differs_from_unkeyed() {
    let key = vec![0x01u8; 32];

    let mut h1 = Blake2b::new(32);
    h1.update(b"message");
    let d1 = h1.finalize().unwrap();

    let mut h2 = Blake2b::new_keyed(32, &key);
    h2.update(b"message");
    let d2 = h2.finalize().unwrap();

    assert_ne!(d1.as_slice(), d2.as_slice());
}

// 출력 길이 변경은 출력 값을 변경해야 함
#[test]
fn blake2b_different_hash_lengths() {
    let mut h32 = Blake2b::new(32);
    h32.update(b"test");
    let d32 = h32.finalize().unwrap();

    let mut h64 = Blake2b::new(64);
    h64.update(b"test");
    let d64 = h64.finalize().unwrap();

    assert_ne!(d32.as_slice(), &d64.as_slice()[..32]);
}

// blake2b_long: 출력 길이 검증
#[test]
fn blake2b_long_lengths() {
    for len in [1usize, 32, 64, 65, 128, 256, 1024] {
        let out = blake2b_long(b"input", len).unwrap();
        assert_eq!(out.as_slice().len(), len);
    }
}

// blake2b_long: ≤64 바이트 경로는 단일 Blake2b와 일치해야 함
#[test]
fn blake2b_long_short_matches_direct() {
    let input = b"test input";
    for len in [1usize, 16, 32, 64] {
        let long_out = blake2b_long(input, len).unwrap();

        let len_prefix = (len as u32).to_le_bytes();
        let mut h = Blake2b::new(len);
        h.update(&len_prefix);
        h.update(input);
        let direct = h.finalize().unwrap();

        assert_eq!(long_out.as_slice(), direct.as_slice(), "len={len}");
    }
}

// blake2b_long: 동일 입력·길이는 항상 동일 출력
#[test]
fn blake2b_long_deterministic() {
    let d1 = blake2b_long(b"hello", 80).unwrap();
    let d2 = blake2b_long(b"hello", 80).unwrap();
    assert_eq!(d1.as_slice(), d2.as_slice());
}

// blake2b_long: 입력이 다르면 출력이 달라야 함
#[test]
fn blake2b_long_different_inputs() {
    let d1 = blake2b_long(b"input1", 64).unwrap();
    let d2 = blake2b_long(b"input2", 64).unwrap();
    assert_ne!(d1.as_slice(), d2.as_slice());
}

// blake2b_long: out_len=0 은 오류를 반환해야 함
#[test]
fn blake2b_long_zero_len_rejected() {
    assert!(blake2b_long(b"input", 0).is_err());
}
