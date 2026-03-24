use entlib_native_blake::{BLAKE3_OUT_LEN, Blake3};

//
// BLAKE3 공식 테스트 벡터 (https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json)
// 입력: 0x00, 0x01, ..., 0xFA (연속 바이트)
//

fn make_input(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

// 공식 벡터: 입력 0바이트
#[test]
fn blake3_empty() {
    let h = Blake3::new();
    let d = h.finalize().unwrap();
    let expected = [
        0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9,
        0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f,
        0x32, 0x62,
    ];
    assert_eq!(d.as_slice(), &expected);
}

// 공식 벡터: 입력 1바이트 (0x00)
#[test]
fn blake3_one_byte() {
    let mut h = Blake3::new();
    h.update(&[0x00]);
    let d = h.finalize().unwrap();
    let expected = [
        0x2d, 0x3a, 0xde, 0xdf, 0xf1, 0x1b, 0x61, 0xf1, 0x4c, 0x88, 0x6e, 0x35, 0xaf, 0xa0, 0x36,
        0x73, 0x6d, 0xcd, 0x87, 0xa7, 0x4d, 0x27, 0xb5, 0xc1, 0x51, 0x02, 0x25, 0xd0, 0xf5, 0x92,
        0xe2, 0x13,
    ];
    assert_eq!(d.as_slice(), &expected);
}

// 공식 벡터: 입력 1023바이트 (단일 청크 경계 직전)
#[test]
fn blake3_1023_bytes() {
    let input = make_input(1023);
    let mut h = Blake3::new();
    h.update(&input);
    let d = h.finalize().unwrap();
    let expected = [
        0x10, 0x10, 0x89, 0x70, 0xee, 0xda, 0x3e, 0xb9, 0x32, 0xba, 0xac, 0x14, 0x28, 0xc7, 0xa2,
        0x16, 0x3b, 0x0e, 0x92, 0x4c, 0x9a, 0x9e, 0x25, 0xb3, 0x5b, 0xba, 0x72, 0xb2, 0x8f, 0x70,
        0xbd, 0x11,
    ];
    assert_eq!(d.as_slice(), &expected);
}

// 공식 벡터: 입력 1024바이트 (정확히 1청크)
#[test]
fn blake3_1024_bytes() {
    let input = make_input(1024);
    let mut h = Blake3::new();
    h.update(&input);
    let d = h.finalize().unwrap();
    let expected = [
        0x42, 0x21, 0x47, 0x39, 0xf0, 0x95, 0xa4, 0x06, 0xf3, 0xfc, 0x83, 0xde, 0xb8, 0x89, 0x74,
        0x4a, 0xc0, 0x0d, 0xf8, 0x31, 0xc1, 0x0d, 0xaa, 0x55, 0x18, 0x9b, 0x5d, 0x12, 0x1c, 0x85,
        0x5a, 0xf7,
    ];
    assert_eq!(d.as_slice(), &expected);
}

// 공식 벡터: 입력 1025바이트 (청크 경계 직후, 트리 시작)
#[test]
fn blake3_1025_bytes() {
    let input = make_input(1025);
    let mut h = Blake3::new();
    h.update(&input);
    let d = h.finalize().unwrap();
    let expected = [
        0xd0, 0x02, 0x78, 0xae, 0x47, 0xeb, 0x27, 0xb3, 0x4f, 0xae, 0xcf, 0x67, 0xb4, 0xfe, 0x26,
        0x3f, 0x82, 0xd5, 0x41, 0x29, 0x16, 0xc1, 0xff, 0xd9, 0x7c, 0x8c, 0xb7, 0xfb, 0x81, 0x4b,
        0x84, 0x44,
    ];
    assert_eq!(d.as_slice(), &expected);
}

// 공식 벡터: 입력 2048바이트 (정확히 2청크)
#[test]
fn blake3_2048_bytes() {
    let input = make_input(2048);
    let mut h = Blake3::new();
    h.update(&input);
    let d = h.finalize().unwrap();
    let expected = [
        0xe7, 0x76, 0xb6, 0x02, 0x8c, 0x7c, 0xd2, 0x2a, 0x4d, 0x0b, 0xa1, 0x82, 0xa8, 0xbf, 0x62,
        0x20, 0x5d, 0x2e, 0xf5, 0x76, 0x46, 0x7e, 0x83, 0x8e, 0xd6, 0xf2, 0x52, 0x9b, 0x85, 0xfb,
        0xa2, 0x4a,
    ];
    assert_eq!(d.as_slice(), &expected);
}

// 결정론성: 동일 입력은 동일 출력
#[test]
fn blake3_deterministic() {
    let input = make_input(500);
    let mut h1 = Blake3::new();
    h1.update(&input);
    let d1 = h1.finalize().unwrap();

    let mut h2 = Blake3::new();
    h2.update(&input);
    let d2 = h2.finalize().unwrap();

    assert_eq!(d1.as_slice(), d2.as_slice());
}

// 스트리밍 업데이트: 분할 공급과 일괄 공급 결과 일치
#[test]
fn blake3_streaming_matches_single() {
    let input = make_input(3000);

    let mut h1 = Blake3::new();
    h1.update(&input);
    let d1 = h1.finalize().unwrap();

    let mut h2 = Blake3::new();
    h2.update(&input[..1000]);
    h2.update(&input[1000..2000]);
    h2.update(&input[2000..]);
    let d2 = h2.finalize().unwrap();

    assert_eq!(d1.as_slice(), d2.as_slice());
}

// 입력이 다르면 출력이 달라야 함
#[test]
fn blake3_different_inputs() {
    let mut h1 = Blake3::new();
    h1.update(b"input one");
    let d1 = h1.finalize().unwrap();

    let mut h2 = Blake3::new();
    h2.update(b"input two");
    let d2 = h2.finalize().unwrap();

    assert_ne!(d1.as_slice(), d2.as_slice());
}

// 출력 길이
#[test]
fn blake3_output_length() {
    let h = Blake3::new();
    let d = h.finalize().unwrap();
    assert_eq!(d.as_slice().len(), BLAKE3_OUT_LEN);
    assert_eq!(BLAKE3_OUT_LEN, 32);
}

// XOF: 임의 길이 출력
#[test]
fn blake3_xof_lengths() {
    for len in [1usize, 32, 64, 128, 256, 1000] {
        let mut h = Blake3::new();
        h.update(b"xof test");
        let d = h.finalize_xof(len).unwrap();
        assert_eq!(d.as_slice().len(), len);
    }
}

// XOF: 출력 앞 32바이트는 finalize()와 일치해야 함
#[test]
fn blake3_xof_prefix_matches_finalize() {
    let input = make_input(512);

    let mut h1 = Blake3::new();
    h1.update(&input);
    let d32 = h1.finalize().unwrap();

    let mut h2 = Blake3::new();
    h2.update(&input);
    let d64 = h2.finalize_xof(64).unwrap();

    assert_eq!(d32.as_slice(), &d64.as_slice()[..32]);
}

// 키드 모드: 결정론성
#[test]
fn blake3_keyed_deterministic() {
    let key = [0x42u8; 32];
    let mut h1 = Blake3::new_keyed(&key);
    h1.update(b"message");
    let d1 = h1.finalize().unwrap();

    let mut h2 = Blake3::new_keyed(&key);
    h2.update(b"message");
    let d2 = h2.finalize().unwrap();

    assert_eq!(d1.as_slice(), d2.as_slice());
}

// 키드 모드와 일반 모드의 출력이 달라야 함
#[test]
fn blake3_keyed_differs_from_unkeyed() {
    let key = [0x01u8; 32];

    let mut h1 = Blake3::new();
    h1.update(b"message");
    let d1 = h1.finalize().unwrap();

    let mut h2 = Blake3::new_keyed(&key);
    h2.update(b"message");
    let d2 = h2.finalize().unwrap();

    assert_ne!(d1.as_slice(), d2.as_slice());
}

// 키가 다르면 출력이 달라야 함
#[test]
fn blake3_different_keys() {
    let key1 = [0x01u8; 32];
    let key2 = [0x02u8; 32];

    let mut h1 = Blake3::new_keyed(&key1);
    h1.update(b"message");
    let d1 = h1.finalize().unwrap();

    let mut h2 = Blake3::new_keyed(&key2);
    h2.update(b"message");
    let d2 = h2.finalize().unwrap();

    assert_ne!(d1.as_slice(), d2.as_slice());
}
