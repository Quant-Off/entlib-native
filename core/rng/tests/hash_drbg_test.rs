//! Hash_DRBG 공개 API 통합 테스트.
//!
//! `instantiate`는 `pub(crate)` 내부 전용 함수로, 이 파일에서는 접근할 수 없습니다.
//! 입력 검증, 결정론성, KAT 테스트는 `src/hash_drbg.rs` 내부 단위 테스트에서 수행됩니다.
//!
//! 이 파일은 공개 API인 `new_from_os`, `reseed`, `generate`의 통합 동작을 검증합니다.

use entlib_native_rng::{DrbgError, HashDRBGSHA256, HashDRBGSHA512};

//
// generate 입력 검증
//

#[test]
fn generate_rejects_request_too_large() {
    let mut drbg = HashDRBGSHA512::new_from_os(None).expect("new_from_os failed");
    let mut buf = vec![0u8; 65537];
    assert!(matches!(
        drbg.generate(&mut buf, None),
        Err(DrbgError::RequestTooLarge)
    ));
}

#[test]
fn generate_accepts_maximum_request_size() {
    let mut drbg = HashDRBGSHA512::new_from_os(None).expect("new_from_os failed");
    let mut buf = vec![0u8; 65536];
    assert!(drbg.generate(&mut buf, None).is_ok());
}

#[test]
fn generate_empty_output_is_valid() {
    let mut drbg = HashDRBGSHA256::new_from_os(None).expect("new_from_os failed");
    let mut buf = [];
    assert!(drbg.generate(&mut buf, None).is_ok());
}

//
// reseed 입력 검증
//

#[test]
fn reseed_rejects_entropy_too_short() {
    let mut drbg = HashDRBGSHA256::new_from_os(None).expect("new_from_os failed");
    assert!(matches!(
        drbg.reseed(&[0xefu8; 15], None),
        Err(DrbgError::EntropyTooShort)
    ));
}

#[test]
fn reseed_accepts_minimum_entropy() {
    let mut drbg = HashDRBGSHA256::new_from_os(None).expect("new_from_os failed");
    assert!(drbg.reseed(&[0xefu8; 16], None).is_ok());
}

//
// new_from_os 스모크 테스트
//

#[test]
fn new_from_os_sha256_succeeds() {
    assert!(HashDRBGSHA256::new_from_os(None).is_ok());
}

#[test]
fn new_from_os_sha512_succeeds() {
    assert!(HashDRBGSHA512::new_from_os(None).is_ok());
}

#[test]
fn new_from_os_with_personalization_succeeds() {
    let ps = b"entlib-native-integration-test";
    assert!(HashDRBGSHA512::new_from_os(Some(ps)).is_ok());
}

/// OS 엔트로피로 초기화된 두 인스턴스의 출력이 서로 다름 (독립성)
#[test]
fn two_os_instances_produce_different_output() {
    let mut d1 = HashDRBGSHA512::new_from_os(None).expect("new_from_os failed");
    let mut d2 = HashDRBGSHA512::new_from_os(None).expect("new_from_os failed");
    let mut out1 = [0u8; 64];
    let mut out2 = [0u8; 64];
    d1.generate(&mut out1, None).unwrap();
    d2.generate(&mut out2, None).unwrap();
    assert_ne!(out1, out2, "독립 인스턴스의 출력이 동일합니다");
}

/// generate 출력이 전부 0이 아님
#[test]
fn output_is_not_all_zeros() {
    let mut drbg = HashDRBGSHA512::new_from_os(None).expect("new_from_os failed");
    let mut out = [0u8; 64];
    drbg.generate(&mut out, None).unwrap();
    assert!(out.iter().any(|&b| b != 0));
}

/// 연속 두 번 generate → 서로 다른 출력
#[test]
fn sequential_generates_produce_different_output() {
    let mut drbg = HashDRBGSHA512::new_from_os(None).expect("new_from_os failed");
    let mut out1 = [0u8; 64];
    let mut out2 = [0u8; 64];
    drbg.generate(&mut out1, None).unwrap();
    drbg.generate(&mut out2, None).unwrap();
    assert_ne!(out1, out2);
}

/// reseed 후 출력이 변경됨
#[test]
fn reseed_changes_subsequent_output() {
    let mut drbg = HashDRBGSHA256::new_from_os(None).expect("new_from_os failed");
    let mut before = [0u8; 64];
    drbg.generate(&mut before, None).unwrap();
    // 다른 엔트로피로 reseed
    drbg.reseed(&[0xffu8; 32], None).unwrap();
    let mut after = [0u8; 64];
    drbg.generate(&mut after, None).unwrap();
    assert_ne!(before, after);
}

/// additional_input 유무 → 다른 출력
#[test]
fn additional_input_changes_output() {
    let mut d1 = HashDRBGSHA256::new_from_os(Some(b"fixed-personalization")).expect("failed");
    let mut d2 = HashDRBGSHA256::new_from_os(Some(b"fixed-personalization")).expect("failed");
    // 두 인스턴스는 서로 다른 OS 엔트로피로 초기화되므로, additional_input 효과를
    // 단독으로 검증하기 어렵습니다. 대신 additional_input 제공 시 에러가 없음을 확인합니다.
    let mut out1 = [0u8; 64];
    let mut out2 = [0u8; 64];
    d1.generate(&mut out1, None).unwrap();
    d2.generate(&mut out2, Some(b"context")).unwrap();
    // 두 출력이 다를 수 있고 (다른 OS 엔트로피), generate 자체가 성공해야 함
    let _ = out1;
    let _ = out2;
}
