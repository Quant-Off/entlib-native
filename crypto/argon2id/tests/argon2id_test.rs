use entlib_native_argon2id::Argon2id;

//
// RFC 9106 Appendix B.4 공식 테스트 벡터
//

#[test]
fn rfc9106_b4_test_vector() {
    let password = [0x01u8; 32];
    let salt    = [0x02u8; 16];
    let secret  = [0x03u8; 8];
    let ad      = [0x04u8; 12];

    let params = Argon2id::new(3, 32, 4, 32).unwrap();
    let tag = params.hash(&password, &salt, &secret, &ad).unwrap();

    let expected = [
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c,
        0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
        0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e,
        0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59,
    ];
    assert_eq!(tag.as_slice(), &expected,
        "RFC 9106 B.4 벡터 불일치\ngot:  {:02x?}\nwant: {:02x?}",
        tag.as_slice(), &expected);
}

//
// 파라미터 유효성 검사
//

#[test]
fn param_time_cost_zero_rejected() {
    assert!(Argon2id::new(0, 64, 1, 32).is_err());
}

#[test]
fn param_memory_too_small_rejected() {
    // memory_cost < 8 * parallelism
    assert!(Argon2id::new(1, 7, 1, 32).is_err());
    assert!(Argon2id::new(1, 31, 4, 32).is_err());
}

#[test]
fn param_parallelism_zero_rejected() {
    assert!(Argon2id::new(1, 64, 0, 32).is_err());
}

#[test]
fn param_tag_length_too_short_rejected() {
    assert!(Argon2id::new(1, 64, 1, 0).is_err());
    assert!(Argon2id::new(1, 64, 1, 3).is_err());
}

#[test]
fn param_minimum_valid_accepted() {
    assert!(Argon2id::new(1, 8, 1, 4).is_ok());
}

//
// 솔트 유효성 검사
//

#[test]
fn salt_too_short_rejected() {
    let params = Argon2id::new(1, 64, 1, 32).unwrap();
    assert!(params.hash(b"password", b"short", &[], &[]).is_err());
    assert!(params.hash(b"password", b"1234567", &[], &[]).is_err()); // 7바이트
}

#[test]
fn salt_minimum_length_accepted() {
    let params = Argon2id::new(1, 64, 1, 32).unwrap();
    assert!(params.hash(b"password", b"12345678", &[], &[]).is_ok()); // 8바이트
}

//
// 출력 길이
//

#[test]
fn tag_length_4() {
    let params = Argon2id::new(1, 64, 1, 4).unwrap();
    let tag = params.hash(b"password", b"somesalt", &[], &[]).unwrap();
    assert_eq!(tag.as_slice().len(), 4);
}

#[test]
fn tag_length_32() {
    let params = Argon2id::new(1, 64, 1, 32).unwrap();
    let tag = params.hash(b"password", b"somesalt", &[], &[]).unwrap();
    assert_eq!(tag.as_slice().len(), 32);
}

#[test]
fn tag_length_64() {
    let params = Argon2id::new(1, 64, 1, 64).unwrap();
    let tag = params.hash(b"password", b"somesalt", &[], &[]).unwrap();
    assert_eq!(tag.as_slice().len(), 64);
}

#[test]
fn tag_length_77() {
    // H' 가변 출력 경로 검증 (64 < τ)
    let params = Argon2id::new(1, 64, 1, 77).unwrap();
    let tag = params.hash(b"password", b"somesalt", &[], &[]).unwrap();
    assert_eq!(tag.as_slice().len(), 77);
}

//
// 결정론성
//

#[test]
fn same_inputs_same_tag() {
    let params = Argon2id::new(1, 64, 1, 32).unwrap();
    let t1 = params.hash(b"password", b"somesalt", &[], &[]).unwrap();
    let t2 = params.hash(b"password", b"somesalt", &[], &[]).unwrap();
    assert_eq!(t1.as_slice(), t2.as_slice());
}

//
// 도메인 분리: 각 입력 필드가 독립적으로 출력에 영향을 주어야 함
//

#[test]
fn different_passwords_give_different_tags() {
    let params = Argon2id::new(1, 64, 1, 32).unwrap();
    let t1 = params.hash(b"password1", b"somesalt", &[], &[]).unwrap();
    let t2 = params.hash(b"password2", b"somesalt", &[], &[]).unwrap();
    assert_ne!(t1.as_slice(), t2.as_slice());
}

#[test]
fn different_salts_give_different_tags() {
    let params = Argon2id::new(1, 64, 1, 32).unwrap();
    let t1 = params.hash(b"password", b"somesalt", &[], &[]).unwrap();
    let t2 = params.hash(b"password", b"otherslt", &[], &[]).unwrap();
    assert_ne!(t1.as_slice(), t2.as_slice());
}

#[test]
fn different_secrets_give_different_tags() {
    let params = Argon2id::new(1, 64, 1, 32).unwrap();
    let t1 = params.hash(b"password", b"somesalt", b"secret1!", &[]).unwrap();
    let t2 = params.hash(b"password", b"somesalt", b"secret2!", &[]).unwrap();
    assert_ne!(t1.as_slice(), t2.as_slice());
}

#[test]
fn different_ad_give_different_tags() {
    let params = Argon2id::new(1, 64, 1, 32).unwrap();
    let t1 = params.hash(b"password", b"somesalt", &[], b"context1").unwrap();
    let t2 = params.hash(b"password", b"somesalt", &[], b"context2").unwrap();
    assert_ne!(t1.as_slice(), t2.as_slice());
}

#[test]
fn empty_secret_and_nonempty_secret_differ() {
    let params = Argon2id::new(1, 64, 1, 32).unwrap();
    let t1 = params.hash(b"password", b"somesalt", &[], &[]).unwrap();
    let t2 = params.hash(b"password", b"somesalt", b"secret!!", &[]).unwrap();
    assert_ne!(t1.as_slice(), t2.as_slice());
}

//
// 파라미터 변경 시 출력이 달라져야 함
//

#[test]
fn different_time_cost_gives_different_tags() {
    let p1 = Argon2id::new(1, 64, 1, 32).unwrap();
    let p2 = Argon2id::new(2, 64, 1, 32).unwrap();
    let t1 = p1.hash(b"password", b"somesalt", &[], &[]).unwrap();
    let t2 = p2.hash(b"password", b"somesalt", &[], &[]).unwrap();
    assert_ne!(t1.as_slice(), t2.as_slice());
}

#[test]
fn different_memory_cost_gives_different_tags() {
    let p1 = Argon2id::new(1, 64,  1, 32).unwrap();
    let p2 = Argon2id::new(1, 128, 1, 32).unwrap();
    let t1 = p1.hash(b"password", b"somesalt", &[], &[]).unwrap();
    let t2 = p2.hash(b"password", b"somesalt", &[], &[]).unwrap();
    assert_ne!(t1.as_slice(), t2.as_slice());
}

#[test]
fn different_parallelism_gives_different_tags() {
    let p1 = Argon2id::new(1, 64, 1, 32).unwrap();
    let p2 = Argon2id::new(1, 64, 2, 32).unwrap();
    let t1 = p1.hash(b"password", b"somesalt", &[], &[]).unwrap();
    let t2 = p2.hash(b"password", b"somesalt", &[], &[]).unwrap();
    assert_ne!(t1.as_slice(), t2.as_slice());
}

//
// 빈 패스워드·솔트 경계
//

#[test]
fn empty_password_accepted() {
    let params = Argon2id::new(1, 64, 1, 32).unwrap();
    let tag = params.hash(b"", b"somesalt", &[], &[]).unwrap();
    assert_eq!(tag.as_slice().len(), 32);
}

#[test]
fn empty_password_differs_from_nonempty() {
    let params = Argon2id::new(1, 64, 1, 32).unwrap();
    let t1 = params.hash(b"",         b"somesalt", &[], &[]).unwrap();
    let t2 = params.hash(b"password", b"somesalt", &[], &[]).unwrap();
    assert_ne!(t1.as_slice(), t2.as_slice());
}

//
// 병렬성 = 1 경계: 단일 레인 경로
//

#[test]
fn parallelism_1_produces_consistent_output() {
    let params = Argon2id::new(2, 64, 1, 32).unwrap();
    let t1 = params.hash(b"pw", b"saltsalt", &[], &[]).unwrap();
    let t2 = params.hash(b"pw", b"saltsalt", &[], &[]).unwrap();
    assert_eq!(t1.as_slice(), t2.as_slice());
}

//
// 멀티-레인 경로
//

#[test]
fn parallelism_4_produces_consistent_output() {
    let params = Argon2id::new(2, 64, 4, 32).unwrap();
    let t1 = params.hash(b"pw", b"saltsalt", &[], &[]).unwrap();
    let t2 = params.hash(b"pw", b"saltsalt", &[], &[]).unwrap();
    assert_eq!(t1.as_slice(), t2.as_slice());
}
