use entlib_native_mldsa::{HashDRBGRng, MLDSA, MLDSAParameter};

fn make_rng() -> HashDRBGRng {
    HashDRBGRng::new_from_os(None).expect("OS 엔트로피 소스 초기화 실패")
}

//
// 키 생성 — 길이 / 파라미터 셋 내장 검증
//

#[test]
fn test_keygen_lengths_44() {
    let param = MLDSAParameter::MLDSA44;
    let (pk, sk) = MLDSA::key_gen(param, &mut make_rng()).expect("key_gen 실패");
    assert_eq!(pk.len(), param.pk_len());
    assert_eq!(sk.len(), param.sk_len());
    assert_eq!(pk.param(), param);
    assert_eq!(sk.param(), param);
}

#[test]
fn test_keygen_lengths_65() {
    let param = MLDSAParameter::MLDSA65;
    let (pk, sk) = MLDSA::key_gen(param, &mut make_rng()).expect("key_gen 실패");
    assert_eq!(pk.len(), param.pk_len());
    assert_eq!(sk.len(), param.sk_len());
}

#[test]
fn test_keygen_lengths_87() {
    let param = MLDSAParameter::MLDSA87;
    let (pk, sk) = MLDSA::key_gen(param, &mut make_rng()).expect("key_gen 실패");
    assert_eq!(pk.len(), param.pk_len());
    assert_eq!(sk.len(), param.sk_len());
}

//
// 서명 + 검증 라운드트립
//

#[test]
fn test_sign_verify_roundtrip_44() {
    let mut rng = make_rng();
    let (pk, sk) = MLDSA::key_gen(MLDSAParameter::MLDSA44, &mut rng).expect("key_gen 실패");

    let sig = MLDSA::sign(&sk, b"Hello, ML-DSA-44!", b"test-context", &mut rng).expect("sign 실패");
    assert_eq!(sig.len(), MLDSAParameter::MLDSA44.sig_len());

    let ok = MLDSA::verify(&pk, b"Hello, ML-DSA-44!", sig.as_slice(), b"test-context")
        .expect("verify 실패");
    assert!(ok);
}

#[test]
fn test_sign_verify_roundtrip_65() {
    let mut rng = make_rng();
    let (pk, sk) = MLDSA::key_gen(MLDSAParameter::MLDSA65, &mut rng).expect("key_gen 실패");

    let sig = MLDSA::sign(&sk, b"Hello, ML-DSA-65!", b"", &mut rng).expect("sign 실패");
    assert_eq!(sig.len(), MLDSAParameter::MLDSA65.sig_len());

    let ok = MLDSA::verify(&pk, b"Hello, ML-DSA-65!", sig.as_slice(), b"").expect("verify 실패");
    assert!(ok);
}

#[test]
fn test_sign_verify_roundtrip_87() {
    let mut rng = make_rng();
    let (pk, sk) = MLDSA::key_gen(MLDSAParameter::MLDSA87, &mut rng).expect("key_gen 실패");

    let sig =
        MLDSA::sign(&sk, b"Hello, ML-DSA-87!", b"security-level-5", &mut rng).expect("sign 실패");
    assert_eq!(sig.len(), MLDSAParameter::MLDSA87.sig_len());

    let ok = MLDSA::verify(
        &pk,
        b"Hello, ML-DSA-87!",
        sig.as_slice(),
        b"security-level-5",
    )
    .expect("verify 실패");
    assert!(ok);
}

//
// 변조된 메시지 거부
//

#[test]
fn test_verify_rejects_tampered_message_44() {
    let mut rng = make_rng();
    let (pk, sk) = MLDSA::key_gen(MLDSAParameter::MLDSA44, &mut rng).expect("key_gen 실패");
    let sig = MLDSA::sign(&sk, b"original", b"", &mut rng).expect("sign 실패");
    let ok = MLDSA::verify(&pk, b"tampered", sig.as_slice(), b"").expect("verify 실패");
    assert!(!ok);
}

#[test]
fn test_verify_rejects_tampered_message_65() {
    let mut rng = make_rng();
    let (pk, sk) = MLDSA::key_gen(MLDSAParameter::MLDSA65, &mut rng).expect("key_gen 실패");
    let sig = MLDSA::sign(&sk, b"original", b"", &mut rng).expect("sign 실패");
    let ok = MLDSA::verify(&pk, b"tampered", sig.as_slice(), b"").expect("verify 실패");
    assert!(!ok);
}

#[test]
fn test_verify_rejects_tampered_message_87() {
    let mut rng = make_rng();
    let (pk, sk) = MLDSA::key_gen(MLDSAParameter::MLDSA87, &mut rng).expect("key_gen 실패");
    let sig = MLDSA::sign(&sk, b"original", b"", &mut rng).expect("sign 실패");
    let ok = MLDSA::verify(&pk, b"tampered", sig.as_slice(), b"").expect("verify 실패");
    assert!(!ok);
}

//
// 변조된 서명 거부
//

#[test]
fn test_verify_rejects_tampered_signature_44() {
    let mut rng = make_rng();
    let (pk, sk) = MLDSA::key_gen(MLDSAParameter::MLDSA44, &mut rng).expect("key_gen 실패");
    let mut sig = MLDSA::sign(&sk, b"test message", b"", &mut rng).expect("sign 실패");
    sig.as_mut_slice()[100] ^= 0xFF;
    let ok = MLDSA::verify(&pk, b"test message", sig.as_slice(), b"").expect("verify 실패");
    assert!(!ok);
}

#[test]
fn test_verify_rejects_tampered_signature_65() {
    let mut rng = make_rng();
    let (pk, sk) = MLDSA::key_gen(MLDSAParameter::MLDSA65, &mut rng).expect("key_gen 실패");
    let mut sig = MLDSA::sign(&sk, b"test message", b"", &mut rng).expect("sign 실패");
    sig.as_mut_slice()[200] ^= 0xFF;
    let ok = MLDSA::verify(&pk, b"test message", sig.as_slice(), b"").expect("verify 실패");
    assert!(!ok);
}

#[test]
fn test_verify_rejects_tampered_signature_87() {
    let mut rng = make_rng();
    let (pk, sk) = MLDSA::key_gen(MLDSAParameter::MLDSA87, &mut rng).expect("key_gen 실패");
    let mut sig = MLDSA::sign(&sk, b"test message", b"", &mut rng).expect("sign 실패");
    sig.as_mut_slice()[300] ^= 0xFF;
    let ok = MLDSA::verify(&pk, b"test message", sig.as_slice(), b"").expect("verify 실패");
    assert!(!ok);
}

//
// 컨텍스트 불일치 거부
//

#[test]
fn test_verify_rejects_wrong_context() {
    let mut rng = make_rng();
    let (pk, sk) = MLDSA::key_gen(MLDSAParameter::MLDSA44, &mut rng).expect("key_gen 실패");
    let sig = MLDSA::sign(&sk, b"test message", b"ctx-A", &mut rng).expect("sign 실패");
    let ok = MLDSA::verify(&pk, b"test message", sig.as_slice(), b"ctx-B").expect("verify 실패");
    assert!(!ok);
}

//
// 컨텍스트 길이 초과 오류
//

#[test]
fn test_sign_rejects_oversized_context() {
    let mut rng = make_rng();
    let (_pk, sk) = MLDSA::key_gen(MLDSAParameter::MLDSA44, &mut rng).expect("key_gen 실패");
    let long_ctx = vec![0u8; 256];
    assert!(MLDSA::sign(&sk, b"msg", &long_ctx, &mut rng).is_err());
}

#[test]
fn test_verify_rejects_oversized_context() {
    let mut rng = make_rng();
    let (pk, _sk) = MLDSA::key_gen(MLDSAParameter::MLDSA44, &mut rng).expect("key_gen 실패");
    let dummy_sig = vec![0u8; MLDSAParameter::MLDSA44.sig_len()];
    let long_ctx = vec![0u8; 256];
    assert!(MLDSA::verify(&pk, b"msg", &dummy_sig, &long_ctx).is_err());
}
