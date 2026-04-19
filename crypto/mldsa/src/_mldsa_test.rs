#[cfg(test)]
mod tests {
    use crate::mldsa::{MLDSA, MLDSAParameter};
    use crate::mldsa_keys::{
        MLDSAPrivateKey, MLDSAPrivateKeyTrait, MLDSAPublicKey, MLDSAPublicKeyTrait, keygen_internal,
    };
    use crate::ntt::N;

    // ML-DSA-44 파라미터
    const K44: usize = 4;
    const L44: usize = 4;
    const ETA44: i32 = 2;
    const PK44_LEN: usize = 1312;
    const SK44_LEN: usize = 2560;

    // ML-DSA-65 파라미터
    const K65: usize = 6;
    const L65: usize = 5;
    const ETA65: i32 = 4;
    const PK65_LEN: usize = 1952;
    const SK65_LEN: usize = 4032;

    //
    // pkEncode / pkDecode 라운드트립 (ML-DSA-44)
    //

    #[test]
    fn test_pk_encode_decode_roundtrip_44() {
        let xi = [0u8; 32];
        let (pk, _sk) = keygen_internal::<K44, L44, ETA44>(&xi).expect("keygen_internal failed");

        // pkEncode
        let pk_bytes: [u8; PK44_LEN] =
            <MLDSAPublicKey<K44> as MLDSAPublicKeyTrait<K44, PK44_LEN>>::pk_encode(&pk);

        // pkDecode
        let pk2 = <MLDSAPublicKey<K44> as MLDSAPublicKeyTrait<K44, PK44_LEN>>::pk_decode(&pk_bytes);

        // ρ 일치 검증
        assert_eq!(pk.rho, pk2.rho, "pkDecode: ρ 불일치");

        // t1 계수 일치 검증
        for i in 0..K44 {
            for j in 0..N {
                assert_eq!(
                    pk.t1.vec[i].coeffs[j].0, pk2.t1.vec[i].coeffs[j].0,
                    "pkDecode: t1[{i}][{j}] 불일치"
                );
            }
        }
    }

    //
    // pkEncode / pkDecode 라운드트립 (ML-DSA-65)
    //

    #[test]
    fn test_pk_encode_decode_roundtrip_65() {
        let xi = [1u8; 32];
        let (pk, _sk) = keygen_internal::<K65, L65, ETA65>(&xi).expect("keygen_internal failed");

        let pk_bytes: [u8; PK65_LEN] =
            <MLDSAPublicKey<K65> as MLDSAPublicKeyTrait<K65, PK65_LEN>>::pk_encode(&pk);
        let pk2 = <MLDSAPublicKey<K65> as MLDSAPublicKeyTrait<K65, PK65_LEN>>::pk_decode(&pk_bytes);

        assert_eq!(pk.rho, pk2.rho, "pkDecode: ρ 불일치");
        for i in 0..K65 {
            for j in 0..N {
                assert_eq!(
                    pk.t1.vec[i].coeffs[j].0, pk2.t1.vec[i].coeffs[j].0,
                    "pkDecode: t1[{i}][{j}] 불일치"
                );
            }
        }
    }

    //
    // skEncode / skDecode 라운드트립 (ML-DSA-44)
    //

    #[test]
    fn test_sk_encode_decode_roundtrip_44() {
        type SK44 = MLDSAPrivateKey<K44, L44, ETA44>;

        let xi = [2u8; 32];
        let (_pk, sk) = keygen_internal::<K44, L44, ETA44>(&xi).expect("keygen_internal failed");

        // skEncode → SecureBuffer
        let sk_buf = <SK44 as MLDSAPrivateKeyTrait<K44, L44, SK44_LEN>>::sk_encode(&sk)
            .expect("skEncode failed");

        // SecureBuffer 길이 검증
        assert_eq!(sk_buf.len(), SK44_LEN, "skEncode: 길이 불일치");

        // skDecode
        let sk2 = <SK44 as MLDSAPrivateKeyTrait<K44, L44, SK44_LEN>>::sk_decode(&sk_buf)
            .expect("skDecode failed");

        // 고정 필드 일치 검증
        assert_eq!(sk.rho, sk2.rho, "skDecode: ρ 불일치");
        assert_eq!(sk.k_seed, sk2.k_seed, "skDecode: K_seed 불일치");
        assert_eq!(sk.tr, sk2.tr, "skDecode: tr 불일치");

        // s1 계수 일치 검증
        for i in 0..L44 {
            for j in 0..N {
                assert_eq!(
                    sk.s1.vec[i].coeffs[j].0, sk2.s1.vec[i].coeffs[j].0,
                    "skDecode: s1[{i}][{j}] 불일치"
                );
            }
        }

        // s2 계수 일치 검증
        for i in 0..K44 {
            for j in 0..N {
                assert_eq!(
                    sk.s2.vec[i].coeffs[j].0, sk2.s2.vec[i].coeffs[j].0,
                    "skDecode: s2[{i}][{j}] 불일치"
                );
            }
        }

        // t0 계수 일치 검증
        for i in 0..K44 {
            for j in 0..N {
                assert_eq!(
                    sk.t0.vec[i].coeffs[j].0, sk2.t0.vec[i].coeffs[j].0,
                    "skDecode: t0[{i}][{j}] 불일치"
                );
            }
        }
    }

    //
    // skEncode / skDecode 라운드트립 (ML-DSA-65)
    //

    #[test]
    fn test_sk_encode_decode_roundtrip_65() {
        type SK65 = MLDSAPrivateKey<K65, L65, ETA65>;

        let xi = [3u8; 32];
        let (_pk, sk) = keygen_internal::<K65, L65, ETA65>(&xi).expect("keygen_internal failed");

        let sk_buf = <SK65 as MLDSAPrivateKeyTrait<K65, L65, SK65_LEN>>::sk_encode(&sk)
            .expect("skEncode failed");

        assert_eq!(sk_buf.len(), SK65_LEN, "skEncode: 길이 불일치");

        let sk2 = <SK65 as MLDSAPrivateKeyTrait<K65, L65, SK65_LEN>>::sk_decode(&sk_buf)
            .expect("skDecode failed");

        assert_eq!(sk.rho, sk2.rho, "skDecode: ρ 불일치");
        assert_eq!(sk.k_seed, sk2.k_seed, "skDecode: K_seed 불일치");
        assert_eq!(sk.tr, sk2.tr, "skDecode: tr 불일치");
    }

    //
    // 서명 + 검증 종단 간 테스트 (ML-DSA-44)
    //

    #[test]
    fn test_sign_verify_roundtrip_44() {
        let xi = [0xAAu8; 32];
        let (pk_bytes, sk_buf) =
            MLDSA::key_gen_internal(MLDSAParameter::MLDSA44, &xi).expect("key_gen_internal failed");

        let message = b"Hello, ML-DSA-44!";
        let m_prime = {
            let mut v = Vec::new();
            v.push(0x00u8); // domain_sep
            v.push(0u8); // |ctx| = 0
            v.extend_from_slice(message);
            v
        };
        let rnd = [0u8; 32]; // 결정론적 서명

        let sig = MLDSA::sign_internal(MLDSAParameter::MLDSA44, &sk_buf, &m_prime, &rnd)
            .expect("sign_internal failed");

        assert_eq!(sig.len(), 2420, "서명 길이 불일치");

        let ok =
            MLDSA::verify_internal(MLDSAParameter::MLDSA44, &pk_bytes, &m_prime, sig.as_slice())
                .expect("verify_internal failed");

        assert!(ok, "서명 검증 실패 (ML-DSA-44)");
    }

    //
    // 서명 + 검증 종단 간 테스트 (ML-DSA-65)
    //

    #[test]
    fn test_sign_verify_roundtrip_65() {
        let xi = [0xBBu8; 32];
        let (pk_bytes, sk_buf) =
            MLDSA::key_gen_internal(MLDSAParameter::MLDSA65, &xi).expect("key_gen_internal failed");

        let message = b"Hello, ML-DSA-65!";
        let m_prime = {
            let mut v = Vec::new();
            v.push(0x00u8);
            v.push(0u8);
            v.extend_from_slice(message);
            v
        };
        let rnd = [0u8; 32];

        let sig = MLDSA::sign_internal(MLDSAParameter::MLDSA65, &sk_buf, &m_prime, &rnd)
            .expect("sign_internal failed");

        assert_eq!(sig.len(), 3309, "서명 길이 불일치");

        let ok =
            MLDSA::verify_internal(MLDSAParameter::MLDSA65, &pk_bytes, &m_prime, sig.as_slice())
                .expect("verify_internal failed");

        assert!(ok, "서명 검증 실패 (ML-DSA-65)");
    }

    //
    // 변조된 메시지 검증 거부 테스트
    //

    #[test]
    fn test_verify_rejects_tampered_message_44() {
        let xi = [0xCCu8; 32];
        let (pk_bytes, sk_buf) =
            MLDSA::key_gen_internal(MLDSAParameter::MLDSA44, &xi).expect("key_gen_internal failed");

        let m_prime_orig = b"\x00\x00Hello";
        let rnd = [0u8; 32];

        let sig = MLDSA::sign_internal(MLDSAParameter::MLDSA44, &sk_buf, m_prime_orig, &rnd)
            .expect("sign_internal failed");

        let m_prime_tampered = b"\x00\x00World";
        let ok = MLDSA::verify_internal(
            MLDSAParameter::MLDSA44,
            &pk_bytes,
            m_prime_tampered,
            sig.as_slice(),
        )
        .expect("verify_internal error");

        assert!(!ok, "변조된 메시지가 검증을 통과해서는 안 됩니다");
    }

    //
    // 변조된 서명 검증 거부 테스트
    //

    #[test]
    fn test_verify_rejects_tampered_signature_44() {
        let xi = [0xDDu8; 32];
        let (pk_bytes, sk_buf) =
            MLDSA::key_gen_internal(MLDSAParameter::MLDSA44, &xi).expect("key_gen_internal failed");

        let m_prime = b"\x00\x00TestMessage";
        let rnd = [0u8; 32];

        let mut sig = MLDSA::sign_internal(MLDSAParameter::MLDSA44, &sk_buf, m_prime, &rnd)
            .expect("sign_internal failed");

        // 서명 중간 바이트 비트 플립
        sig.as_mut_slice()[100] ^= 0xFF;

        let ok =
            MLDSA::verify_internal(MLDSAParameter::MLDSA44, &pk_bytes, m_prime, sig.as_slice())
                .expect("verify_internal error");

        assert!(!ok, "변조된 서명이 검증을 통과해서는 안 됩니다");
    }
}
