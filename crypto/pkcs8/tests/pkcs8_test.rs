use entlib_native_pkcs8::{Algorithm, Pkcs8Params, decrypt, decrypt_pem, encrypt, encrypt_pem};

const SALT: [u8; 16] = [0x01; 16];
const NONCE: [u8; 12] = [0x02; 12];

fn test_params(t: u32, m: u32, p: u32) -> Pkcs8Params {
    Pkcs8Params::new(t, m, p, SALT, NONCE)
}

//
// 라운드트립 — DER
//

#[test]
fn encrypt_decrypt_mldsa65_roundtrip() {
    let key = vec![0xABu8; 64];
    let pass = b"correct horse battery staple";
    let params = test_params(1, 64, 1);

    let der = encrypt(Algorithm::MLDSA65, &key, pass, &params).unwrap();
    let (algo, recovered) = decrypt(&der, pass).unwrap();

    assert_eq!(algo, Algorithm::MLDSA65);
    assert_eq!(recovered.as_slice(), &key[..]);
}

#[test]
fn encrypt_decrypt_mldsa44_roundtrip() {
    let key = vec![0x11u8; 32];
    let pass = b"passphrase";
    let params = test_params(1, 64, 1);

    let der = encrypt(Algorithm::MLDSA44, &key, pass, &params).unwrap();
    let (algo, recovered) = decrypt(&der, pass).unwrap();

    assert_eq!(algo, Algorithm::MLDSA44);
    assert_eq!(recovered.as_slice(), &key[..]);
}

#[test]
fn encrypt_decrypt_mldsa87_roundtrip() {
    let key = vec![0xFFu8; 128];
    let pass = b"test";
    let params = test_params(1, 64, 1);

    let der = encrypt(Algorithm::MLDSA87, &key, pass, &params).unwrap();
    let (algo, recovered) = decrypt(&der, pass).unwrap();

    assert_eq!(algo, Algorithm::MLDSA87);
    assert_eq!(recovered.as_slice(), &key[..]);
}

//
// 라운드트립 — PEM
//

#[test]
fn encrypt_pem_decrypt_pem_roundtrip() {
    let key = vec![0x42u8; 48];
    let pass = b"pem passphrase";
    let params = test_params(1, 64, 1);

    let pem = encrypt_pem(Algorithm::MLDSA65, &key, pass, &params).unwrap();
    assert!(
        pem.as_slice()
            .starts_with(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    );

    let (algo, recovered) = decrypt_pem(pem.as_slice(), pass).unwrap();
    assert_eq!(algo, Algorithm::MLDSA65);
    assert_eq!(recovered.as_slice(), &key[..]);
}

//
// 잘못된 패스프레이즈 → AuthenticationFailed
//

#[test]
fn wrong_passphrase_fails() {
    let key = vec![0x77u8; 32];
    let params = test_params(1, 64, 1);

    let der = encrypt(Algorithm::MLDSA65, &key, b"correct", &params).unwrap();
    let err = decrypt(&der, b"wrong").err().unwrap();

    assert_eq!(err, entlib_native_pkcs8::Pkcs8Error::AuthenticationFailed);
}

//
// 결정론성: 동일 파라미터(salt/nonce)는 동일 DER
//

#[test]
fn same_params_deterministic() {
    let key = vec![0x55u8; 32];
    let pass = b"pass";
    let p1 = test_params(1, 64, 1);
    let p2 = test_params(1, 64, 1);

    let d1 = encrypt(Algorithm::MLDSA65, &key, pass, &p1).unwrap();
    let d2 = encrypt(Algorithm::MLDSA65, &key, pass, &p2).unwrap();
    assert_eq!(d1, d2);
}

//
// 다른 salt → 다른 DER
//

#[test]
fn different_salts_produce_different_der() {
    let key = vec![0x33u8; 32];
    let pass = b"same_pass";

    let s1 = SALT;
    let mut s2 = SALT;
    s2[0] ^= 0xFF;

    let p1 = Pkcs8Params::new(1, 64, 1, s1, NONCE);
    let p2 = Pkcs8Params::new(1, 64, 1, s2, NONCE);

    let d1 = encrypt(Algorithm::MLDSA65, &key, pass, &p1).unwrap();
    let d2 = encrypt(Algorithm::MLDSA65, &key, pass, &p2).unwrap();
    assert_ne!(d1, d2);
}

//
// 빈 키도 허용
//

#[test]
fn empty_key_accepted() {
    let params = test_params(1, 64, 1);
    let der = encrypt(Algorithm::MLDSA65, &[], b"pass", &params).unwrap();
    let (_, recovered) = decrypt(&der, b"pass").unwrap();
    assert_eq!(recovered.as_slice(), &[] as &[u8]);
}

//
// Algorithm::from_name
//

#[test]
fn algorithm_from_name_roundtrip() {
    for (name, expected) in [
        ("ml-dsa-44", Algorithm::MLDSA44),
        ("ml-dsa-65", Algorithm::MLDSA65),
        ("ml-dsa-87", Algorithm::MLDSA87),
        ("ML-DSA-44", Algorithm::MLDSA44),
        ("mldsa65", Algorithm::MLDSA65),
    ] {
        assert_eq!(Algorithm::from_name(name).unwrap(), expected, "name={name}");
    }
}

#[test]
fn algorithm_from_name_invalid() {
    assert!(Algorithm::from_name("rsa-2048").is_err());
    assert!(Algorithm::from_name("").is_err());
}
