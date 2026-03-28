use entlib_native_armor::asn1::Oid;

pub(crate) fn oid_pbes2() -> Oid {
    Oid::from_arcs(&[1, 2, 840, 113549, 1, 5, 13]).unwrap()
}

pub(crate) fn oid_aes256_gcm() -> Oid {
    Oid::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 1, 46]).unwrap()
}

// 비표준 사설 OID: entlib-native Argon2id KDF 식별자
pub(crate) fn oid_argon2id() -> Oid {
    Oid::from_arcs(&[1, 3, 6, 1, 4, 1, 54752, 1, 1]).unwrap()
}

// NIST FIPS 204 ML-DSA OID
pub(crate) fn oid_mldsa44() -> Oid {
    Oid::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 3, 17]).unwrap()
}

pub(crate) fn oid_mldsa65() -> Oid {
    Oid::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 3, 18]).unwrap()
}

pub(crate) fn oid_mldsa87() -> Oid {
    Oid::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 3, 19]).unwrap()
}

// NIST FIPS 203 ML-KEM OID
pub(crate) fn oid_mlkem512() -> Oid {
    Oid::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 4, 1]).unwrap()
}

pub(crate) fn oid_mlkem768() -> Oid {
    Oid::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 4, 2]).unwrap()
}

pub(crate) fn oid_mlkem1024() -> Oid {
    Oid::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 4, 3]).unwrap()
}
