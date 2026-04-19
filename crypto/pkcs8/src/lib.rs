mod algorithm;
mod error;
mod oid;

pub use algorithm::Algorithm;
pub use error::Pkcs8Error;

use core::ptr::write_volatile;
use entlib_native_aes::{AES256GCM, GCM_NONCE_LEN, GCM_TAG_LEN};
use entlib_native_argon2id::Argon2id;
use entlib_native_armor::{
    ArmorError,
    der::{DerReader, DerWriter, MAX_DEPTH},
    pem::{PemLabel, decode as pem_decode, encode as pem_encode},
};
use entlib_native_secure_buffer::SecureBuffer;

// NIST SP 800-63B 권고 파라미터
pub const DEFAULT_TIME_COST: u32 = 2;
pub const DEFAULT_MEMORY_COST: u32 = 19456;
pub const DEFAULT_PARALLELISM: u32 = 1;

pub struct Pkcs8Params {
    pub time_cost: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
    pub salt: [u8; 16],
    pub nonce: [u8; GCM_NONCE_LEN],
}

impl Pkcs8Params {
    pub fn new(
        time_cost: u32,
        memory_cost: u32,
        parallelism: u32,
        salt: [u8; 16],
        nonce: [u8; GCM_NONCE_LEN],
    ) -> Self {
        Self {
            time_cost,
            memory_cost,
            parallelism,
            salt,
            nonce,
        }
    }
}

/// 개인 키를 PKCS#8 EncryptedPrivateKeyInfo DER로 암호화합니다.
pub fn encrypt(
    algorithm: Algorithm,
    key_bytes: &[u8],
    passphrase: &[u8],
    params: &Pkcs8Params,
) -> Result<Vec<u8>, Pkcs8Error> {
    let pki = encode_pki(algorithm, key_bytes)?;
    let key = derive_key(
        passphrase,
        &params.salt,
        params.time_cost,
        params.memory_cost,
        params.parallelism,
    )?;

    let pt = pki.as_slice();
    let mut ct = vec![0u8; pt.len()];
    let mut tag = [0u8; GCM_TAG_LEN];
    AES256GCM::encrypt(&key, &params.nonce, &[], pt, &mut ct, &mut tag)
        .map_err(|_| Pkcs8Error::EncryptionFailed)?;

    let mut encrypted_data = Vec::with_capacity(ct.len() + GCM_TAG_LEN);
    encrypted_data.extend_from_slice(&ct);
    encrypted_data.extend_from_slice(&tag);

    encode_epki(&encrypted_data, params)
}

/// PKCS#8 EncryptedPrivateKeyInfo DER을 복호화합니다.
pub fn decrypt(
    encrypted_der: &[u8],
    passphrase: &[u8],
) -> Result<(Algorithm, SecureBuffer), Pkcs8Error> {
    decode_epki(encrypted_der, passphrase)
}

/// 개인 키를 PKCS#8 PEM으로 암호화합니다.
pub fn encrypt_pem(
    algorithm: Algorithm,
    key_bytes: &[u8],
    passphrase: &[u8],
    params: &Pkcs8Params,
) -> Result<SecureBuffer, Pkcs8Error> {
    let der = encrypt(algorithm, key_bytes, passphrase, params)?;
    pem_encode(&der, PemLabel::EncryptedPrivateKey).map_err(|_| Pkcs8Error::PemEncodingFailed)
}

/// PKCS#8 PEM을 복호화합니다.
pub fn decrypt_pem(pem: &[u8], passphrase: &[u8]) -> Result<(Algorithm, SecureBuffer), Pkcs8Error> {
    let (label, der) = pem_decode(pem).map_err(|_| Pkcs8Error::PemDecodingFailed)?;
    if label != PemLabel::EncryptedPrivateKey {
        return Err(Pkcs8Error::InvalidStructure);
    }
    decode_epki(der.as_slice(), passphrase)
}

/// 공개 키를 SubjectPublicKeyInfo PEM으로 인코딩합니다.
pub fn encode_spki_pem(algorithm: Algorithm, pk_bytes: &[u8]) -> Result<SecureBuffer, Pkcs8Error> {
    let e = |_: ArmorError| Pkcs8Error::DerEncodingFailed;

    let mut alg_w = DerWriter::new();
    alg_w.write_oid(&algorithm.oid()).map_err(e)?;
    let alg_contents = alg_w.finish();

    let mut spki_w = DerWriter::new();
    spki_w.write_sequence(&alg_contents).map_err(e)?;
    spki_w.write_bit_string(pk_bytes, 0).map_err(e)?;
    let spki_contents = spki_w.finish();

    let mut outer = DerWriter::new();
    outer.write_sequence(&spki_contents).map_err(e)?;
    let der = outer.finish();

    pem_encode(&der, PemLabel::PublicKey).map_err(|_| Pkcs8Error::PemEncodingFailed)
}

// PrivateKeyInfo ::= SEQUENCE { INTEGER 0, SEQUENCE { OID }, OCTET STRING key }
fn encode_pki(algorithm: Algorithm, key_bytes: &[u8]) -> Result<SecureBuffer, Pkcs8Error> {
    let e = |_: ArmorError| Pkcs8Error::DerEncodingFailed;

    let mut alg_w = DerWriter::new();
    alg_w.write_oid(&algorithm.oid()).map_err(e)?;
    let alg_contents = alg_w.finish();

    let mut pki_w = DerWriter::new();
    pki_w.write_integer_unsigned(&[0u8]).map_err(e)?;
    pki_w.write_sequence(&alg_contents).map_err(e)?;
    pki_w.write_octet_string(key_bytes).map_err(e)?;
    let pki_contents = pki_w.finish();

    let mut outer = DerWriter::new();
    outer.write_sequence(&pki_contents).map_err(e)?;
    let mut der = outer.finish();

    let mut buf = SecureBuffer::new_owned(der.len()).map_err(|_| Pkcs8Error::AllocationFailed)?;
    buf.as_mut_slice().copy_from_slice(&der);
    for b in der.iter_mut() {
        unsafe { write_volatile(b, 0) };
    }
    Ok(buf)
}

// EncryptedPrivateKeyInfo DER 인코딩
fn encode_epki(encrypted_data: &[u8], params: &Pkcs8Params) -> Result<Vec<u8>, Pkcs8Error> {
    let e = |_: ArmorError| Pkcs8Error::DerEncodingFailed;

    let mut a2_w = DerWriter::new();
    a2_w.write_integer_unsigned(&params.time_cost.to_be_bytes())
        .map_err(e)?;
    a2_w.write_integer_unsigned(&params.memory_cost.to_be_bytes())
        .map_err(e)?;
    a2_w.write_integer_unsigned(&params.parallelism.to_be_bytes())
        .map_err(e)?;
    a2_w.write_octet_string(&params.salt).map_err(e)?;
    let a2_params = a2_w.finish();

    let mut kdf_w = DerWriter::new();
    kdf_w.write_oid(&oid::oid_argon2id()).map_err(e)?;
    kdf_w.write_sequence(&a2_params).map_err(e)?;
    let kdf_contents = kdf_w.finish();

    let mut gcm_w = DerWriter::new();
    gcm_w.write_octet_string(&params.nonce).map_err(e)?;
    gcm_w
        .write_integer_unsigned(&[GCM_TAG_LEN as u8])
        .map_err(e)?;
    let gcm_params = gcm_w.finish();

    let mut enc_w = DerWriter::new();
    enc_w.write_oid(&oid::oid_aes256_gcm()).map_err(e)?;
    enc_w.write_sequence(&gcm_params).map_err(e)?;
    let enc_contents = enc_w.finish();

    let mut pbes2_w = DerWriter::new();
    pbes2_w.write_sequence(&kdf_contents).map_err(e)?;
    pbes2_w.write_sequence(&enc_contents).map_err(e)?;
    let pbes2_contents = pbes2_w.finish();

    let mut alg_w = DerWriter::new();
    alg_w.write_oid(&oid::oid_pbes2()).map_err(e)?;
    alg_w.write_sequence(&pbes2_contents).map_err(e)?;
    let alg_contents = alg_w.finish();

    let mut epki_w = DerWriter::new();
    epki_w.write_sequence(&alg_contents).map_err(e)?;
    epki_w.write_octet_string(encrypted_data).map_err(e)?;
    let epki_contents = epki_w.finish();

    let mut outer = DerWriter::new();
    outer.write_sequence(&epki_contents).map_err(e)?;
    Ok(outer.finish())
}

// EncryptedPrivateKeyInfo DER 파싱 및 복호화
fn decode_epki(der: &[u8], passphrase: &[u8]) -> Result<(Algorithm, SecureBuffer), Pkcs8Error> {
    let e_der = |_: ArmorError| Pkcs8Error::DerDecodingFailed;
    let mut depth = MAX_DEPTH;

    let mut r = DerReader::new(der).map_err(e_der)?;
    let mut epki = r.read_sequence(&mut depth).map_err(e_der)?;
    r.expect_empty().map_err(e_der)?;

    // AlgorithmIdentifier
    let mut alg_id = epki.read_sequence(&mut depth).map_err(e_der)?;
    let pbes2_oid = alg_id.read_oid().map_err(e_der)?;
    if !pbes2_oid.ct_eq(&oid::oid_pbes2()) {
        return Err(Pkcs8Error::InvalidStructure);
    }

    // PBES2-params
    let mut pbes2 = alg_id.read_sequence(&mut depth).map_err(e_der)?;
    alg_id.expect_empty().map_err(e_der)?;

    // keyDerivationFunc
    let mut kdf = pbes2.read_sequence(&mut depth).map_err(e_der)?;
    let kdf_oid = kdf.read_oid().map_err(e_der)?;
    if !kdf_oid.ct_eq(&oid::oid_argon2id()) {
        return Err(Pkcs8Error::InvalidStructure);
    }
    let mut a2_params = kdf.read_sequence(&mut depth).map_err(e_der)?;
    kdf.expect_empty().map_err(e_der)?;

    let tc = der_integer_to_u32(a2_params.read_integer_bytes().map_err(e_der)?)?;
    let mc = der_integer_to_u32(a2_params.read_integer_bytes().map_err(e_der)?)?;
    let par = der_integer_to_u32(a2_params.read_integer_bytes().map_err(e_der)?)?;
    let salt = a2_params.read_octet_string().map_err(e_der)?;
    a2_params.expect_empty().map_err(e_der)?;
    if salt.len() < 8 {
        return Err(Pkcs8Error::InvalidStructure);
    }

    // encryptionScheme
    let mut enc = pbes2.read_sequence(&mut depth).map_err(e_der)?;
    pbes2.expect_empty().map_err(e_der)?;
    let gcm_oid = enc.read_oid().map_err(e_der)?;
    if !gcm_oid.ct_eq(&oid::oid_aes256_gcm()) {
        return Err(Pkcs8Error::InvalidStructure);
    }
    let mut gcm_params = enc.read_sequence(&mut depth).map_err(e_der)?;
    enc.expect_empty().map_err(e_der)?;
    let nonce = gcm_params.read_octet_string().map_err(e_der)?;
    let _tag_len = gcm_params.read_integer_bytes().map_err(e_der)?;
    gcm_params.expect_empty().map_err(e_der)?;
    if nonce.len() != GCM_NONCE_LEN {
        return Err(Pkcs8Error::InvalidStructure);
    }

    // encryptedData
    let encrypted_data = epki.read_octet_string().map_err(e_der)?;
    epki.expect_empty().map_err(e_der)?;
    if encrypted_data.len() < GCM_TAG_LEN {
        return Err(Pkcs8Error::InvalidStructure);
    }
    let ct_len = encrypted_data.len() - GCM_TAG_LEN;
    let ct = &encrypted_data[..ct_len];
    let tag: [u8; GCM_TAG_LEN] = encrypted_data[ct_len..]
        .try_into()
        .map_err(|_| Pkcs8Error::InvalidStructure)?;
    let nonce_arr: [u8; GCM_NONCE_LEN] =
        nonce.try_into().map_err(|_| Pkcs8Error::InvalidStructure)?;

    let key = derive_key(passphrase, salt, tc, mc, par)?;

    let mut pt = SecureBuffer::new_owned(ct_len).map_err(|_| Pkcs8Error::AllocationFailed)?;
    AES256GCM::decrypt(&key, &nonce_arr, &[], ct, &tag, pt.as_mut_slice())
        .map_err(|_| Pkcs8Error::AuthenticationFailed)?;

    // PrivateKeyInfo 파싱
    let pki_der = pt.as_slice();
    let mut depth2 = MAX_DEPTH;
    let mut pki_r = DerReader::new(pki_der).map_err(e_der)?;
    let mut pki = pki_r.read_sequence(&mut depth2).map_err(e_der)?;
    pki_r.expect_empty().map_err(e_der)?;
    let _version = pki.read_integer_bytes().map_err(e_der)?;
    let mut alg_seq = pki.read_sequence(&mut depth2).map_err(e_der)?;
    let alg_oid = alg_seq.read_oid().map_err(e_der)?;
    let algorithm = Algorithm::from_oid(&alg_oid)?;
    let key_buf = pki.read_octet_string_secure().map_err(e_der)?;
    pki.expect_empty().map_err(e_der)?;

    Ok((algorithm, key_buf))
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
) -> Result<SecureBuffer, Pkcs8Error> {
    Argon2id::new(time_cost, memory_cost, parallelism, 32)
        .and_then(|a| a.hash(passphrase, salt, &[], &[]))
        .map_err(|_| Pkcs8Error::KdfFailed)
}

fn der_integer_to_u32(bytes: &[u8]) -> Result<u32, Pkcs8Error> {
    let s = if bytes.first() == Some(&0x00) {
        &bytes[1..]
    } else {
        bytes
    };
    if s.len() > 4 {
        return Err(Pkcs8Error::InvalidStructure);
    }
    let mut val = 0u32;
    for &b in s {
        val = (val << 8) | (b as u32);
    }
    Ok(val)
}
