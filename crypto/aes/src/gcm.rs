//! AES-256-GCM AEAD 모듈입니다.
//! NIST SP 800-38D 준거. 96비트 nonce, 128비트 인증 태그를 지원합니다.

use core::ptr::write_volatile;
use entlib_native_constant_time::traits::ConstantTimeEq;
use entlib_native_secure_buffer::SecureBuffer;

use crate::aes::{aes256_encrypt_block, KeySchedule};
use crate::error::AESError;
use crate::ghash::GHashState;

// GCM은 96비트(12 bytes) nonce만 지원 (NIST SP 800-38D 권고)
pub const GCM_NONCE_LEN: usize = 12;
pub const GCM_TAG_LEN: usize = 16;

// J0 = nonce(12) || 0x00000001
fn build_j0(nonce: &[u8; 12]) -> [u8; 16] {
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 0x01;
    j0
}

// inc32: J0의 하위 32비트를 빅엔디안으로 1 증가
fn inc32(block: &[u8; 16]) -> [u8; 16] {
    let mut out = *block;
    let ctr = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);
    let next = ctr.wrapping_add(1).to_be_bytes();
    out[12] = next[0];
    out[13] = next[1];
    out[14] = next[2];
    out[15] = next[3];
    out
}

// GCTR: CTR 모드 암·복호화 (J0+1부터 시작)
// output.len() == data.len() 보장
fn gctr(ks: &KeySchedule, j0: &[u8; 16], data: &[u8], output: &mut [u8]) {
    let mut ctr = inc32(j0);
    let mut keystream = [0u8; 16];
    let mut i = 0;
    while i < data.len() {
        keystream = ctr;
        aes256_encrypt_block(&mut keystream, ks);
        let chunk = core::cmp::min(16, data.len() - i);
        for j in 0..chunk {
            output[i + j] = data[i + j] ^ keystream[j];
        }
        i += chunk;
        ctr = inc32(&ctr);
    }
    for b in &mut keystream {
        unsafe { write_volatile(b, 0) };
    }
}

// 16바이트 슬라이스 상수-시간 비교
fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut r = 0xFFu8;
    for i in 0..16 {
        r &= a[i].ct_eq(&b[i]).unwrap_u8();
    }
    r == 0xFF
}

/// AES-256-GCM AEAD 암호화 구조체입니다.
/// NIST SP 800-38D 준거이며 96비트 nonce만 지원합니다.
pub struct AES256GCM;

impl AES256GCM {
    /// AES-256-GCM 암호화 함수입니다.
    ///
    /// # Arguments
    /// - `key` — 256비트(32 bytes) AES 키
    /// - `nonce` — 96비트(12 bytes) nonce (반드시 유일해야 함)
    /// - `aad` — 추가 인증 데이터 (암호화되지 않음)
    /// - `plaintext` — 평문
    /// - `ciphertext_out` — 암호문 출력 버퍼 (`plaintext.len()` bytes)
    /// - `tag_out` — 16바이트 인증 태그 출력
    ///
    /// # Security Note
    /// 동일한 (key, nonce) 쌍을 재사용하면 기밀성·무결성이 완전히 붕괴됩니다.
    pub fn encrypt(
        key: &SecureBuffer,
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext_out: &mut [u8],
        tag_out: &mut [u8; GCM_TAG_LEN],
    ) -> Result<(), AESError> {
        if key.len() != 32 {
            return Err(AESError::InvalidKeyLength);
        }
        if ciphertext_out.len() < plaintext.len() {
            return Err(AESError::OutputBufferTooSmall);
        }

        let key_arr: [u8; 32] = {
            let s = key.as_slice();
            [
                s[0],  s[1],  s[2],  s[3],  s[4],  s[5],  s[6],  s[7],
                s[8],  s[9],  s[10], s[11], s[12], s[13], s[14], s[15],
                s[16], s[17], s[18], s[19], s[20], s[21], s[22], s[23],
                s[24], s[25], s[26], s[27], s[28], s[29], s[30], s[31],
            ]
        };
        let ks = KeySchedule::new(&key_arr);

        // H = AES_K(0^128)
        let mut h_block = [0u8; 16];
        aes256_encrypt_block(&mut h_block, &ks);

        let j0 = build_j0(nonce);

        // 평문 암호화 (CTR)
        gctr(&ks, &j0, plaintext, ciphertext_out);

        // GHASH(AAD, CT)
        let mut ghash = GHashState::new(&h_block);
        ghash.update(aad);
        ghash.update(&ciphertext_out[..plaintext.len()]);
        let s = ghash.finalize(aad.len() as u64, plaintext.len() as u64);

        // 태그 = E_K(J0) XOR GHASH
        let mut ej0 = j0;
        aes256_encrypt_block(&mut ej0, &ks);
        for i in 0..16 {
            tag_out[i] = ej0[i] ^ s[i];
        }

        for b in &mut ej0 {
            unsafe { write_volatile(b, 0) };
        }
        for b in &mut h_block {
            unsafe { write_volatile(b, 0) };
        }
        Ok(())
    }

    /// AES-256-GCM 복호화 및 태그 검증 함수입니다.
    ///
    /// # Security Note
    /// 태그 검증에 실패하면 평문을 출력하지 않습니다. 상수-시간 비교를 사용합니다.
    pub fn decrypt(
        key: &SecureBuffer,
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; GCM_TAG_LEN],
        plaintext_out: &mut [u8],
    ) -> Result<(), AESError> {
        if key.len() != 32 {
            return Err(AESError::InvalidKeyLength);
        }
        if plaintext_out.len() < ciphertext.len() {
            return Err(AESError::OutputBufferTooSmall);
        }

        let key_arr: [u8; 32] = {
            let s = key.as_slice();
            [
                s[0],  s[1],  s[2],  s[3],  s[4],  s[5],  s[6],  s[7],
                s[8],  s[9],  s[10], s[11], s[12], s[13], s[14], s[15],
                s[16], s[17], s[18], s[19], s[20], s[21], s[22], s[23],
                s[24], s[25], s[26], s[27], s[28], s[29], s[30], s[31],
            ]
        };
        let ks = KeySchedule::new(&key_arr);

        let mut h_block = [0u8; 16];
        aes256_encrypt_block(&mut h_block, &ks);

        let j0 = build_j0(nonce);

        // 태그 재계산 (복호화 전)
        let mut ghash = GHashState::new(&h_block);
        ghash.update(aad);
        ghash.update(ciphertext);
        let s = ghash.finalize(aad.len() as u64, ciphertext.len() as u64);

        let mut ej0 = j0;
        aes256_encrypt_block(&mut ej0, &ks);
        let mut expected_tag = [0u8; 16];
        for i in 0..16 {
            expected_tag[i] = ej0[i] ^ s[i];
        }

        // 상수-시간 태그 검증 — 검증 통과 전에 평문 출력 금지
        if !ct_eq_16(&expected_tag, tag) {
            for b in &mut ej0 { unsafe { write_volatile(b, 0) }; }
            for b in &mut h_block { unsafe { write_volatile(b, 0) }; }
            return Err(AESError::AuthenticationFailed);
        }

        // 태그 검증 통과 후에만 복호화
        gctr(&ks, &j0, ciphertext, plaintext_out);

        for b in &mut ej0 { unsafe { write_volatile(b, 0) }; }
        for b in &mut h_block { unsafe { write_volatile(b, 0) }; }
        Ok(())
    }
}
