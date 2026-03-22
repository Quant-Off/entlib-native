use core::ptr::write_volatile;
use entlib_native_constant_time::traits::ConstantTimeEq;
use entlib_native_hmac::HMACSHA256;
use entlib_native_secure_buffer::SecureBuffer;

use crate::aes::{aes256_decrypt_block, aes256_encrypt_block, KeySchedule};
use crate::error::AESError;

pub const CBC_IV_LEN: usize = 16;
pub const CBC_HMAC_LEN: usize = 32;

/// CBC 암호화 출력 크기: IV(16) || 패딩된 암호문 || HMAC-SHA256(32)
pub fn cbc_output_len(plaintext_len: usize) -> usize {
    let padded = (plaintext_len / 16 + 1) * 16;
    CBC_IV_LEN + padded + CBC_HMAC_LEN
}

/// CBC 복호화 최대 평문 크기 (입력에서 IV·HMAC 제거, PKCS7 최소 1바이트)
pub fn cbc_plaintext_max_len(input_len: usize) -> Option<usize> {
    input_len.checked_sub(CBC_IV_LEN + CBC_HMAC_LEN + 1)
}

// 32바이트 슬라이스 상수-시간 비교
fn ct_eq_32(a: &[u8], b: &[u8]) -> bool {
    if a.len() != 32 || b.len() != 32 {
        return false;
    }
    let mut r = 0xFFu8;
    for i in 0..32 {
        r &= a[i].ct_eq(&b[i]).unwrap_u8();
    }
    r == 0xFF
}

// PKCS7 패딩 검증 (복호화 후) — HMAC 검증 통과 후에만 호출
fn pkcs7_unpad_len(data: &[u8]) -> Result<usize, AESError> {
    if data.is_empty() || data.len() % 16 != 0 {
        return Err(AESError::InternalError);
    }
    let pad_byte = data[data.len() - 1];
    let pad_len = pad_byte as usize;
    if pad_len == 0 || pad_len > 16 {
        return Err(AESError::InternalError);
    }
    // 패딩 바이트 상수-시간 검증
    let mut valid = 0xFFu8;
    for i in (data.len() - pad_len)..data.len() {
        let diff = data[i] ^ pad_byte;
        let not_zero = (diff | diff.wrapping_neg()) >> 7;
        valid &= (not_zero ^ 1).wrapping_neg();
    }
    if valid == 0xFF {
        Ok(data.len() - pad_len)
    } else {
        Err(AESError::InternalError)
    }
}

// Q. T. Felix NOTE: 설계 중에 알아차린건데, HMAC-SHA-256 단일로 계산되도록 구현해버림
// fxxk@@@ ^^7 일단 커밋 하고 pr로 수정
//

/// AES-256-CBC + PKCS7 + Encrypt-then-MAC(HMAC-SHA256)
///
/// CBC 모드는 단독으로 사용할 수 없습니다. 암호문 전체(IV 포함)에
/// 대해 HMAC-SHA256 무결성 태그를 붙여야 합니다.
pub struct AES256CBCHmac;

impl AES256CBCHmac {
    /// CBC-HMAC 암호화
    ///
    /// # Arguments
    /// - `enc_key` — 256비트(32 bytes) AES 암호화 키
    /// - `mac_key` — HMAC-SHA256 무결성 키 (최소 14 bytes, 권장 32 bytes)
    /// - `iv` — 128비트(16 bytes) 초기화 벡터 (각 메시지마다 고유해야 함)
    /// - `plaintext` — 평문
    /// - `output` — 출력 버퍼, 최소 `cbc_output_len(plaintext.len())` bytes
    ///
    /// # Returns
    /// 출력에 쓰인 바이트 수
    ///
    /// # Security Note
    /// 출력 형식: `IV(16) || CT_padded || HMAC-SHA256(IV||CT_padded)(32)`
    /// IV는 각 암호화마다 고유한 값을 사용해야 합니다(nonce-reuse 금지).
    pub fn encrypt(
        enc_key: &SecureBuffer,
        mac_key: &SecureBuffer,
        iv: &[u8; CBC_IV_LEN],
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, AESError> {
        if enc_key.len() != 32 {
            return Err(AESError::InvalidKeyLength);
        }
        let required = cbc_output_len(plaintext.len());
        if output.len() < required {
            return Err(AESError::OutputBufferTooSmall);
        }

        let enc_key_arr: [u8; 32] = {
            let s = enc_key.as_slice();
            [
                s[0],  s[1],  s[2],  s[3],  s[4],  s[5],  s[6],  s[7],
                s[8],  s[9],  s[10], s[11], s[12], s[13], s[14], s[15],
                s[16], s[17], s[18], s[19], s[20], s[21], s[22], s[23],
                s[24], s[25], s[26], s[27], s[28], s[29], s[30], s[31],
            ]
        };
        let ks = KeySchedule::new(&enc_key_arr);

        // IV를 출력 선두에 기록
        output[..16].copy_from_slice(iv);

        let ct_start = 16usize;
        let padded_len = (plaintext.len() / 16 + 1) * 16;
        let ct_end = ct_start + padded_len;

        let mut prev_block = *iv;
        let full_blocks = plaintext.len() / 16;

        // 완전한 블록 암호화
        for i in 0..full_blocks {
            let mut block = [0u8; 16];
            block.copy_from_slice(&plaintext[i * 16..(i + 1) * 16]);
            for j in 0..16 {
                block[j] ^= prev_block[j];
            }
            aes256_encrypt_block(&mut block, &ks);
            output[ct_start + i * 16..ct_start + (i + 1) * 16].copy_from_slice(&block);
            prev_block = block;
            for b in &mut block {
                unsafe { write_volatile(b, 0) };
            }
        }

        // 마지막 블록: 나머지 바이트 + PKCS7 패딩
        let rem = plaintext.len() - full_blocks * 16;
        let pad_byte = (padded_len - plaintext.len()) as u8;
        let mut last_block = [pad_byte; 16];
        last_block[..rem].copy_from_slice(&plaintext[full_blocks * 16..]);
        for j in 0..16 {
            last_block[j] ^= prev_block[j];
        }
        aes256_encrypt_block(&mut last_block, &ks);
        output[ct_start + full_blocks * 16..ct_end].copy_from_slice(&last_block);
        for b in &mut last_block {
            unsafe { write_volatile(b, 0) };
        }
        for b in &mut prev_block {
            unsafe { write_volatile(b, 0) };
        }

        // Encrypt-then-MAC: HMAC-SHA256(IV || 암호문)
        let mut hmac = HMACSHA256::new(mac_key.as_slice())
            .map_err(|_| AESError::InternalError)?;
        hmac.update(&output[..ct_end]);
        let mac = hmac.finalize().map_err(|_| AESError::InternalError)?;
        output[ct_end..ct_end + 32].copy_from_slice(mac.as_slice());

        Ok(ct_end + 32)
    }

    /// CBC-HMAC 복호화
    ///
    /// # Arguments
    /// - `enc_key` — 256비트(32 bytes) AES 복호화 키
    /// - `mac_key` — HMAC-SHA256 검증 키
    /// - `input` — `IV(16) || CT || HMAC(32)` 형식의 입력
    /// - `output` — 평문 출력 버퍼
    ///
    /// # Returns
    /// 복호화된 평문 바이트 수
    ///
    /// # Security Note
    /// MAC 검증에 실패하면 복호화를 수행하지 않습니다. 패딩 오라클 공격 방지.
    pub fn decrypt(
        enc_key: &SecureBuffer,
        mac_key: &SecureBuffer,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, AESError> {
        if enc_key.len() != 32 {
            return Err(AESError::InvalidKeyLength);
        }
        // 최소 크기: IV(16) + 블록 1개(16) + HMAC(32) = 64
        if input.len() < 64 || (input.len() - 48) % 16 != 0 {
            return Err(AESError::InvalidInputLength);
        }

        let mac_start = input.len() - 32;
        let received_mac = &input[mac_start..];
        let authenticated = &input[..mac_start];

        // MAC 검증 (먼저, Encrypt-then-MAC)
        let mut hmac = HMACSHA256::new(mac_key.as_slice())
            .map_err(|_| AESError::InternalError)?;
        hmac.update(authenticated);
        let expected_mac = hmac.finalize().map_err(|_| AESError::InternalError)?;

        // 상수-시간 MAC 비교
        if !ct_eq_32(expected_mac.as_slice(), received_mac) {
            return Err(AESError::AuthenticationFailed);
        }

        // MAC 검증 통과 후 복호화
        let iv: [u8; 16] = [
            input[0],  input[1],  input[2],  input[3],
            input[4],  input[5],  input[6],  input[7],
            input[8],  input[9],  input[10], input[11],
            input[12], input[13], input[14], input[15],
        ];
        let ciphertext = authenticated;
        let ct_blocks = &ciphertext[16..]; // IV 제외한 암호문 부분

        if output.len() < ct_blocks.len() {
            return Err(AESError::OutputBufferTooSmall);
        }

        let enc_key_arr: [u8; 32] = {
            let s = enc_key.as_slice();
            [
                s[0],  s[1],  s[2],  s[3],  s[4],  s[5],  s[6],  s[7],
                s[8],  s[9],  s[10], s[11], s[12], s[13], s[14], s[15],
                s[16], s[17], s[18], s[19], s[20], s[21], s[22], s[23],
                s[24], s[25], s[26], s[27], s[28], s[29], s[30], s[31],
            ]
        };
        let ks = KeySchedule::new(&enc_key_arr);

        let block_count = ct_blocks.len() / 16;
        let mut prev_block = iv;

        for i in 0..block_count {
            let mut block = [0u8; 16];
            block.copy_from_slice(&ct_blocks[i * 16..(i + 1) * 16]);
            let cipher_block = block;
            aes256_decrypt_block(&mut block, &ks);
            for j in 0..16 {
                block[j] ^= prev_block[j];
            }
            output[i * 16..(i + 1) * 16].copy_from_slice(&block);
            prev_block = cipher_block;
            for b in &mut block {
                unsafe { write_volatile(b, 0) };
            }
        }
        for b in &mut prev_block {
            unsafe { write_volatile(b, 0) };
        }

        let plaintext_len = pkcs7_unpad_len(&output[..ct_blocks.len()])?;
        Ok(plaintext_len)
    }
}
