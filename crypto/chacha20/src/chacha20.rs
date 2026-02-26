//! CHaCha20 (poly1305) 암호화 모듈입니다.
//!
//! # Authors
//! Q. T. Felix

use crate::chacha20_state::process_chacha20;
use crate::poly1305::generate_poly1305;
use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};
use entlib_native_constant_time::constant_time::ConstantTimeOps;
use entlib_native_core_secure::secure_buffer::SecureBuffer;

const MAX_MAC_BUFFER_LEN: usize = 2048; // todo: 프로토콜 최대 패킷(MTU) 사양에 맞게 조정, def2048

#[inline(always)]
fn append_padded(buffer: &mut [u8], offset: &mut usize, data: &[u8]) {
    let len = data.len();
    buffer[*offset..*offset + len].copy_from_slice(data);
    *offset += len;

    let rem = *offset % 16;
    if rem != 0 {
        *offset += 16 - rem;
    }
}

/// RFC 8439 ChaCha20-Poly1305 AEAD 암호화 함수입니다.
///
/// # Security
/// - mac_data Vec 재할당 완전 차단 (정확한 최대 크기 사전 capacity)
/// - 모든 민감 데이터 사용 즉시 zeroize
///
/// # Return
/// `ciphertext || tag` 형태의 `SecureBuffer`
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> SecureBuffer {
    // 1. Poly1305 One-Time Key (counter = 0)
    let otk_secure = process_chacha20(key, nonce, 0, &[0u8; 32]);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&otk_secure.inner[0..32]);

    // 2. Ciphertext (counter = 1)
    let ct_secure = process_chacha20(key, nonce, 1, plaintext);

    // 3. Poly1305 MAC 입력 구성 (고정 크기 스택 배열 사용)
    let max_mac_len = aad.len() + ct_secure.inner.len() + 48;
    assert!(
        max_mac_len <= MAX_MAC_BUFFER_LEN,
        "MAC data exceeds max buffer length"
    );

    let mut mac_data = [0u8; MAX_MAC_BUFFER_LEN];
    let mut offset = 0;

    append_padded(&mut mac_data, &mut offset, aad);
    append_padded(&mut mac_data, &mut offset, &ct_secure.inner);

    mac_data[offset..offset + 8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    offset += 8;
    mac_data[offset..offset + 8].copy_from_slice(&(ct_secure.inner.len() as u64).to_le_bytes());
    offset += 8;

    // 4. Tag 생성 (전체 버퍼가 아닌 실제 데이터 길이만큼만 전달)
    let tag_secure = generate_poly1305(&otk, &mac_data[..offset]);

    // 5. 최종 결과 = CT + Tag
    let ct_len = ct_secure.inner.len();
    let mut result = SecureBuffer {
        inner: vec![0u8; ct_len + 16],
    };
    result.inner[0..ct_len].copy_from_slice(&ct_secure.inner);
    result.inner[ct_len..].copy_from_slice(&tag_secure.inner);

    // 6. 모든 민감 데이터 즉시 zeroize
    drop(otk_secure);
    drop(ct_secure);
    drop(tag_secure);

    for b in mac_data.iter_mut() {
        unsafe {
            write_volatile(b, 0);
        }
    }
    for b in otk.iter_mut() {
        unsafe {
            write_volatile(b, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);

    result
}

/// RFC 8439 ChaCha20-Poly1305 AEAD 복호화 함수입니다.
///
/// # Security
/// - Verify-then-Decrypt 패턴 완벽 준수 (MAC 검증 -> 성공시에만 복호화)
/// - mac_data Vec 재할당 완전 차단
/// - 검증 실패 시 `None` 반환 -> 0-byte 평문 충돌 방지 및 명확한 에러 핸들링 보장
pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Option<SecureBuffer> {
    // 0. 기본 길이 검증 (공개 정보)
    if ciphertext_with_tag.len() < 16 {
        return None;
    }

    let ct_len = ciphertext_with_tag.len() - 16;
    let ct = &ciphertext_with_tag[0..ct_len];
    let received_tag = &ciphertext_with_tag[ct_len..];

    // 1. Poly1305 One-Time Key 생성
    let otk_secure = process_chacha20(key, nonce, 0, &[0u8; 32]);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&otk_secure.inner[0..32]);

    // 2. MAC 입력 데이터 구성 (반드시 고정 크기 스택 배열 사용)
    let max_mac_len = aad.len() + ct.len() + 48;
    if max_mac_len > MAX_MAC_BUFFER_LEN {
        return None; // 스펙 초과 시 즉시 실패
    }

    let mut mac_data = [0u8; MAX_MAC_BUFFER_LEN];
    let mut offset = 0;

    append_padded(&mut mac_data, &mut offset, aad);
    append_padded(&mut mac_data, &mut offset, ct);

    mac_data[offset..offset + 8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    offset += 8;
    mac_data[offset..offset + 8].copy_from_slice(&(ct.len() as u64).to_le_bytes());
    offset += 8;

    // 3. Expected Tag 계산
    let expected_tag_secure = generate_poly1305(&otk, &mac_data[..offset]);

    // 4. 상수-시간 tag 검증
    let mut xor_diff = 0u8;
    for i in 0..16 {
        xor_diff |= expected_tag_secure.inner[i] ^ received_tag[i];
    }
    let mask = xor_diff.ct_is_zero(); // valid -> 0xFF, invalid -> 0x00

    // 5. 조건 분기 없는 완전한 항상 복호화 수행 및 ct_select 선택
    let pt_secure = process_chacha20(key, nonce, 1, ct);
    let mut result_buf = SecureBuffer {
        inner: vec![0u8; ct_len],
    };

    // 마스크에 따라 원본 복호화 데이터(0xFF) 또는 0(0x00)을 상수-시간으로 선택
    for i in 0..ct_len {
        result_buf.inner[i] = pt_secure.inner[i].ct_select(0, mask);
    }
    drop(pt_secure);

    // 6. 민감 데이터 즉시 소거 (스택 배열은 사용된 길이까지만 소거)
    drop(otk_secure);
    drop(expected_tag_secure);

    for byte in mac_data.iter_mut().take(offset) {
        unsafe {
            write_volatile(byte, 0);
        }
    }
    for b in otk.iter_mut() {
        unsafe {
            write_volatile(b, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);

    // 7. 결과 반환
    // Q. T. Felix NOTE: 여기서 논리적 수행을 위한 분기를 사용하는데 암호화된 값 반환에 대한 조건문이라서
    // 크게 상관없을거라 판단했고 일단 놔두겠지만, 추 후 상수-시간 연산 도입 고려해볼 만 함
    if mask == 0xFF { Some(result_buf) } else { None }
}
