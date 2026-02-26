//! ChaCha20-Poly1305 AEAD 및 저수준 모듈 FFI 인터페이스 (Java JNI / FFM API 연동용)
//!
//! # Security
//! - 모든 출력은 Opaque Pointer(*mut SecureBuffer) 형태로 반환 (Callee-allocated 패턴)
//! - Java 측에서 반드시 작업 완료 후 `free_secure_buffer`를 호출해야 함 (Zeroize + Dealloc 보장)
//! - decrypt 실패 시 null 포인터 반환 -> 명확한 AuthenticationFailedException 유도
//! - 입력 길이 검증 필수, heap allocation 최소화, constant-time 보장 유지

use core::ptr::null_mut;
use entlib_native_core_secure::secure_buffer::SecureBuffer;

use entlib_native_chacha20::chacha20::{chacha20_poly1305_decrypt, chacha20_poly1305_encrypt};
use entlib_native_chacha20::chacha20_state::process_chacha20;
use entlib_native_chacha20::poly1305::generate_poly1305;

/// ChaCha20 단일 처리 FFI (저수준 모듈 노출)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn process_chacha20_ffi(
    key_ptr: *const u8,
    key_len: usize,
    nonce_ptr: *const u8,
    nonce_len: usize,
    counter: u32,
    data_ptr: *const u8,
    data_len: usize,
) -> *mut SecureBuffer {
    if key_len != 32 || nonce_len != 12 {
        return null_mut();
    }

    let key = unsafe { core::slice::from_raw_parts(key_ptr, 32) };
    let key_arr: &[u8; 32] = key.try_into().expect("key length already checked");
    let nonce = unsafe { core::slice::from_raw_parts(nonce_ptr, 12) };
    let nonce_arr: &[u8; 12] = nonce.try_into().expect("nonce length already checked");
    let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len) };

    let result = process_chacha20(key_arr, nonce_arr, counter, data);

    // SecureBuffer를 Box로 감싸 힙으로 이동시킨 후, 원시 포인터로 변환하여 Java로 전달 (Ownership transfer)
    Box::into_raw(Box::new(result))
}

/// Poly1305 MAC 생성 FFI (저수준 모듈 노출)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn generate_poly1305_ffi(
    key_ptr: *const u8,
    key_len: usize,
    data_ptr: *const u8,
    data_len: usize,
) -> *mut SecureBuffer {
    if key_len != 32 {
        return null_mut();
    }

    let key = unsafe { core::slice::from_raw_parts(key_ptr, 32) };
    let key_arr: &[u8; 32] = key.try_into().expect("key length already checked");
    let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len) };

    let result = generate_poly1305(key_arr, data);

    Box::into_raw(Box::new(result))
}

/// RFC 8439 ChaCha20-Poly1305 AEAD 암호화 FFI
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chacha20_poly1305_encrypt_ffi(
    key_ptr: *const u8,
    key_len: usize,
    nonce_ptr: *const u8,
    nonce_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
) -> *mut SecureBuffer {
    if key_len != 32 || nonce_len != 12 {
        return null_mut();
    }

    let key = unsafe { core::slice::from_raw_parts(key_ptr, 32) };
    let key_arr: &[u8; 32] = key.try_into().expect("key length already checked");
    let nonce = unsafe { core::slice::from_raw_parts(nonce_ptr, 12) };
    let nonce_arr: &[u8; 12] = nonce.try_into().expect("nonce length already checked");
    let aad = unsafe { core::slice::from_raw_parts(aad_ptr, aad_len) };
    let plaintext = unsafe { core::slice::from_raw_parts(plaintext_ptr, plaintext_len) };

    let result = chacha20_poly1305_encrypt(key_arr, nonce_arr, aad, plaintext);

    Box::into_raw(Box::new(result))
}

/// RFC 8439 ChaCha20-Poly1305 AEAD 복호화 FFI
/// 실패 시 null 반환 -> Java에서 AuthenticationFailedException 발생
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chacha20_poly1305_decrypt_ffi(
    key_ptr: *const u8,
    key_len: usize,
    nonce_ptr: *const u8,
    nonce_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    ciphertext_with_tag_ptr: *const u8,
    ciphertext_with_tag_len: usize,
) -> *mut SecureBuffer {
    if key_len != 32 || nonce_len != 12 {
        return null_mut();
    }

    let key = unsafe { core::slice::from_raw_parts(key_ptr, 32) };
    let key_arr: &[u8; 32] = key.try_into().expect("key length already checked");
    let nonce = unsafe { core::slice::from_raw_parts(nonce_ptr, 12) };
    let nonce_arr: &[u8; 12] = nonce.try_into().expect("nonce length already checked");
    let aad = unsafe { core::slice::from_raw_parts(aad_ptr, aad_len) };
    let ct_with_tag =
        unsafe { core::slice::from_raw_parts(ciphertext_with_tag_ptr, ciphertext_with_tag_len) };

    if let Some(result) = chacha20_poly1305_decrypt(key_arr, nonce_arr, aad, ct_with_tag) {
        Box::into_raw(Box::new(result))
    } else {
        null_mut()
    }
}
