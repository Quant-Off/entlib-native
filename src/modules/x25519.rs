/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

use crate::helper::{array_from_raw, random_array, slice_from_raw_mut};
use x25519_dalek::{PublicKey, StaticSecret};

// X25519 sizes
pub const X25519_SK_SIZE: usize = 32;
pub const X25519_PK_SIZE: usize = 32;
pub const X25519_SS_SIZE: usize = 32;

/// X25519 키 페어를 생성합니다.
///
/// # Arguments
/// * `sk_ptr` - Output pointer for secret key (32 bytes)
/// * `pk_ptr` - Output pointer for public key (32 bytes)
///
/// # Returns
/// * 0 on success
/// * -1 on invalid pointer
#[unsafe(no_mangle)]
pub extern "C" fn x25519_keygen(sk_ptr: *mut u8, pk_ptr: *mut u8) -> i32 {
    unsafe {
        let sk_bytes: [u8; X25519_SK_SIZE] = random_array();
        let secret = StaticSecret::from(sk_bytes);
        let public = PublicKey::from(&secret);

        let sk_slice = match slice_from_raw_mut(sk_ptr, X25519_SK_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let pk_slice = match slice_from_raw_mut(pk_ptr, X25519_PK_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        sk_slice.copy_from_slice(&sk_bytes);
        pk_slice.copy_from_slice(public.as_bytes());
        0
    }
}

/// 비밀 키를 사용하여 공개 키를 계산(생성)합니다.
///
/// # Arguments
/// * `pk_ptr` - Output pointer for public key (32 bytes)
/// * `sk_ptr` - Input pointer for secret key (32 bytes)
///
/// # Returns
/// * 0 on success
/// * -1 on invalid pointer
#[unsafe(no_mangle)]
pub extern "C" fn x25519_sk_to_pk(pk_ptr: *mut u8, sk_ptr: *const u8) -> i32 {
    unsafe {
        let sk_bytes: [u8; X25519_SK_SIZE] = match array_from_raw(sk_ptr) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let secret = StaticSecret::from(sk_bytes);
        let public = PublicKey::from(&secret);

        let pk_slice = match slice_from_raw_mut(pk_ptr, X25519_PK_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        pk_slice.copy_from_slice(public.as_bytes());
        0
    }
}

/// Perform X25519 Diffie-Hellman key exchange
///
/// Computes shared secret from my secret key and peer's public key.
///
/// # Arguments
/// * `ss_ptr` - Output pointer for shared secret (32 bytes)
/// * `sk_ptr` - Input pointer for my secret key (32 bytes)
/// * `pk_ptr` - Input pointer for peer's public key (32 bytes)
///
/// # Returns
/// * 0 on success
/// * -1 on invalid pointer
#[unsafe(no_mangle)]
pub extern "C" fn x25519_dh(
    ss_ptr: *mut u8,
    sk_ptr: *const u8,
    pk_ptr: *const u8,
) -> i32 {
    unsafe {
        let sk_bytes: [u8; X25519_SK_SIZE] = match array_from_raw(sk_ptr) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let pk_bytes: [u8; X25519_PK_SIZE] = match array_from_raw(pk_ptr) {
            Ok(p) => p,
            Err(_) => return -1,
        };

        let secret = StaticSecret::from(sk_bytes);
        let public = PublicKey::from(pk_bytes);

        let shared_secret = secret.diffie_hellman(&public);

        let ss_slice = match slice_from_raw_mut(ss_ptr, X25519_SS_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        ss_slice.copy_from_slice(shared_secret.as_bytes());
        0
    }
}
