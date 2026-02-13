/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

use crate::helper::{array_from_raw, random_array, slice_from_raw_mut};
use libcrux_ml_kem::mlkem512::{MlKem512Ciphertext, MlKem512PrivateKey, MlKem512PublicKey};
use libcrux_ml_kem::mlkem768::{MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use libcrux_ml_kem::mlkem1024::{MlKem1024Ciphertext, MlKem1024PrivateKey, MlKem1024PublicKey};
use libcrux_ml_kem::{mlkem512, mlkem768, mlkem1024};

// ML-KEM-512 sizes
pub const ML_KEM_512_DK_SIZE: usize = 1632;
pub const ML_KEM_512_EK_SIZE: usize = 800;
pub const ML_KEM_512_CT_SIZE: usize = 768;
pub const ML_KEM_512_SS_SIZE: usize = 32;

// ML-KEM-768 sizes
pub const ML_KEM_768_DK_SIZE: usize = 2400;
pub const ML_KEM_768_EK_SIZE: usize = 1184;
pub const ML_KEM_768_CT_SIZE: usize = 1088;
pub const ML_KEM_768_SS_SIZE: usize = 32;

// ML-KEM-1024 sizes
pub const ML_KEM_1024_DK_SIZE: usize = 3168;
pub const ML_KEM_1024_EK_SIZE: usize = 1568;
pub const ML_KEM_1024_CT_SIZE: usize = 1568;
pub const ML_KEM_1024_SS_SIZE: usize = 32;

//
// ML-KEM-512 - start
//

/// # Safety
/// `sk_ptr`은 최소 `ML_KEM_512_DK_SIZE`, `pk_ptr`은 최소 `ML_KEM_512_EK_SIZE` 바이트의 유효한 메모리를 가리켜야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_512_keygen(sk_ptr: *mut u8, pk_ptr: *mut u8) -> i32 {
    unsafe {
        let randomness = random_array();
        let key_pair = mlkem512::generate_key_pair(randomness);

        let sk_slice = match slice_from_raw_mut(sk_ptr, ML_KEM_512_DK_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let pk_slice = match slice_from_raw_mut(pk_ptr, ML_KEM_512_EK_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        sk_slice.copy_from_slice(key_pair.sk().as_ref());
        pk_slice.copy_from_slice(key_pair.pk().as_ref());
        0
    }
}

/// # Safety
/// `ct_ptr`은 최소 `ML_KEM_512_CT_SIZE`, `ss_ptr`은 `ML_KEM_512_SS_SIZE`, `pk_ptr`은 `ML_KEM_512_EK_SIZE` 바이트의 유효한 메모리를 가리켜야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_512_encapsulate(
    ct_ptr: *mut u8,
    ss_ptr: *mut u8,
    pk_ptr: *const u8,
) -> i32 {
    unsafe {
        let pk_bytes: [u8; ML_KEM_512_EK_SIZE] = match array_from_raw(pk_ptr) {
            Ok(p) => p,
            Err(_) => return -1,
        };

        let public_key = MlKem512PublicKey::from(pk_bytes);
        let randomness = random_array();

        let (ciphertext, shared_secret) = mlkem512::encapsulate(&public_key, randomness);

        let ct_slice = match slice_from_raw_mut(ct_ptr, ML_KEM_512_CT_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let ss_slice = match slice_from_raw_mut(ss_ptr, ML_KEM_512_SS_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        ct_slice.copy_from_slice(ciphertext.as_ref());
        ss_slice.copy_from_slice(shared_secret.as_ref());
        0
    }
}

/// # Safety
/// `ss_ptr`은 최소 `ML_KEM_512_SS_SIZE`, `ct_ptr`은 `ML_KEM_512_CT_SIZE`, `sk_ptr`은 `ML_KEM_512_DK_SIZE` 바이트의 유효한 메모리를 가리켜야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_512_decapsulate(
    ss_ptr: *mut u8,
    ct_ptr: *const u8,
    sk_ptr: *const u8,
) -> i32 {
    unsafe {
        let ct_bytes: [u8; ML_KEM_512_CT_SIZE] = match array_from_raw(ct_ptr) {
            Ok(c) => c,
            Err(_) => return -1,
        };

        let sk_bytes: [u8; ML_KEM_512_DK_SIZE] = match array_from_raw(sk_ptr) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let ciphertext = MlKem512Ciphertext::from(ct_bytes);
        let private_key = MlKem512PrivateKey::from(sk_bytes);

        let shared_secret = mlkem512::decapsulate(&private_key, &ciphertext);

        let ss_slice = match slice_from_raw_mut(ss_ptr, ML_KEM_512_SS_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        ss_slice.copy_from_slice(shared_secret.as_ref());
        0
    }
}
//
// ML-KEM-512 - end
//

//
// ML-KEM-768 - start
//
/// # Safety
/// `sk_ptr`은 최소 `ML_KEM_768_DK_SIZE`, `pk_ptr`은 최소 `ML_KEM_768_EK_SIZE` 바이트의 유효한 메모리를 가리켜야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_768_keygen(sk_ptr: *mut u8, pk_ptr: *mut u8) -> i32 {
    unsafe {
        let randomness = random_array();
        let key_pair = mlkem768::generate_key_pair(randomness);

        let sk_slice = match slice_from_raw_mut(sk_ptr, ML_KEM_768_DK_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let pk_slice = match slice_from_raw_mut(pk_ptr, ML_KEM_768_EK_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        sk_slice.copy_from_slice(key_pair.sk().as_ref());
        pk_slice.copy_from_slice(key_pair.pk().as_ref());
        0
    }
}

/// # Safety
/// `ct_ptr`은 최소 `ML_KEM_768_CT_SIZE`, `ss_ptr`은 `ML_KEM_768_SS_SIZE`, `pk_ptr`은 `ML_KEM_768_EK_SIZE` 바이트의 유효한 메모리를 가리켜야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_768_encapsulate(
    ct_ptr: *mut u8,
    ss_ptr: *mut u8,
    pk_ptr: *const u8,
) -> i32 {
    unsafe {
        let pk_bytes: [u8; ML_KEM_768_EK_SIZE] = match array_from_raw(pk_ptr) {
            Ok(p) => p,
            Err(_) => return -1,
        };

        let public_key = MlKem768PublicKey::from(pk_bytes);
        let randomness = random_array();

        let (ciphertext, shared_secret) = mlkem768::encapsulate(&public_key, randomness);

        let ct_slice = match slice_from_raw_mut(ct_ptr, ML_KEM_768_CT_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let ss_slice = match slice_from_raw_mut(ss_ptr, ML_KEM_768_SS_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        ct_slice.copy_from_slice(ciphertext.as_ref());
        ss_slice.copy_from_slice(shared_secret.as_ref());
        0
    }
}

/// # Safety
/// `ss_ptr`은 최소 `ML_KEM_768_SS_SIZE`, `ct_ptr`은 `ML_KEM_768_CT_SIZE`, `sk_ptr`은 `ML_KEM_768_DK_SIZE` 바이트의 유효한 메모리를 가리켜야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_768_decapsulate(
    ss_ptr: *mut u8,
    ct_ptr: *const u8,
    sk_ptr: *const u8,
) -> i32 {
    unsafe {
        let ct_bytes: [u8; ML_KEM_768_CT_SIZE] = match array_from_raw(ct_ptr) {
            Ok(c) => c,
            Err(_) => return -1,
        };

        let sk_bytes: [u8; ML_KEM_768_DK_SIZE] = match array_from_raw(sk_ptr) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let ciphertext = MlKem768Ciphertext::from(ct_bytes);
        let private_key = MlKem768PrivateKey::from(sk_bytes);

        let shared_secret = mlkem768::decapsulate(&private_key, &ciphertext);

        let ss_slice = match slice_from_raw_mut(ss_ptr, ML_KEM_768_SS_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        ss_slice.copy_from_slice(shared_secret.as_ref());
        0
    }
}
//
// ML-KEM-768 - end
//

//
// ML-KEM-1024 - start
//
/// # Safety
/// `sk_ptr`은 최소 `ML_KEM_1024_DK_SIZE`, `pk_ptr`은 최소 `ML_KEM_1024_EK_SIZE` 바이트의 유효한 메모리를 가리켜야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_1024_keygen(sk_ptr: *mut u8, pk_ptr: *mut u8) -> i32 {
    unsafe {
        let randomness = random_array();
        let key_pair = mlkem1024::generate_key_pair(randomness);

        let sk_slice = match slice_from_raw_mut(sk_ptr, ML_KEM_1024_DK_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let pk_slice = match slice_from_raw_mut(pk_ptr, ML_KEM_1024_EK_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        sk_slice.copy_from_slice(key_pair.sk().as_ref());
        pk_slice.copy_from_slice(key_pair.pk().as_ref());
        0
    }
}

/// # Safety
/// `ct_ptr`은 최소 `ML_KEM_1024_CT_SIZE`, `ss_ptr`은 `ML_KEM_1024_SS_SIZE`, `pk_ptr`은 `ML_KEM_1024_EK_SIZE` 바이트의 유효한 메모리를 가리켜야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_1024_encapsulate(
    ct_ptr: *mut u8,
    ss_ptr: *mut u8,
    pk_ptr: *const u8,
) -> i32 {
    unsafe {
        let pk_bytes: [u8; ML_KEM_1024_EK_SIZE] = match array_from_raw(pk_ptr) {
            Ok(p) => p,
            Err(_) => return -1,
        };

        let public_key = MlKem1024PublicKey::from(pk_bytes);
        let randomness = random_array();

        let (ciphertext, shared_secret) = mlkem1024::encapsulate(&public_key, randomness);

        let ct_slice = match slice_from_raw_mut(ct_ptr, ML_KEM_1024_CT_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let ss_slice = match slice_from_raw_mut(ss_ptr, ML_KEM_1024_SS_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        ct_slice.copy_from_slice(ciphertext.as_ref());
        ss_slice.copy_from_slice(shared_secret.as_ref());
        0
    }
}

/// # Safety
/// `ss_ptr`은 최소 `ML_KEM_1024_SS_SIZE`, `ct_ptr`은 `ML_KEM_1024_CT_SIZE`, `sk_ptr`은 `ML_KEM_1024_DK_SIZE` 바이트의 유효한 메모리를 가리켜야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_1024_decapsulate(
    ss_ptr: *mut u8,
    ct_ptr: *const u8,
    sk_ptr: *const u8,
) -> i32 {
    unsafe {
        let ct_bytes: [u8; ML_KEM_1024_CT_SIZE] = match array_from_raw(ct_ptr) {
            Ok(c) => c,
            Err(_) => return -1,
        };

        let sk_bytes: [u8; ML_KEM_1024_DK_SIZE] = match array_from_raw(sk_ptr) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let ciphertext = MlKem1024Ciphertext::from(ct_bytes);
        let private_key = MlKem1024PrivateKey::from(sk_bytes);

        let shared_secret = mlkem1024::decapsulate(&private_key, &ciphertext);

        let ss_slice = match slice_from_raw_mut(ss_ptr, ML_KEM_1024_SS_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        ss_slice.copy_from_slice(shared_secret.as_ref());
        0
    }
}
//
// ML-KEM-1024 - end
//
