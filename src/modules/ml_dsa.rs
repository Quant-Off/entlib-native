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

use crate::helper::{random_array, slice_from_raw_mut, bytes_from_raw, array_from_raw};
use libcrux_ml_dsa::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use libcrux_ml_dsa::ml_dsa_44::{MLDSA44SigningKey, MLDSA44VerificationKey, MLDSA44Signature};
use libcrux_ml_dsa::ml_dsa_65::{MLDSA65SigningKey, MLDSA65VerificationKey, MLDSA65Signature};
use libcrux_ml_dsa::ml_dsa_87::{MLDSA87SigningKey, MLDSA87VerificationKey, MLDSA87Signature};

// ML-DSA-44 sizes
pub const ML_DSA_44_SK_SIZE: usize = 2560;
pub const ML_DSA_44_PK_SIZE: usize = 1312;
pub const ML_DSA_44_SIG_SIZE: usize = 2420;

// ML-DSA-65 sizes
pub const ML_DSA_65_SK_SIZE: usize = 4032;
pub const ML_DSA_65_PK_SIZE: usize = 1952;
pub const ML_DSA_65_SIG_SIZE: usize = 3309;

// ML-DSA-87 sizes
pub const ML_DSA_87_SK_SIZE: usize = 4896;
pub const ML_DSA_87_PK_SIZE: usize = 2592;
pub const ML_DSA_87_SIG_SIZE: usize = 4627;

//
// ML-DSA-44 - start
//
#[unsafe(no_mangle)]
pub extern "C" fn ml_dsa_44_keygen(sk_ptr: *mut u8, pk_ptr: *mut u8) -> i32 {
    unsafe {
        let randomness = random_array();
        let key_pair = ml_dsa_44::generate_key_pair(randomness);

        let sk_slice = match slice_from_raw_mut(sk_ptr, ML_DSA_44_SK_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let pk_slice = match slice_from_raw_mut(pk_ptr, ML_DSA_44_PK_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        sk_slice.copy_from_slice(key_pair.signing_key.as_ref());
        pk_slice.copy_from_slice(key_pair.verification_key.as_ref());
        0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ml_dsa_44_sign(
    sig_ptr: *mut u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_ptr: *const u8,
) -> i32 {
    unsafe {
        let msg = match bytes_from_raw(msg_ptr, msg_len) {
            Ok(m) => m,
            Err(_) => return -1,
        };

        let sk_bytes: [u8; ML_DSA_44_SK_SIZE] = match array_from_raw(sk_ptr) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let signing_key = MLDSA44SigningKey::new(sk_bytes);
        let randomness = random_array();

        match ml_dsa_44::sign(&signing_key, &msg, b"", randomness) {
            Ok(signature) => {
                let sig_slice = match slice_from_raw_mut(sig_ptr, ML_DSA_44_SIG_SIZE) {
                    Ok(s) => s,
                    Err(_) => return -1,
                };
                sig_slice.copy_from_slice(signature.as_ref());
                0
            }
            Err(_) => -2,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ml_dsa_44_verify(
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
    pk_ptr: *const u8,
) -> i32 {
    unsafe {
        let msg = match bytes_from_raw(msg_ptr, msg_len) {
            Ok(m) => m,
            Err(_) => return -1,
        };

        let pk_bytes: [u8; ML_DSA_44_PK_SIZE] = match array_from_raw(pk_ptr) {
            Ok(p) => p,
            Err(_) => return -1,
        };

        let sig_bytes: [u8; ML_DSA_44_SIG_SIZE] = match array_from_raw(sig_ptr) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let verification_key = MLDSA44VerificationKey::new(pk_bytes);
        let signature = MLDSA44Signature::new(sig_bytes);

        match ml_dsa_44::verify(&verification_key, &msg, b"", &signature) {
            Ok(_) => 0,
            Err(_) => -2,
        }
    }
}
//
// ML-DSA-44 - end
//

//
// ML-DSA-65 - start
//
#[unsafe(no_mangle)]
pub extern "C" fn ml_dsa_65_keygen(sk_ptr: *mut u8, pk_ptr: *mut u8) -> i32 {
    unsafe {
        let randomness = random_array();
        let key_pair = ml_dsa_65::generate_key_pair(randomness);

        let sk_slice = match slice_from_raw_mut(sk_ptr, ML_DSA_65_SK_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let pk_slice = match slice_from_raw_mut(pk_ptr, ML_DSA_65_PK_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        sk_slice.copy_from_slice(key_pair.signing_key.as_ref());
        pk_slice.copy_from_slice(key_pair.verification_key.as_ref());
        0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ml_dsa_65_sign(
    sig_ptr: *mut u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_ptr: *const u8,
) -> i32 {
    unsafe {
        let msg = match bytes_from_raw(msg_ptr, msg_len) {
            Ok(m) => m,
            Err(_) => return -1,
        };

        let sk_bytes: [u8; ML_DSA_65_SK_SIZE] = match array_from_raw(sk_ptr) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let signing_key = MLDSA65SigningKey::new(sk_bytes);
        let randomness = random_array();

        match ml_dsa_65::sign(&signing_key, &msg, b"", randomness) {
            Ok(signature) => {
                let sig_slice = match slice_from_raw_mut(sig_ptr, ML_DSA_65_SIG_SIZE) {
                    Ok(s) => s,
                    Err(_) => return -1,
                };
                sig_slice.copy_from_slice(signature.as_ref());
                0
            }
            Err(_) => -2,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ml_dsa_65_verify(
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
    pk_ptr: *const u8,
) -> i32 {
    unsafe {
        let msg = match bytes_from_raw(msg_ptr, msg_len) {
            Ok(m) => m,
            Err(_) => return -1,
        };

        let pk_bytes: [u8; ML_DSA_65_PK_SIZE] = match array_from_raw(pk_ptr) {
            Ok(p) => p,
            Err(_) => return -1,
        };

        let sig_bytes: [u8; ML_DSA_65_SIG_SIZE] = match array_from_raw(sig_ptr) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let verification_key = MLDSA65VerificationKey::new(pk_bytes);
        let signature = MLDSA65Signature::new(sig_bytes);

        match ml_dsa_65::verify(&verification_key, &msg, b"", &signature) {
            Ok(_) => 0,
            Err(_) => -2,
        }
    }
}
//
// ML-DSA-65 - end
//

//
// ML-DSA-87 - start
//
#[unsafe(no_mangle)]
pub extern "C" fn ml_dsa_87_keygen(sk_ptr: *mut u8, pk_ptr: *mut u8) -> i32 {
    unsafe {
        let randomness = random_array();
        let key_pair = ml_dsa_87::generate_key_pair(randomness);

        let sk_slice = match slice_from_raw_mut(sk_ptr, ML_DSA_87_SK_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let pk_slice = match slice_from_raw_mut(pk_ptr, ML_DSA_87_PK_SIZE) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        sk_slice.copy_from_slice(key_pair.signing_key.as_ref());
        pk_slice.copy_from_slice(key_pair.verification_key.as_ref());
        0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ml_dsa_87_sign(
    sig_ptr: *mut u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_ptr: *const u8,
) -> i32 {
    unsafe {
        let msg = match bytes_from_raw(msg_ptr, msg_len) {
            Ok(m) => m,
            Err(_) => return -1,
        };

        let sk_bytes: [u8; ML_DSA_87_SK_SIZE] = match array_from_raw(sk_ptr) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let signing_key = MLDSA87SigningKey::new(sk_bytes);
        let randomness = random_array();

        match ml_dsa_87::sign(&signing_key, &msg, b"", randomness) {
            Ok(signature) => {
                let sig_slice = match slice_from_raw_mut(sig_ptr, ML_DSA_87_SIG_SIZE) {
                    Ok(s) => s,
                    Err(_) => return -1,
                };
                sig_slice.copy_from_slice(signature.as_ref());
                0
            }
            Err(_) => -2,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ml_dsa_87_verify(
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
    pk_ptr: *const u8,
) -> i32 {
    unsafe {
        let msg = match bytes_from_raw(msg_ptr, msg_len) {
            Ok(m) => m,
            Err(_) => return -1,
        };

        let pk_bytes: [u8; ML_DSA_87_PK_SIZE] = match array_from_raw(pk_ptr) {
            Ok(p) => p,
            Err(_) => return -1,
        };

        let sig_bytes: [u8; ML_DSA_87_SIG_SIZE] = match array_from_raw(sig_ptr) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let verification_key = MLDSA87VerificationKey::new(pk_bytes);
        let signature = MLDSA87Signature::new(sig_bytes);

        match ml_dsa_87::verify(&verification_key, &msg, b"", &signature) {
            Ok(_) => 0,
            Err(_) => -2,
        }
    }
}
//
// ML-DSA-87 - end
//