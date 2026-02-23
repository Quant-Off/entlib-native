//! 난수 생성기 FFI 브릿지 모듈
//!
//! `base_rng` (하드웨어 TRNG)와 `mixed` (ChaCha20 혼합 RNG)를 Java/Kotlin 네이티브 환경으로
//! 안전하게 노출합니다. ANU QRNG 네트워크 엔트로피도 전략 선택으로 사용 가능.
//!
//! # Security
//! - 모든 민감 상태는 `MixedRng::Drop` + `SecureBuffer::Drop`에 의해 강제 zeroize
//! - FFI 경계에서 철저한 null 체크 + 에러 코드 매핑
//! - Rust 2024 에디션 완벽 호환 (unsafe-op-in-unsafe-fn 해결)
//!
//! # Author
//! Q. T. Felix

use core::ptr;
use entlib_native_core_secure::secure_buffer::SecureBuffer;
use entlib_native_rng::base_rng::{RngError, generate_hardware_random_bytes, next_generate};
use entlib_native_rng::mixed::{EntropyStrategy, MixedRng};
use std::boxed::Box;

/// FFI 에러 코드 매핑 (모든 RngError variant + FFI 전용 코드 커버)
#[inline(always)]
fn map_rng_error(err: RngError) -> u8 {
    match err {
        RngError::UnsupportedHardware => 1,
        RngError::EntropyDepletion => 2,
        RngError::NetworkFailure => 4,
        RngError::ParseError => 5,
    }
}

// ================================================
// 하드웨어 진난수 생성기 (Hardware TRNG) FFI
// ================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_rng_hw_generate(
    len: usize,
    err_flag: *mut u8,
) -> *mut SecureBuffer {
    if !err_flag.is_null() {
        unsafe {
            *err_flag = 0;
        }
    }

    match generate_hardware_random_bytes(len) {
        Ok(buffer) => Box::into_raw(Box::new(buffer)),
        Err(e) => {
            if !err_flag.is_null() {
                unsafe {
                    *err_flag = map_rng_error(e);
                }
            }
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_rng_hw_next_generate(buf: *mut SecureBuffer) -> u8 {
    if buf.is_null() {
        return 3; // Invalid pointer
    }

    let buffer = unsafe { &mut *buf };
    match next_generate(buffer) {
        Ok(_) => 0,
        Err(e) => map_rng_error(e),
    }
}

// ================================================
// 혼합 난수 생성기 (Mixed RNG with ChaCha20) FFI
// ================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_rng_mixed_new_with_strategy(
    strategy: u8,
    err_flag: *mut u8,
) -> *mut MixedRng {
    if !err_flag.is_null() {
        unsafe {
            *err_flag = 0;
        }
    }

    let entropy_strategy = match strategy {
        0 => EntropyStrategy::LocalHardware,
        1 => EntropyStrategy::QuantumNetwork,
        _ => {
            if !err_flag.is_null() {
                unsafe {
                    *err_flag = 3;
                } // Invalid strategy
            }
            return ptr::null_mut();
        }
    };

    match MixedRng::new(entropy_strategy) {
        Ok(rng) => Box::into_raw(Box::new(rng)),
        Err(e) => {
            if !err_flag.is_null() {
                unsafe {
                    *err_flag = map_rng_error(e);
                }
            }
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_rng_mixed_new(err_flag: *mut u8) -> *mut MixedRng {
    unsafe { entlib_rng_mixed_new_with_strategy(0, err_flag) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_rng_mixed_generate(
    rng_ptr: *mut MixedRng,
    len: usize,
    err_flag: *mut u8,
) -> *mut SecureBuffer {
    if !err_flag.is_null() {
        unsafe {
            *err_flag = 0;
        }
    }

    if rng_ptr.is_null() {
        if !err_flag.is_null() {
            unsafe {
                *err_flag = 3;
            }
        }
        return ptr::null_mut();
    }

    let rng = unsafe { &mut *rng_ptr };
    match rng.generate(len) {
        Ok(buffer) => Box::into_raw(Box::new(buffer)),
        Err(e) => {
            if !err_flag.is_null() {
                unsafe {
                    *err_flag = map_rng_error(e);
                }
            }
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_rng_mixed_free(rng_ptr: *mut MixedRng) {
    if !rng_ptr.is_null() {
        let _ = unsafe { Box::from_raw(rng_ptr) }; // Drop → zeroize 보장
    }
}
