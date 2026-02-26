//! 난수 생성기 FFI 브릿지 모듈
//!
//! [entlib_native_rng::base_rng], [entlib_native_rng::mixed], [entlib_native_rng::base_rng::anu_qrng]
//! 모듈을 모두 Java로 안전하게 노출합니다.
//!
//! # security
//! - 모든 민감 상태는 `MixedRng::Drop` + `SecureBuffer::Drop`에 의해 강제 zeroize
//! - anu qrng는 네트워크 호출이므로 `NetworkFailure`/`ParseError` 처리 필수
//! - heap 메모리 누수를 방지하기 위한 버퍼 해제 함수 추가
//!
//! # Author
//! Q. T. Felix

use core::ptr;
use entlib_native_core_secure::secure_buffer::SecureBuffer;
use entlib_native_rng::anu_qrng::AnuQrngClient;
use entlib_native_rng::base_rng::{RngError, generate_hardware_random_bytes, next_generate};
use entlib_native_rng::mixed::{EntropyStrategy, MixedRng};
use std::boxed::Box;

/// ffi 에러 코드 매핑
#[inline(always)]
fn map_rng_error(err: RngError) -> u8 {
    match err {
        RngError::UnsupportedHardware => 1,
        RngError::EntropyDepletion => 2,
        RngError::InvalidPointer => 3,
        RngError::NetworkFailure(msg) => {
            eprintln!("[ENTLIB] RNG NetworkFailure: {}", msg); // 일단 네트워크 문제 부터 파악
            4
        }
        RngError::ParseError => 5,
        RngError::InvalidParameter => 6,
    }
}

//
// 하드웨어 진난수 생성기 (hardware trng) ffi
//

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
        return map_rng_error(RngError::InvalidPointer);
    }

    let buffer = unsafe { &mut *buf };
    match next_generate(buffer) {
        Ok(_) => 0,
        Err(e) => map_rng_error(e),
    }
}

//
// anu 양자 난수 생성기 (quantum rng) ffi
//

#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_rng_anu_generate(
    len: usize,
    err_flag: *mut u8,
) -> *mut SecureBuffer {
    if !err_flag.is_null() {
        unsafe {
            *err_flag = 0;
        }
    }

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            if !err_flag.is_null() {
                unsafe {
                    *err_flag = map_rng_error(RngError::NetworkFailure(format!(
                        "tokio 런타임 빌드 실패: {}",
                        e
                    )));
                }
            }
            return ptr::null_mut();
        }
    };

    match rt.block_on(AnuQrngClient::fetch_secure_bytes(len)) {
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

//
// 혼합 난수 생성기 (mixed rng with chacha20) ffi
//

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
                    *err_flag = map_rng_error(RngError::InvalidParameter);
                }
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
                *err_flag = map_rng_error(RngError::InvalidPointer);
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
        // drop -> zeroize 보장
        let _ = unsafe { Box::from_raw(rng_ptr) };
    }
}
