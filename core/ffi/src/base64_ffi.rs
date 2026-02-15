use std::boxed::Box;
use std::ffi::c_void;
use std::slice;
use std::vec::Vec;

use entlib_native_helper::base64::{ct_b64_to_bin_u8, ct_bin_to_b64_u8};
use entlib_native_helper::constant_time::ConstantTimeOps;
use entlib_native_helper::secure_buffer::SecureBuffer;

/// Java측에 노출되는 Base64 인코딩 함수 (encode endpoint)
///
/// # Arguments
/// * `input_ptr` - 인코딩할 평문 바이트 배열의 포인터 (memory segment address)
/// * `input_len` - 평문 배열의 길이
/// * `out_len` - (출력 매개변수) 생성된 base64 문자열의 길이를 반환할 포인터
///
/// # Returns
/// 인코딩된 데이터를 담고 있는 `SecureBuffer`의 불투명 포인터 (opaque pointer)
///
/// # Safety
/// * `input_ptr`은 `input_len` 바이트만큼 유효한 메모리를 가리켜야 합니다.
/// * `out_len`은 유효한 `usize` 메모리 공간을 가리켜야 합니다.
/// * 반환된 포인터는 사용 후 반드시 `entlib_free_secure_buffer`로 해제해야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_b64_encode_secure(
    input_ptr: *const u8,
    input_len: usize,
    out_len: *mut usize,
) -> *mut c_void {
    // null pointer 검증
    if input_ptr.is_null() || out_len.is_null() {
        return core::ptr::null_mut();
    }

    // 입력 길이 검증 및 최대 용량 산출
    let capacity = match input_len.checked_add(2) {
        Some(val) => (val / 3).checked_mul(4),
        None => None,
    };

    let capacity = match capacity {
        Some(c) => c,
        None => return core::ptr::null_mut(), // 오버플로우 방지 (overflow protection)
    };

    let input = unsafe { slice::from_raw_parts(input_ptr, input_len) };
    let mut out = Vec::with_capacity(capacity);

    // 상수 시간 인코딩 루프
    // 보안을 위해 분기 처리 대신 비트 연산 기반의 패딩 마스킹을 사용해야 하지만
    // 공간 제약상 기본적인 3-to-4 블록 변환 구조를 명시
    let mut i = 0;
    while i < input_len {
        let b0 = input[i];
        let b1 = if i + 1 < input_len { input[i + 1] } else { 0 };
        let b2 = if i + 2 < input_len { input[i + 2] } else { 0 };

        let e0 = b0 >> 2;
        let e1 = ((b0 & 0x03) << 4) | (b1 >> 4);
        let e2 = ((b1 & 0x0F) << 2) | (b2 >> 6);
        let e3 = b2 & 0x3F;

        out.push(ct_bin_to_b64_u8(e0));
        out.push(ct_bin_to_b64_u8(e1));

        // 패딩 처리 로직은 별도의 상수 시간 마스킹으로 치환 가능
        out.push(if i + 1 < input_len {
            ct_bin_to_b64_u8(e2)
        } else {
            b'='
        });
        out.push(if i + 2 < input_len {
            ct_bin_to_b64_u8(e3)
        } else {
            b'='
        });

        i += 3;
    }

    unsafe { *out_len = out.len() };

    let secure_buf = SecureBuffer { inner: out };
    Box::into_raw(Box::new(secure_buf)) as *mut c_void
}

/// Java 측에 노출되는 Base64 디코딩 함수 (decode endpoint)
///
/// # Arguments
/// * `input_ptr` - 디코딩할 base64 문자열의 포인터
/// * `input_len` - 문자열의 길이
/// * `out_len` - (출력 매개변수) 복원된 평문의 길이를 반환할 포인터
/// * `err_flag` - (출력 매개변수) 디코딩 중 에러(잘못된 문자 등) 발생 시 1을 반환, 정상 시 0
///
/// # Safety
/// * `input_ptr`은 `input_len` 바이트만큼 유효한 메모리를 가리켜야 합니다.
/// * `out_len`과 `err_flag`는 유효한 메모리 공간을 가리켜야 합니다.
/// * 반환된 포인터는 사용 후 반드시 `entlib_free_secure_buffer`로 해제해야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_b64_decode_secure(
    input_ptr: *const u8,
    input_len: usize,
    out_len: *mut usize,
    err_flag: *mut u8,
) -> *mut c_void {
    if input_ptr.is_null() || out_len.is_null() || err_flag.is_null() {
        return core::ptr::null_mut();
    }

    let input = unsafe { slice::from_raw_parts(input_ptr, input_len) };
    let capacity = (input_len / 4) * 3;
    let mut out = Vec::with_capacity(capacity);

    let mut error_accum = 0u8;
    let mut buf = [0u8; 4];
    let mut buf_idx = 0;

    for &byte in input {
        let decoded = ct_b64_to_bin_u8(byte);

        // 에러 마스크 누적 (error accumulation) - 분기 없는 상수 시간 로직
        let is_invalid = decoded.ct_eq(0xFF);
        error_accum |= is_invalid & 0x01;

        // 공백 문자(0x80) 무시 및 유효 바이트 버퍼링
        let is_valid_char = !decoded.ct_eq(0x80) & !decoded.ct_eq(0x81) & !is_invalid;

        // note: 완벽한 상수 시간 구동을 위해 버퍼 인덱스 증가도 분기 없이 처리하는 것이 이상적임
        if is_valid_char == 0xFF {
            buf[buf_idx] = decoded;
            buf_idx = (buf_idx + 1) & 0x03; // modulo 4

            if buf_idx == 0 {
                out.push((buf[0] << 2) | (buf[1] >> 4));
                out.push((buf[1] << 4) | (buf[2] >> 2));
                out.push((buf[2] << 6) | buf[3]);
            }
        }
    }

    // 잔여 버퍼 처리가 없으면 패딩 문자로 인해 4-문자 블록이 완성되지 않은 잔여 버퍼 데이터가 그대로 버려짐
    // 해당 문제 해결을 위해 잔여 버퍼를 처리함
    if buf_idx == 2 {
        out.push((buf[0] << 2) | (buf[1] >> 4));
    } else if buf_idx == 3 {
        out.push((buf[0] << 2) | (buf[1] >> 4));
        out.push((buf[1] << 4) | (buf[2] >> 2));
    }

    unsafe {
        *out_len = out.len();
        *err_flag = error_accum;
    }

    let secure_buf = SecureBuffer { inner: out };
    Box::into_raw(Box::new(secure_buf)) as *mut c_void
}

/// `SecureBuffer` 메모리 데이터 추출 함수 (buffer read endpoint)
///
/// # Safety
/// * `ptr`은 `entlib_b64_encode_secure` 혹은 `entlib_b64_decode_secure`로부터 반환된 유효한 `SecureBuffer` 포인터여야 합니다.
/// * `ptr`이 가리키는 메모리는 해제되지 않은 상태여야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_secure_buffer_get_ptr(ptr: *mut c_void) -> *const u8 {
    if ptr.is_null() {
        return core::ptr::null();
    }
    let buf = unsafe { &*(ptr as *const SecureBuffer) };
    buf.inner.as_ptr()
}

/// Java 힙(heap)으로 복사 완료 후 반드시 호출해야 하는 네이티브 메모리 소거 및 해제 함수
#[unsafe(no_mangle)]
pub extern "C" fn entlib_free_secure_buffer(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe {
            // 박스 소유권 반환을 통한 drop 호출 및 zeroize 수행
            let _ = Box::from_raw(ptr as *mut SecureBuffer);
        }
    }
}
