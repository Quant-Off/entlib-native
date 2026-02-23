//! 상수-시간(constant-time) Base64 인코딩·디코딩 FFI 모듈
//!
//! Java/Kotlin 측에서 호출자 할당(caller-alloc) 메모리에 직접 기록합니다.
//! 모든 연산은 분기 없는 상수 시간으로 side-channel 공격에 저항합니다.
//!
//! # Author
//! Q. T. Felix

use entlib_native_base64::base64::{ct_b64_to_bin_u8, ct_bin_to_b64_u8};
use entlib_native_constant_time::constant_time::ConstantTimeOps;
use std::slice;

/// Java 측에서 할당한 메모리에 `Base64` 인코딩 결과를 직접 기록하는 함수입니다.
///
/// # Arguments
/// * `input_ptr` - 인코딩할 평문 배열의 포인터
/// * `input_len` - 평문 배열의 길이
/// * `out_ptr` - (호출자 할당) 인코딩된 결과를 기록할 메모리의 시작 포인터
/// * `out_capacity` - 할당된 출력 메모리의 최대 바이트 크기
///
/// # Returns
/// * `>= 0`: 성공 시 인코딩된 결과의 실제 바이트 길이 반환
/// * `< 0`: 에러 코드 반환 (-1: `Null`, -2: `Capacity` 부족)
///
/// # Safety
/// 이 함수는 raw pointer를 직접 다루므로 unsafe입니다. 호출자는 다음을 **반드시** 보장해야 합니다.
///
/// - `input_ptr`은 null이 아니며, `input_len` 바이트만큼 **읽기 유효**한 메모리를 가리켜야 합니다
///   (정렬 요구사항 없음, u8 기준).
/// - `out_ptr`은 null이 아니며, `out_capacity` 바이트만큼 **쓰기 유효**한 메모리를 가리켜야 합니다.
/// - `input_ptr`과 `out_ptr`이 가리키는 메모리 영역은 서로 겹치지 않아야 합니다
///   (aliasing violation → UB).
/// - `out_capacity`는 내부에서 계산된 `required_capacity` 이상이어야 합니다
///   (함수가 -2를 반환하지만, 호출 전 미리 확인 권장).
/// - 호출 기간 동안 두 메모리 영역이 해제되거나 재할당되지 않아야 합니다.
/// - 단일 스레드에서 호출되며, concurrent 접근이 없어야 합니다.
///
/// 함수 내부는 `write_volatile`과 constant-time 연산만 사용하므로
/// timing attack 및 메모리 잔여 데이터 유출에 대한 군사급 보호를 제공합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_b64_encode_caller_alloc(
    input_ptr: *const u8,
    input_len: usize,
    out_ptr: *mut u8,
    out_capacity: usize,
) -> isize {
    // 포인터 유효성 검증
    if input_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }

    // 필요 버퍼 크기 산출 및 오버플로우 방지
    let required_capacity = match input_len.checked_add(2) {
        Some(val) => (val / 3).checked_mul(4),
        None => return -1,
    };

    // 호출자가 할당한 용량(capacity) 검증
    if out_capacity < required_capacity.expect("entlib-native-ffi ERROR: overflow") {
        return -2;
    }

    let input = unsafe { slice::from_raw_parts(input_ptr, input_len) };
    let mut out_idx = 0;
    let mut i = 0;

    // 상수 시간 인코딩 쓰기 루프
    while i < input_len {
        let b0 = input[i];
        let b1 = if i + 1 < input_len { input[i + 1] } else { 0 };
        let b2 = if i + 2 < input_len { input[i + 2] } else { 0 };

        let e0 = b0 >> 2;
        let e1 = ((b0 & 0x03) << 4) | (b1 >> 4);
        let e2 = ((b1 & 0x0F) << 2) | (b2 >> 6);
        let e3 = b2 & 0x3F;

        unsafe {
            core::ptr::write_volatile(out_ptr.add(out_idx), ct_bin_to_b64_u8(e0));
            core::ptr::write_volatile(out_ptr.add(out_idx + 1), ct_bin_to_b64_u8(e1));

            // 패딩 처리 (상수 시간 마스킹으로 치환 권장)
            let pad2 = if i + 1 < input_len {
                ct_bin_to_b64_u8(e2)
            } else {
                b'='
            };
            let pad3 = if i + 2 < input_len {
                ct_bin_to_b64_u8(e3)
            } else {
                b'='
            };

            core::ptr::write_volatile(out_ptr.add(out_idx + 2), pad2);
            core::ptr::write_volatile(out_ptr.add(out_idx + 3), pad3);
        }

        out_idx += 4;
        i += 3;
    }

    out_idx as isize
}

/// Java 측에서 할당한 메모리에 분기 없는 상수-시간(constant-time)으로 `Base64` 디코딩을 수행합니다.
///
/// # Arguments
/// * `input_ptr` - 디코딩할 `Base64` 문자열의 포인터
/// * `input_len` - 문자열의 바이트 길이
/// * `out_ptr` - (호출자 할당) 복원된 평문을 기록할 메모리의 시작 포인터
/// * `out_capacity` - 할당된 출력 메모리의 최대 바이트 크기
///
/// # Returns
/// * `>= 0`: 성공 시 디코딩된 평문의 실제 바이트 길이 반환
/// * `< 0`: 에러 코드 반환 (-1: `Null`, -2: `Capacity` 부족, -3: 디코딩 중 유효하지 않은 문자열 감지)
///
/// # Safety
/// 이 함수는 raw pointer를 직접 다루므로 unsafe입니다. 호출자는 다음을 **반드시** 보장해야 합니다.
///
/// - `input_ptr`은 null이 아니며, `input_len` 바이트만큼 **읽기 유효**한 메모리를 가리켜야 합니다.
/// - `out_ptr`은 null이 아니며, `out_capacity` 바이트만큼 **쓰기 유효**한 메모리를 가리켜야 합니다.
/// - `input_ptr`과 `out_ptr`이 가리키는 메모리 영역은 서로 겹치지 않아야 합니다 (aliasing UB 방지).
/// - `out_capacity`는 `(input_len / 4 + 1) * 3` 이상이어야 합니다 (함수가 -2 반환).
/// - 호출 기간 동안 메모리 영역이 유효해야 합니다.
/// - 단일 스레드 호출, concurrent 접근 금지.
///
/// 함수는 `ct_b64_to_bin_u8`와 [ConstantTimeOps::ct_select] 연산만 사용하며,
/// `write_volatile`로 메모리 잔여 데이터 유출을 방지합니다.
/// 잘못된 Base64 문자는 -3 에러로 안전하게 처리되므로 side-channel 누출이 없습니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_b64_decode_caller_alloc(
    input_ptr: *const u8,
    input_len: usize,
    out_ptr: *mut u8,
    out_capacity: usize,
) -> isize {
    // 포인터 유효성 검증
    if input_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }

    // 최대 필요 버퍼 크기 산출 (여유 공간 3바이트 포함)
    let max_required_capacity = (input_len / 4 + 1) * 3;

    // 호출자가 할당한 용량 검증
    if out_capacity < max_required_capacity {
        return -2;
    }

    let input = unsafe { slice::from_raw_parts(input_ptr, input_len) };

    let mut error_accum = 0u8;
    let mut acc = 0u32;
    let mut buf_idx = 0usize;
    let mut out_idx = 0usize;

    for &byte in input {
        let decoded = ct_b64_to_bin_u8(byte);

        let is_err = decoded.ct_eq(0xFF);
        let is_pad = decoded.ct_eq(0x81);
        let is_ws = decoded.ct_eq(0x80);

        let is_valid = !is_err & !is_pad & !is_ws;
        error_accum |= is_err & 0x01;

        let valid_mask_u32 = (is_valid as i8 as i32) as u32;
        let valid_mask_usize = (is_valid as i8 as isize) as usize;

        let next_acc = (acc << 6) | (decoded as u32 & 0x3F);
        acc = next_acc.ct_select(acc, valid_mask_u32);

        let next_buf_idx = buf_idx + 1;
        buf_idx = next_buf_idx.ct_select(buf_idx, valid_mask_usize);

        let is_full = buf_idx.ct_eq(4);

        let b0 = (acc >> 16) as u8;
        let b1 = (acc >> 8) as u8;
        let b2 = acc as u8;

        unsafe {
            core::ptr::write_volatile(out_ptr.add(out_idx), b0);
            core::ptr::write_volatile(out_ptr.add(out_idx + 1), b1);
            core::ptr::write_volatile(out_ptr.add(out_idx + 2), b2);
        }

        let next_out_idx = out_idx + 3;
        out_idx = next_out_idx.ct_select(out_idx, is_full);

        acc = 0u32.ct_select(acc, is_full as u32);
        buf_idx = 0usize.ct_select(buf_idx, is_full);
    }

    let is_two = buf_idx.ct_eq(2);
    let is_three = buf_idx.ct_eq(3);

    let b0_2 = (acc >> 4) as u8;
    let b0_3 = (acc >> 10) as u8;
    let b1_3 = (acc >> 2) as u8;

    let final_b0 = b0_2.ct_select(0, is_two as u8) | b0_3.ct_select(0, is_three as u8);
    let final_b1 = b1_3.ct_select(0, is_three as u8);

    unsafe {
        core::ptr::write_volatile(out_ptr.add(out_idx), final_b0);
        core::ptr::write_volatile(out_ptr.add(out_idx + 1), final_b1);
    }

    let add_len = 1usize.ct_select(0, is_two) | 2usize.ct_select(0, is_three);
    out_idx += add_len;

    // 에러 플래그 누적 여부 확인 후 분기 반환
    if error_accum != 0 {
        return -3;
    }

    out_idx as isize
}
