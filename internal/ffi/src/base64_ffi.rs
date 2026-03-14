//! 상수-시간(constant-time) Base64 인코딩·디코딩 FFI 모듈
//!
//! 외부에서 호출자 할당(caller-alloc) 메모리에 직접 기록합니다.
//! 모든 연산은 `entlib-native-base64` 코어 크레이트에 위임되어
//! 분기 없는 상수 시간으로 side-channel 공격에 저항합니다.
//!
//! # Security Note
//! 이 모듈의 함수는 반드시 외부에서 직접 호출되므로 연산 종료 즉시 소거 작업을
//! 진행해선 안 됩니다. 소거 권한은 외부에 있으며, 반드시 소거 지시를 받고
//! 작업을 수행해야 합니다.
//!
//! # Author
//! Q. T. Felix

use crate::FFIStandard;
use entlib_native_base64::{decode, encode};
use entlib_native_result::EntLibResult;
use std::ptr::write_volatile;

const TYPE_ID_BASE64: i8 = 1;

/// Java 측에서 할당한 메모리에 `Base64` 인코딩 결과를 직접 기록하는 함수입니다.
///
/// 내부적으로 [`entlib_native_base64::encode`]에 위임합니다.
///
/// # Arguments
/// * `input` - 인코딩할 평문 배열의 포인터 및 길이를 담은 [`FFIStandard`] 포인터
/// * `output` - (호출자 할당) 인코딩된 결과를 기록할 메모리의 포인터 및 용량을 담은 [`FFIStandard`] 포인터
///
/// # Returns
/// * `status == 0`: 성공, `additional` 필드에 인코딩된 결과의 실제 바이트 길이 기록
/// * `status == -1`: `Null` 포인터, 또는 입력 메모리 페이지 정렬 또는 잠금 실패
/// * `status == -2`: 필요 버퍼 크기 산출 도중 오버플로우 발생, 또는 mlock 실패
/// * `status == -3`: 호출자 할당 출력 용량 부족
///
/// # Safety
/// 이 함수는 raw pointer를 직접 다루므로 unsafe입니다. 호출자는 다음을 **반드시** 보장해야 합니다.
/// - `input`은 null이 아니며, `input.ptr`은 `input.len` 바이트만큼 **읽기 유효**하고
///   OS 페이지 크기에 맞게 정렬되어 있어야 합니다.
/// - `output`은 null이 아니며, `output.ptr`은 `output.len` 바이트만큼 **쓰기 유효**해야 합니다.
/// - `input.ptr`과 `output.ptr`이 가리키는 메모리 영역은 서로 겹치지 않아야 합니다.
/// - 호출 기간 동안 두 메모리 영역이 해제되거나 재할당되지 않아야 합니다.
/// - 단일 스레드에서 호출되며, concurrent 접근이 없어야 합니다.
#[unsafe(no_mangle)]
unsafe extern "C" fn ffi_base64_encode(
    input: *const FFIStandard,
    output: *mut FFIStandard,
) -> EntLibResult {
    // 포인터 유효성 검증
    if input.is_null() || output.is_null() {
        return EntLibResult::new(TYPE_ID_BASE64, -1);
    }

    // FFIStandard -> ManuallyDrop<SecureBuffer> 변환
    // 내부적으로 페이지 정렬 검증 + OS 메모리 잠금(mlock) 수행
    let in_buffer = match unsafe { (*input).into_domain_buffer() } {
        Ok(buf) => buf,
        Err(_) => return EntLibResult::new(TYPE_ID_BASE64, -6),
    };
    let out_struct = unsafe { &mut *output };

    // 필요 버퍼 크기 산출 및 오버플로우 방지
    let required_capacity = match in_buffer.len().checked_add(2) {
        Some(val) => match (val / 3).checked_mul(4) {
            Some(cap) => cap,
            None => return EntLibResult::new(TYPE_ID_BASE64, -2),
        },
        None => return EntLibResult::new(TYPE_ID_BASE64, -2),
    };

    // 호출자가 할당한 용량(capacity) 검증
    if out_struct.len < required_capacity {
        return EntLibResult::new(TYPE_ID_BASE64, -3);
    }

    match encode(&in_buffer) {
        Ok(encoded_buf) => {
            let encoded = encoded_buf.as_slice();
            // write_volatile로 컴파일러 최적화에 의한 소거 방지
            unsafe {
                for (i, &byte) in encoded.iter().enumerate() {
                    write_volatile(out_struct.ptr.add(i), byte);
                }
            }
            EntLibResult::new(TYPE_ID_BASE64, 0).add_additional(required_capacity as isize)
        }
        // encode 내부의 메모리 잠금 실패 등 비정상 경로
        Err(_) => EntLibResult::new(TYPE_ID_BASE64, -2),
    }
}

/// Java 측에서 할당한 메모리에 분기 없는 상수-시간(constant-time)으로 `Base64` 디코딩을 수행합니다.
///
/// 내부적으로 [`entlib_native_base64::decode`]에 위임합니다.
///
/// # Arguments
/// * `input` - 디코딩할 `Base64` 문자열의 포인터 및 길이를 담은 [`FFIStandard`] 포인터
/// * `output` - (호출자 할당) 복원된 평문을 기록할 메모리의 포인터 및 용량을 담은 [`FFIStandard`] 포인터
///
/// # Returns
/// * `status == 0`: 성공, `additional` 필드에 디코딩된 평문의 실제 바이트 길이 기록
/// * `status == -1`: `Null` 포인터, 또는 입력 메모리 페이지 정렬 또는 잠금 실패
/// * `status == -2`: 호출자 할당 출력 용량 부족
/// * `status == -3`: 유효하지 않은 `Base64` 문자열 (길이, 패딩, 문자 오류), 또는 mlock 실패
///
/// # Safety
/// 이 함수는 raw pointer를 직접 다루므로 unsafe입니다. 호출자는 다음을 **반드시** 보장해야 합니다.
/// - `input`은 null이 아니며, `input.ptr`은 `input.len` 바이트만큼 **읽기 유효**하고
///   OS 페이지 크기에 맞게 정렬되어 있어야 합니다.
/// - `output`은 null이 아니며, `output.ptr`은 `output.len` 바이트만큼 **쓰기 유효**해야 합니다.
/// - `input.ptr`과 `output.ptr`이 가리키는 메모리 영역은 서로 겹치지 않아야 합니다.
/// - `output.len`은 `(input.len / 4 + 1) * 3` 이상이어야 합니다.
/// - 호출 기간 동안 메모리 영역이 유효해야 합니다.
/// - 단일 스레드 호출, concurrent 접근 금지.
#[unsafe(no_mangle)]
unsafe extern "C" fn ffi_base64_decode(
    input: *const FFIStandard,
    output: *mut FFIStandard,
) -> EntLibResult {
    // 포인터 유효성 검증
    if input.is_null() || output.is_null() {
        return EntLibResult::new(TYPE_ID_BASE64, -1);
    }

    // FFIStandard -> ManuallyDrop<SecureBuffer> 변환
    // 내부적으로 페이지 정렬 검증 + OS 메모리 잠금(mlock) 수행
    let in_buffer = match unsafe { (*input).into_domain_buffer() } {
        Ok(buf) => buf,
        Err(_) => return EntLibResult::new(TYPE_ID_BASE64, -6),
    };

    let out_struct = unsafe { &mut *output };

    // 최대 필요 버퍼 크기 산출 (여유 공간 3바이트 포함)
    let max_required_capacity = (in_buffer.len() / 4 + 1) * 3;

    // 호출자가 할당한 용량 검증
    if out_struct.len < max_required_capacity {
        return EntLibResult::new(TYPE_ID_BASE64, -4);
    }

    match decode(&in_buffer) {
        Ok(decoded_buf) => {
            let decoded = decoded_buf.as_slice();
            let decoded_len = decoded.len();
            // write_volatile로 컴파일러 최적화에 의한 소거 방지
            unsafe {
                for (i, &byte) in decoded.iter().enumerate() {
                    write_volatile(out_struct.ptr.add(i), byte);
                }
            }
            EntLibResult::new(TYPE_ID_BASE64, 0).add_additional(decoded_len as isize)
        }
        // 유효하지 않은 Base64 문자열 또는 메모리 잠금 실패
        Err(_) => EntLibResult::new(TYPE_ID_BASE64, -5),
    }
}
