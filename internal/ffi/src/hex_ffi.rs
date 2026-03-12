use crate::FFIStandard;
use entlib_native_hex::{decode, encode};
use entlib_native_result::EntLibResult;
use std::ptr::write_volatile;

// 모듈 식별자 및 상태 코드 (예시)
const TYPE_ID_HEX: i8 = 2;

/// Java FFM API를 통해 호출되는 FFI 전용 상수-시간 Hex 인코딩 함수입니다.
///
/// # Security
/// - **Zero-Trust**: 전달받은 포인터의 Null 여부와 정렬(Alignment) 상태를 엄격히 검증합니다.
/// - **UCA 규정 준수**: 입력 버퍼의 생명주기 통제권을 존중하며, 새롭게 생성된
///   출력 버퍼의 소유권(is_rust_owned = true)을 Java 측에 명시적으로 전달합니다.
#[unsafe(no_mangle)]
pub extern "C" fn entlib_ffi_hex_encode(
    input: *const FFIStandard,
    output: *mut FFIStandard,
) -> EntLibResult {
    // 포인터 유효성 검증
    if input.is_null() || output.is_null() {
        return EntLibResult::new(TYPE_ID_HEX, -1);
    }

    let input_buf = match unsafe { (*input).into_domain_buffer() } {
        Ok(buf) => buf,
        Err(_) => return EntLibResult::new(TYPE_ID_HEX, -2),
    };
    let out_struct = unsafe { &mut *output };

    // 인코딩 길이 = 원본 길이 * 2
    let required_len = input_buf.len() * 2;
    if out_struct.len < required_len {
        return EntLibResult::new(TYPE_ID_HEX, -3);
    }

    // ManuallyDrop<SecureBuffer>를 Deref하여 &SecureBuffer로 전달
    match encode(&*input_buf) {
        Ok(mut encoded_buf) => {
            let encoded = encoded_buf.as_slice();

            unsafe {
                for (i, &byte) in encoded.iter().enumerate() {
                    write_volatile(out_struct.ptr.add(i), byte);
                }
            }
            // 이 스코프 벗어나면서 encoded_buf -> 소거 -> 메모리 락 해제
            EntLibResult::new(TYPE_ID_HEX, 0).add_additional(required_len as isize)
        }
        // encode 내부의 메모리 잠금 실패 등 비정상 경로
        Err(_) => EntLibResult::new(TYPE_ID_HEX, -4),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ffi_hex_decode(
    input: *const FFIStandard,
    output: *mut FFIStandard,
) -> EntLibResult {
    if input.is_null() || output.is_null() {
        return EntLibResult::new(TYPE_ID_HEX, -1);
    }

    let input_buf = match unsafe { (*input).into_domain_buffer() } {
        Ok(buf) => buf,
        Err(_) => return EntLibResult::new(TYPE_ID_HEX, -2),
    };

    // Hex 인코딩 데이터는 반드시 짝수 길이를 가짐
    // 길이는 비밀 데이터가 아님 -> 상수-시간 분기 필요 X
    if input_buf.len() % 2 != 0 {
        return EntLibResult::new(TYPE_ID_HEX, -5);
    }

    let out_struct = unsafe { &mut *output };

    let required_len = input_buf.len() / 2;
    if out_struct.len < required_len {
        return EntLibResult::new(TYPE_ID_HEX, -3);
    }

    match decode(&*input_buf) {
        Ok(mut encoded_buf) => {
            let encoded = encoded_buf.as_slice();

            unsafe {
                for (i, &byte) in encoded.iter().enumerate() {
                    write_volatile(out_struct.ptr.add(i), byte);
                }
            }
            EntLibResult::new(TYPE_ID_HEX, 0).add_additional(required_len as isize)
        }
        Err(_) => EntLibResult::new(TYPE_ID_HEX, -4),
    }
}
