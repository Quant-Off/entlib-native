mod hex;

use crate::hex::{decode_hex_core_ct, encode_hex_core_ct};
use entlib_native_base::error::hex::HexError;
use entlib_native_secure_buffer::SecureBuffer;

/// 군사급 보안 요구사항을 충족하는 상수 시간 Hex 인코딩 함수입니다.
///
/// Rust 내부에서 할당된 안전한 메모리 블록(RO 패턴)에 결과를 담아 반환합니다.
///
/// # Arguments
/// - `input` - 인코딩할 원본 평문 데이터가 담긴 SecureBuffer
///
/// # Returns
/// - `Ok(SecureBuffer)` - Hex 인코딩이 완료된 새 버퍼 (OS 레벨 잠금 완료)
/// - `Err` - 메모리 할당 실패 시
pub fn encode(input: &SecureBuffer) -> Result<SecureBuffer, HexError> {
    // 1. 읽기 전용 및 쓰기 전용 슬라이스 확보
    // 내부 데이터를 다룰 때 as_slice 및 as_mut_slice를 통해 반환된 슬라이스는 SecureBuffer의 수명에 묶여 있습니다.
    let input_slice = input.as_slice();
    let required_len = input_slice.len() * 2;

    // 2. 출력용 SecureBuffer 생성 (RO 패턴)
    // new_owned 메소드를 통해 Rust 내부에서 페이지 정렬된 안전한 메모리를 새로 할당합니다.
    let mut output_buffer = SecureBuffer::new_owned(required_len)?;

    // 3. 상수 시간 인코딩 연산 수행
    encode_hex_core_ct(input_slice, output_buffer.as_mut_slice());

    // 4. 안전하게 래핑된 버퍼 반환
    Ok(output_buffer)
}

/// 군사급 보안 요구사항을 충족하는 상수-시간 Hex 디코딩 함수입니다.
///
/// Rust 내부에서 할당된 안전한 메모리 블록(RO 패턴)에 디코딩된 바이너리 결과를 담아 반환합니다.
/// 디코딩 중 유효하지 않은 문자가 발견되더라도 연산 시간은 동일하며,
/// 실패 시 중간에 생성된 버퍼는 즉시 물리적으로 소거(Zeroize)됩니다.
///
/// # Arguments
/// - `input` - 디코딩할 Hex 문자열 데이터가 담긴 SecureBuffer
///
/// # Returns
/// - `Ok(SecureBuffer)` - 디코딩이 완료된 새 버퍼 (OS 레벨 잠금 완료)
/// - `Err` - 메모리 할당 실패 또는 유효하지 않은 Hex 문자열 입력 시
pub fn decode(input: &SecureBuffer) -> Result<SecureBuffer, HexError> {
    // 1. 읽기 전용 슬라이스 확보
    let input_slice = input.as_slice();

    // 디코딩된 데이터의 길이는 입력 Hex 문자열의 절반입니다.
    let required_len = input_slice.len() / 2;

    // 2. 출력용 SecureBuffer 생성 (RO 패턴 적용)
    // new_owned를 통해 Rust 내부에서 페이지 정렬된 안전한 메모리를 새로 할당받고 OS 잠금을 수행합니다.
    let mut output_buffer = SecureBuffer::new_owned(required_len)?;

    // 3. 상수-시간 디코딩 연산 수행
    // 입력에 유효하지 않은 문자가 포함되어 있어도 즉시 반환(Early Return)하지 않고 끝까지 연산합니다.
    let is_valid = decode_hex_core_ct(input_slice, output_buffer.as_mut_slice());

    // 4. 디코딩 성공 여부 검증 (상수-시간 영역 -> 일반 제어 흐름 영역)
    // Choice::unwrap_u8()을 호출하여 결과가 0xFF(True)인지 확인합니다.
    if is_valid.unwrap_u8() == 0xFF {
        Ok(output_buffer)
    } else {
        // 5. 에러 발생 시의 안티 포렌식(Anti-Forensics) 및 물리적 파기
        // 함수가 Err를 반환하며 스코프를 벗어날 때, output_buffer의 Drop 로직이 자동으로 호출됩니다.
        // 이때 할당된 전체 capacity에 대해 Zeroizer::zeroize_raw가 수행되어 불완전한 데이터가 물리적으로 소거됩니다.

        // 타이밍/패딩 오라클 공격 방지를 위해 에러 원인(위치, 발생한 문자 등)을 상세히 밝히지 않고 균일한 메시지를 반환합니다.
        Err(HexError::IllegalCharacter)
    }
}
