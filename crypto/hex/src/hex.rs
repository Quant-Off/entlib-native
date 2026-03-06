use entlib_native_constant_time::constant_time::ConstantTimeOps;
use entlib_native_core_secure::secure_buffer::SecureBuffer;

#[derive(Debug, PartialEq, Eq)]
pub enum HexError {
    InvalidLength,
    InvalidData,
    BufferTooSmall,
}

/// 단일 4비트(Nibble) 값을 소문자 Hex ASCII 값으로 변환합니다.
#[inline(always)]
fn ct_encode_lower(val: u8) -> u8 {
    let is_digit = val.wrapping_sub(10).ct_is_negative(); // val < 10 이면 0xFF
    let char_digit = val.wrapping_add(b'0');
    let char_lower = val.wrapping_sub(10).wrapping_add(b'a');

    let mut res = 0u8;
    res = char_lower.ct_select(res, !is_digit);
    res = char_digit.ct_select(res, is_digit);
    res
}

/// 단일 4비트 값을 대문자 Hex ASCII 값으로 변환합니다.
#[inline(always)]
fn ct_encode_upper(val: u8) -> u8 {
    let is_digit = val.wrapping_sub(10).ct_is_negative();
    let char_digit = val.wrapping_add(b'0');
    let char_upper = val.wrapping_sub(10).wrapping_add(b'A');

    let mut res = 0u8;
    res = char_upper.ct_select(res, !is_digit);
    res = char_digit.ct_select(res, is_digit);
    res
}

/// Hex ASCII 문자를 4비트 값으로 디코딩합니다. (에러 여부 마스크 동시 반환)
#[inline(always)]
fn ct_decode_val(c: u8) -> (u8, u8) {
    // '0'..='9' (48..=57)
    let is_digit = !(c.wrapping_sub(b'0').ct_is_negative() | b'9'.wrapping_sub(c).ct_is_negative());
    let val_digit = c.wrapping_sub(b'0');

    // 'a'..='f' (97..=102)
    let is_lower = !(c.wrapping_sub(b'a').ct_is_negative() | b'f'.wrapping_sub(c).ct_is_negative());
    let val_lower = c.wrapping_sub(b'a').wrapping_add(10);

    // 'A'..='F' (65..=70)
    let is_upper = !(c.wrapping_sub(b'A').ct_is_negative() | b'F'.wrapping_sub(c).ct_is_negative());
    let val_upper = c.wrapping_sub(b'A').wrapping_add(10);

    let is_valid = is_digit | is_lower | is_upper;

    let mut val = 0u8;
    val = val_digit.ct_select(val, is_digit);
    val = val_lower.ct_select(val, is_lower);
    val = val_upper.ct_select(val, is_upper);

    (val, is_valid)
}

//
// 피호출자(Callee) 패턴: Rust가 할당하고 Java로 포인터를 반환할 때 사용
//

/// 민감 데이터를 SecureBuffer 기반의 Hex로 인코딩합니다.
pub fn encode_secure(data: &[u8]) -> SecureBuffer {
    let mut res = vec![0u8; data.len() * 2];
    for (i, &byte) in data.iter().enumerate() {
        res[i * 2] = ct_encode_lower(byte >> 4);
        res[i * 2 + 1] = ct_encode_lower(byte & 0x0F);
    }
    SecureBuffer { inner: res }
}

/// Hex 문자열을 파싱하여 SecureBuffer(원시 바이트)로 안전하게 디코딩합니다.
pub fn decode_secure(hex: &str) -> Result<SecureBuffer, HexError> {
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(HexError::InvalidLength);
    }

    let mut res = Vec::with_capacity(bytes.len() / 2);
    let mut all_valid = 0xFFu8;

    for chunk in bytes.chunks_exact(2) {
        let (high, high_valid) = ct_decode_val(chunk[0]);
        let (low, low_valid) = ct_decode_val(chunk[1]);

        all_valid &= high_valid & low_valid;
        res.push((high << 4) | low);
    }

    if all_valid != 0xFF {
        // 연산을 끝까지 수행하여 연산 시간 차이를 없앤 후 마지막에 일괄적으로 실패 처리
        return Err(HexError::InvalidData);
    }

    Ok(SecureBuffer { inner: res })
}

//
// 호출자(Caller) 패턴: Java 측에서 생성된 Off-Heap 메모리에 직접 작성
//

pub fn encode_to_slice_ct(data: &[u8], out: &mut [u8]) -> Result<(), HexError> {
    if out.len() < data.len() * 2 {
        return Err(HexError::BufferTooSmall);
    }

    for (i, &byte) in data.iter().enumerate() {
        out[i * 2] = ct_encode_lower(byte >> 4);
        out[i * 2 + 1] = ct_encode_lower(byte & 0x0F);
    }
    Ok(())
}

pub fn decode_to_slice_ct(hex: &str, out: &mut [u8]) -> Result<usize, HexError> {
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(HexError::InvalidLength);
    }

    let expected_len = bytes.len() / 2;
    if out.len() < expected_len {
        return Err(HexError::BufferTooSmall);
    }

    let mut all_valid = 0xFFu8;

    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let (high, high_valid) = ct_decode_val(chunk[0]);
        let (low, low_valid) = ct_decode_val(chunk[1]);

        all_valid &= high_valid & low_valid;
        out[i] = (high << 4) | low;
    }

    if all_valid != 0xFF {
        // Q. T. Felix NOTE: 보안을 위해 실패 시 버퍼에 쓰여진 불완전한 데이터를 즉시 0으로 소거할 수도 있음
        out[..expected_len].fill(0);
        return Err(HexError::InvalidData);
    }

    Ok(expected_len)
}
