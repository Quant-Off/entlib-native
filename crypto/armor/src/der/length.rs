//! DER 길이 인코딩/디코딩 모듈입니다.
//! 부정길이(BER) 거부, 비최소 인코딩 거부, 오버플로우 방어를 포함합니다.

use alloc::vec::Vec;

use crate::der::error::DerError;
use crate::error::ArmorError;
use crate::error::ArmorError::DER;

/// 단일 TLV 값의 최대 허용 바이트 수 (16 MiB − 1)
pub(crate) const MAX_VALUE_LEN: usize = 0x00FF_FFFF;

/// `buf[pos]`에서 DER 길이를 디코딩하여 `(length, consumed_bytes)`를 반환하는 함수입니다.
///
/// # Security Note
/// - 부정길이(0x80) 즉시 거부
/// - 예약 바이트(0xFF) 거부
/// - 비최소 인코딩 (long-form으로 표현 가능한 길이를 short-form으로 표현하거나,
///   long-form 바이트에 선행 0x00) 거부
/// - 길이 계산 오버플로우: `checked_mul` + `checked_add`로 방어
pub(crate) fn decode_length(buf: &[u8], pos: usize) -> Result<(usize, usize), ArmorError> {
    if pos >= buf.len() {
        return Err(DER(DerError::UnexpectedEof));
    }
    let first = buf[pos];

    // 부정길이 (BER 전용)
    if first == 0x80 {
        return Err(DER(DerError::IndefiniteLength));
    }
    // 예약 바이트
    if first == 0xFF {
        return Err(DER(DerError::InvalidLength));
    }

    // 단형식 (short form): 0x00–0x7F
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }

    // 장형식 (long form): 0x81–0x84
    let num_len_bytes = (first & 0x7F) as usize;
    // 지원 범위 초과 또는 num_len_bytes == 0 (부정길이로 이미 처리됨)
    if num_len_bytes == 0 || num_len_bytes > 4 {
        return Err(DER(DerError::InvalidLength));
    }

    let end = pos
        .checked_add(1)
        .and_then(|p| p.checked_add(num_len_bytes))
        .ok_or(DER(DerError::LengthOverflow))?;
    if end > buf.len() {
        return Err(DER(DerError::UnexpectedEof));
    }

    // 선행 0x00 금지 (비최소 인코딩)
    if buf[pos + 1] == 0x00 {
        return Err(DER(DerError::NonMinimalLength));
    }

    let mut length: usize = 0;
    for i in 0..num_len_bytes {
        length = length
            .checked_mul(256)
            .ok_or(DER(DerError::LengthOverflow))?
            .checked_add(buf[pos + 1 + i] as usize)
            .ok_or(DER(DerError::LengthOverflow))?;
    }

    // DER: 길이 < 128이면 반드시 단형식으로 인코딩해야 함
    if length < 128 {
        return Err(DER(DerError::NonMinimalLength));
    }

    if length > MAX_VALUE_LEN {
        return Err(DER(DerError::LengthOverflow));
    }

    Ok((length, 1 + num_len_bytes))
}

/// DER 길이를 `buf`에 인코딩하는 함수입니다.
///
/// # Security Note
/// 항상 최소 바이트로 인코딩합니다 (DER 요구사항).
pub(crate) fn encode_length(buf: &mut Vec<u8>, length: usize) -> Result<(), ArmorError> {
    if length > MAX_VALUE_LEN {
        return Err(DER(DerError::LengthOverflow));
    }
    if length < 128 {
        buf.push(length as u8);
    } else if length <= 0xFF {
        buf.push(0x81);
        buf.push(length as u8);
    } else if length <= 0xFFFF {
        buf.push(0x82);
        buf.push((length >> 8) as u8);
        buf.push(length as u8);
    } else if length <= 0xFF_FFFF {
        buf.push(0x83);
        buf.push((length >> 16) as u8);
        buf.push((length >> 8) as u8);
        buf.push(length as u8);
    } else {
        buf.push(0x84);
        buf.push((length >> 24) as u8);
        buf.push((length >> 16) as u8);
        buf.push((length >> 8) as u8);
        buf.push(length as u8);
    }
    Ok(())
}
