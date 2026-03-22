//! PEM 인코더 모듈입니다.

use super::error::PemError;
use super::filter::validate_der_envelope;
use super::label::PemLabel;
use crate::error::ArmorError;
use crate::error::ArmorError::PEM;
use entlib_native_base64 as b64;
use entlib_native_secure_buffer::SecureBuffer;

const LINE_LEN: usize = 64;

/// DER 바이트열을 RFC 7468 PEM 형식으로 인코딩하는 함수입니다.
///
/// # Security Note
/// 인코딩 전 DER 외곽 TLV 구조를 검증하여 손상된 데이터를 거부합니다.
/// DER 원본과 Base64 중간값은 SecureBuffer(mlock)에 보관됩니다.
///
/// # Errors
/// `InvalidDer`, `AllocationError`, `Base64Error`
pub fn encode(der: &[u8], label: PemLabel) -> Result<SecureBuffer, ArmorError> {
    validate_der_envelope(der)?;

    let mut src = SecureBuffer::new_owned(der.len())
        .map_err(|_| PEM(PemError::AllocationError))?;
    src.as_mut_slice().copy_from_slice(der);

    let encoded = b64::encode(&src).map_err(|_| PEM(PemError::Base64Error))?;
    let b64_bytes = encoded.as_slice();

    let label_b = label.as_bytes();
    let b64_len = b64_bytes.len();
    let num_lines = b64_len.div_ceil(LINE_LEN);
    let body_len = b64_len + num_lines;
    // "-----BEGIN " (11) + label + "-----\n" (6)
    let header_len = 11 + label_b.len() + 6;
    // "-----END " (9) + label + "-----\n" (6)
    let footer_len = 9 + label_b.len() + 6;

    let total = header_len
        .checked_add(body_len)
        .and_then(|v| v.checked_add(footer_len))
        .ok_or(PEM(PemError::AllocationError))?;

    let mut out = SecureBuffer::new_owned(total).map_err(|_| PEM(PemError::AllocationError))?;
    let buf = out.as_mut_slice();
    let mut pos = 0;

    write_bytes(buf, &mut pos, b"-----BEGIN ");
    write_bytes(buf, &mut pos, label_b);
    write_bytes(buf, &mut pos, b"-----\n");

    let mut b64_pos = 0;
    while b64_pos < b64_len {
        let end = (b64_pos + LINE_LEN).min(b64_len);
        write_bytes(buf, &mut pos, &b64_bytes[b64_pos..end]);
        buf[pos] = b'\n';
        pos += 1;
        b64_pos = end;
    }

    write_bytes(buf, &mut pos, b"-----END ");
    write_bytes(buf, &mut pos, label_b);
    write_bytes(buf, &mut pos, b"-----\n");

    debug_assert_eq!(pos, total);
    Ok(out)
}

#[inline(always)]
fn write_bytes(buf: &mut [u8], pos: &mut usize, src: &[u8]) {
    buf[*pos..*pos + src.len()].copy_from_slice(src);
    *pos += src.len();
}
