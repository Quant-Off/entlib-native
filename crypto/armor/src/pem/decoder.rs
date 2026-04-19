//! PEM 디코더 모듈입니다.

use super::error::PemError;
use super::filter::validate_der_envelope;
use super::label::PemLabel;
use crate::error::ArmorError;
use crate::error::ArmorError::PEM;
use alloc::vec::Vec;
use entlib_native_base64 as b64;
use entlib_native_secure_buffer::SecureBuffer;

const BEGIN_PREFIX: &[u8] = b"-----BEGIN ";
const END_PREFIX: &[u8] = b"-----END ";
const BOUNDARY_SUFFIX: &[u8] = b"-----";

/// PEM 형식 데이터를 DER 바이트열로 디코딩하는 함수입니다.
///
/// # Security Note
/// 레이블을 허용 목록과 대조하여 비승인 구조체 타입을 거부합니다.
/// 디코딩된 DER의 외곽 TLV 구조를 검증하여 손상된 페이로드를 거부합니다.
/// 결과는 SecureBuffer(mlock)에 보관됩니다.
///
/// # Errors
/// `MissingHeader`, `MissingFooter`, `InvalidHeader`, `InvalidFooter`,
/// `UnknownLabel`, `LabelMismatch`, `EmptyBody`, `Base64Error`,
/// `InvalidDer`, `AllocationError`
pub fn decode(pem: &[u8]) -> Result<(PemLabel, SecureBuffer), ArmorError> {
    let (label, rest) = parse_header(pem)?;
    let (footer_label, b64_body) = collect_body(rest)?;

    if footer_label != label {
        return Err(PEM(PemError::LabelMismatch));
    }
    if b64_body.is_empty() {
        return Err(PEM(PemError::EmptyBody));
    }

    let mut b64_buf =
        SecureBuffer::new_owned(b64_body.len()).map_err(|_| PEM(PemError::AllocationError))?;
    b64_buf.as_mut_slice().copy_from_slice(&b64_body);

    let der = b64::decode(&b64_buf).map_err(|_| PEM(PemError::Base64Error))?;
    validate_der_envelope(der.as_slice())?;

    Ok((label, der))
}

fn parse_header(input: &[u8]) -> Result<(PemLabel, &[u8]), ArmorError> {
    let input = trim_leading_whitespace(input);
    if !input.starts_with(BEGIN_PREFIX) {
        return Err(PEM(PemError::MissingHeader));
    }
    let after_prefix = &input[BEGIN_PREFIX.len()..];
    let dash_pos =
        find_pattern(after_prefix, BOUNDARY_SUFFIX).ok_or(PEM(PemError::InvalidHeader))?;
    let label = PemLabel::from_bytes(&after_prefix[..dash_pos])?;
    let after_suffix = &after_prefix[dash_pos + BOUNDARY_SUFFIX.len()..];
    let after_nl = consume_newline(after_suffix).ok_or(PEM(PemError::InvalidHeader))?;
    Ok((label, after_nl))
}

fn collect_body(mut input: &[u8]) -> Result<(PemLabel, Vec<u8>), ArmorError> {
    let mut body: Vec<u8> = Vec::new();
    loop {
        if input.is_empty() {
            return Err(PEM(PemError::MissingFooter));
        }
        if input.starts_with(END_PREFIX) {
            let after_prefix = &input[END_PREFIX.len()..];
            let dash_pos =
                find_pattern(after_prefix, BOUNDARY_SUFFIX).ok_or(PEM(PemError::InvalidFooter))?;
            let footer_label = PemLabel::from_bytes(&after_prefix[..dash_pos])?;
            return Ok((footer_label, body));
        }
        let (line, rest) = split_line(input);
        for &byte in line {
            if !byte.is_ascii_whitespace() {
                body.push(byte);
            }
        }
        input = rest;
    }
}

fn trim_leading_whitespace(input: &[u8]) -> &[u8] {
    let pos = input
        .iter()
        .position(|&b| !b.is_ascii_whitespace())
        .unwrap_or(input.len());
    &input[pos..]
}

fn consume_newline(input: &[u8]) -> Option<&[u8]> {
    if input.starts_with(b"\r\n") {
        Some(&input[2..])
    } else if input.starts_with(b"\n") {
        Some(&input[1..])
    } else if input.is_empty() {
        Some(input)
    } else {
        None
    }
}

fn split_line(input: &[u8]) -> (&[u8], &[u8]) {
    match input.iter().position(|&b| b == b'\n') {
        Some(pos) => {
            let line_end = if pos > 0 && input[pos - 1] == b'\r' {
                pos - 1
            } else {
                pos
            };
            (&input[..line_end], &input[pos + 1..])
        }
        None => (input, &[]),
    }
}

fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
