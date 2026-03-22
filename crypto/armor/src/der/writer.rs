//! DER 인코더(라이터) 모듈입니다.
//! 항상 최소 바이트 DER 형식으로 인코딩합니다.

use crate::asn1;
use crate::asn1::Oid;
use crate::asn1::Tag;
use crate::der::error::DerError;
use crate::der::length;
use crate::error::ArmorError;
use crate::error::ArmorError::DER;
use alloc::vec::Vec;

/// DER 인코더 구조체입니다.
///
/// 개별 write_* 메서드로 TLV를 누적하고 `finish()`로 최종 바이트열을 회수합니다.
/// 중첩 SEQUENCE는 내부 컨텐츠를 별도 DerWriter로 인코딩한 뒤
/// `write_sequence(inner.finish())` 형태로 조립합니다.
pub struct DerWriter {
    buf: Vec<u8>,
}

impl DerWriter {
    /// 빈 DerWriter를 생성합니다.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// 누적된 인코딩 결과를 반환하는 함수입니다.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    /// SEQUENCE TLV를 인코딩하는 함수입니다.
    pub fn write_sequence(&mut self, inner: &[u8]) -> Result<(), ArmorError> {
        self.push_tlv(Tag::SEQUENCE.0, inner)
    }

    /// SET TLV를 인코딩하는 함수입니다.
    pub fn write_set(&mut self, inner: &[u8]) -> Result<(), ArmorError> {
        self.push_tlv(Tag::SET.0, inner)
    }

    /// EXPLICIT 컨텍스트 태그 `[tag_num]`를 인코딩하는 함수입니다.
    pub fn write_explicit_tag(&mut self, tag_num: u8, inner: &[u8]) -> Result<(), ArmorError> {
        let tag = Tag::context(tag_num, true);
        self.push_tlv(tag.0, inner)
    }

    /// IMPLICIT 컨텍스트 태그 `[tag_num]`를 원시 값 바이트로 인코딩하는 함수입니다.
    pub fn write_implicit_tag(&mut self, tag_num: u8, value: &[u8]) -> Result<(), ArmorError> {
        let tag = Tag::context(tag_num, false);
        self.push_tlv(tag.0, value)
    }

    /// 부호 없는 정수를 DER INTEGER로 인코딩하는 함수입니다.
    ///
    /// # Security Note
    /// - 선행 0x00 바이트를 제거하여 최소 표현을 보장합니다.
    /// - 최상위 비트가 1이면(음수로 오독될 수 있으므로) 0x00 부호 바이트를 자동 삽입합니다.
    /// - 입력이 비어 있으면 정수 0으로 인코딩합니다.
    pub fn write_integer_unsigned(&mut self, bytes: &[u8]) -> Result<(), ArmorError> {
        let stripped = strip_leading_zeros(bytes);

        if stripped.is_empty() {
            // 값 0: INTEGER 0x00
            return self.push_tlv(Tag::INTEGER.0, &[0x00]);
        }

        if stripped[0] & 0x80 != 0 {
            // 최상위 비트가 1: 부호 바이트 0x00 삽입
            let value_len = stripped
                .len()
                .checked_add(1)
                .ok_or(DER(DerError::LengthOverflow))?;
            self.buf.push(Tag::INTEGER.0);
            length::encode_length(&mut self.buf, value_len)?;
            self.buf.push(0x00);
            self.buf.extend_from_slice(stripped);
        } else {
            self.push_tlv(Tag::INTEGER.0, stripped)?;
        }
        Ok(())
    }

    /// 이미 DER 인코딩된 INTEGER 바이트열을 그대로 기록하는 함수입니다.
    ///
    /// # Security Note
    /// 호출자가 유효한 DER INTEGER 값 바이트를 제공해야 합니다.
    pub fn write_integer_raw(&mut self, der_integer_value: &[u8]) -> Result<(), ArmorError> {
        self.push_tlv(Tag::INTEGER.0, der_integer_value)
    }

    /// OCTET STRING을 인코딩하는 함수입니다.
    pub fn write_octet_string(&mut self, data: &[u8]) -> Result<(), ArmorError> {
        self.push_tlv(Tag::OCTET_STRING.0, data)
    }

    /// BIT STRING을 인코딩하는 함수입니다.
    ///
    /// # Arguments
    /// - `data` — 비트 데이터 바이트열
    /// - `unused_bits` — 마지막 바이트의 미사용 비트 수 (0-7)
    ///
    /// # Errors
    /// `unused_bits > 7` 또는 `unused_bits > 0`이면서 `data`가 비어 있으면 `InvalidBitString`.
    pub fn write_bit_string(&mut self, data: &[u8], unused_bits: u8) -> Result<(), ArmorError> {
        if unused_bits > 7 {
            return Err(DER(DerError::InvalidBitString));
        }
        if unused_bits > 0 && data.is_empty() {
            return Err(DER(DerError::InvalidBitString));
        }
        let value_len = data
            .len()
            .checked_add(1)
            .ok_or(DER(DerError::LengthOverflow))?;
        self.buf.push(Tag::BIT_STRING.0);
        length::encode_length(&mut self.buf, value_len)?;
        self.buf.push(unused_bits);
        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// OID를 인코딩하는 함수입니다.
    pub fn write_oid(&mut self, oid: &Oid) -> Result<(), ArmorError> {
        let arcs = oid.arcs();
        if arcs.len() < 2 {
            return Err(DER(DerError::InvalidOid));
        }

        // 값 바이트를 임시 버퍼에 인코딩
        let mut value: Vec<u8> = Vec::new();

        // 첫 번째 하위식별자: 40*a0 + a1
        let first_sub = (arcs[0] as u64)
            .checked_mul(40)
            .and_then(|v| v.checked_add(arcs[1] as u64))
            .ok_or(DER(DerError::InvalidOid))? as u32;
        asn1::encode_base128(&mut value, first_sub);

        for &arc in &arcs[2..] {
            asn1::encode_base128(&mut value, arc);
        }

        self.push_tlv(Tag::OID.0, &value)
    }

    /// NULL을 인코딩하는 함수입니다.
    pub fn write_null(&mut self) -> Result<(), ArmorError> {
        self.buf.push(Tag::NULL.0);
        self.buf.push(0x00);
        Ok(())
    }

    /// BOOLEAN을 인코딩하는 함수입니다.
    ///
    /// # Security Note
    /// DER 규칙: true는 0xFF, false는 0x00으로 인코딩합니다.
    pub fn write_boolean(&mut self, value: bool) -> Result<(), ArmorError> {
        self.buf.push(Tag::BOOLEAN.0);
        self.buf.push(0x01);
        self.buf.push(if value { 0xFF } else { 0x00 });
        Ok(())
    }

    //
    // 내부 헬퍼
    //

    fn push_tlv(&mut self, tag: u8, value: &[u8]) -> Result<(), ArmorError> {
        self.buf.push(tag);
        length::encode_length(&mut self.buf, value.len())?;
        self.buf.extend_from_slice(value);
        Ok(())
    }
}

impl Default for DerWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// 선행 0x00 바이트를 제거하되, 마지막 바이트는 보존합니다.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    if bytes.is_empty() {
        return bytes;
    }
    let first_nonzero = bytes
        .iter()
        .position(|&b| b != 0x00)
        .unwrap_or(bytes.len() - 1);
    &bytes[first_nonzero..]
}
