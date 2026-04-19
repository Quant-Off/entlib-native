//! DER 파서(리더) 모듈입니다.
//! 재귀 없이 커서 기반으로 TLV를 순회하며 깊이 제한으로 중첩 폭탄을 방어합니다.

use crate::asn1::Oid;
use crate::asn1::Tag;
use crate::der::error::DerError;
use crate::der::length;
use crate::error::ArmorError;
use crate::error::ArmorError::DER;
use entlib_native_secure_buffer::SecureBuffer;

/// 단일 TLV(Tag-Length-Value) 파싱 결과입니다.
#[derive(Debug)]
pub struct DerTlv<'a> {
    /// 파싱된 태그
    pub tag: Tag,
    /// 값 바이트 슬라이스 (복사 없이 원본 버퍼 참조)
    pub value: &'a [u8],
}

/// 커서 기반 DER 파서 구조체입니다.
#[derive(Debug)]
///
/// # Security Note
/// - 스택 재귀 없이 반복(iterative) 방식으로 동작합니다.
/// - `read_sequence` 등 중첩 진입 시 `depth`를 감소시켜 최대 `MAX_DEPTH` 레벨로 제한합니다.
/// - 모든 길이 계산은 `checked_add`를 사용하여 오버플로우를 방어합니다.
pub struct DerReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    /// 입력 슬라이스로 DerReader를 생성하는 함수입니다.
    ///
    /// # Errors
    /// 빈 입력이면 `EmptyInput`.
    pub fn new(data: &'a [u8]) -> Result<Self, ArmorError> {
        if data.is_empty() {
            return Err(DER(DerError::EmptyInput));
        }
        Ok(Self { buf: data, pos: 0 })
    }

    pub(crate) fn from_slice(data: &'a [u8]) -> Self {
        Self { buf: data, pos: 0 }
    }

    /// 남은 바이트가 없으면 true를 반환합니다.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// 남은 바이트 수를 반환합니다.
    #[inline(always)]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// 다음 태그를 소비하지 않고 미리 읽는 함수입니다.
    ///
    /// # Errors
    /// EOF, 장형식 태그, EOC 태그 시 오류.
    pub fn peek_tag(&self) -> Result<Tag, ArmorError> {
        if self.pos >= self.buf.len() {
            return Err(DER(DerError::UnexpectedEof));
        }
        let byte = self.buf[self.pos];
        validate_tag_byte(byte)?;
        Ok(Tag(byte))
    }

    /// 다음 TLV 하나를 파싱하는 함수입니다.
    ///
    /// # Security Note
    /// 값 범위 검증(`pos + length <= buf.len()`)을 통해 버퍼 오버리드를 방어합니다.
    pub fn read_tlv(&mut self) -> Result<DerTlv<'a>, ArmorError> {
        let (tag, length) = self.read_tag_and_length()?;
        let value = self.take_value_slice(length)?;
        Ok(DerTlv { tag, value })
    }

    /// SEQUENCE를 읽어 내부 컨텐츠에 대한 새 DerReader를 반환하는 함수입니다.
    ///
    /// # Arguments
    /// `depth` — 남은 허용 중첩 깊이. 진입 시 1 감소.
    ///
    /// # Errors
    /// `depth == 0`이면 `MaxDepthExceeded`.
    pub fn read_sequence(&mut self, depth: &mut u8) -> Result<DerReader<'a>, ArmorError> {
        self.read_constructed(Tag::SEQUENCE, depth)
    }

    /// SET을 읽어 내부 컨텐츠에 대한 새 DerReader를 반환하는 함수입니다.
    pub fn read_set(&mut self, depth: &mut u8) -> Result<DerReader<'a>, ArmorError> {
        self.read_constructed(Tag::SET, depth)
    }

    /// EXPLICIT 컨텍스트 태그 `[tag_num]`를 읽어 내부 DerReader를 반환하는 함수입니다.
    ///
    /// # Arguments
    /// - `tag_num` — 컨텍스트 태그 번호 (0-30)
    /// - `depth` — 남은 허용 중첩 깊이
    pub fn read_explicit_tag(
        &mut self,
        tag_num: u8,
        depth: &mut u8,
    ) -> Result<DerReader<'a>, ArmorError> {
        let expected = Tag::context(tag_num, true);
        self.read_constructed(expected, depth)
    }

    /// IMPLICIT 컨텍스트 태그 `[tag_num]`의 값 바이트를 반환하는 함수입니다.
    ///
    /// IMPLICIT 태그는 원래 타입의 태그가 `[tag_num]`로 교체된 것이므로
    /// 값 바이트는 원래 타입의 내용과 동일합니다.
    pub fn read_implicit_value(&mut self, tag_num: u8) -> Result<&'a [u8], ArmorError> {
        let expected = Tag::context(tag_num, false);
        let (tag, length) = self.read_tag_and_length()?;
        if tag != expected {
            return Err(DER(DerError::UnexpectedTag {
                expected: expected.0,
                got: tag.0,
            }));
        }
        self.take_value_slice(length)
    }

    /// INTEGER 값 바이트를 반환하는 함수입니다.
    ///
    /// # Security Note
    /// 비최소 인코딩(불필요한 선행 0x00 또는 0xFF)을 거부합니다.
    /// 반환 슬라이스에는 부호 바이트(선행 0x00)가 포함될 수 있습니다.
    pub fn read_integer_bytes(&mut self) -> Result<&'a [u8], ArmorError> {
        let (tag, length) = self.read_tag_and_length()?;
        if tag != Tag::INTEGER {
            return Err(DER(DerError::UnexpectedTag {
                expected: Tag::INTEGER.0,
                got: tag.0,
            }));
        }
        let value = self.take_value_slice(length)?;
        validate_integer_encoding(value)?;
        Ok(value)
    }

    /// INTEGER 값을 SecureBuffer로 복사하여 반환하는 함수입니다.
    ///
    /// # Security Note
    /// 비밀 키 파싱 등 민감 데이터에 사용합니다.
    /// 메모리 잠금된 버퍼로 복사하여 스왑 유출을 방지합니다.
    pub fn read_integer_secure(&mut self) -> Result<SecureBuffer, ArmorError> {
        let bytes = self.read_integer_bytes()?;
        copy_to_secure_buffer(bytes)
    }

    /// OCTET STRING 값 바이트를 반환하는 함수입니다.
    pub fn read_octet_string(&mut self) -> Result<&'a [u8], ArmorError> {
        let (tag, length) = self.read_tag_and_length()?;
        if tag != Tag::OCTET_STRING {
            return Err(DER(DerError::UnexpectedTag {
                expected: Tag::OCTET_STRING.0,
                got: tag.0,
            }));
        }
        self.take_value_slice(length)
    }

    /// OCTET STRING 값을 SecureBuffer로 복사하는 함수입니다.
    ///
    /// # Security Note
    /// 암호화된 키 블롭 등 민감 데이터에 사용합니다.
    pub fn read_octet_string_secure(&mut self) -> Result<SecureBuffer, ArmorError> {
        let bytes = self.read_octet_string()?;
        copy_to_secure_buffer(bytes)
    }

    /// BIT STRING을 파싱하여 `(데이터 슬라이스, 미사용 비트 수)`를 반환하는 함수입니다.
    ///
    /// # Security Note
    /// 미사용 비트 수 바이트가 0–7 범위를 벗어나면 즉시 거부합니다.
    /// 암호 키 파싱 시 미사용 비트는 항상 0이어야 합니다.
    pub fn read_bit_string(&mut self) -> Result<(&'a [u8], u8), ArmorError> {
        let (tag, length) = self.read_tag_and_length()?;
        if tag != Tag::BIT_STRING {
            return Err(DER(DerError::UnexpectedTag {
                expected: Tag::BIT_STRING.0,
                got: tag.0,
            }));
        }
        if length == 0 {
            return Err(DER(DerError::InvalidBitString));
        }
        let raw = self.take_value_slice(length)?;
        let unused_bits = raw[0];
        if unused_bits > 7 {
            return Err(DER(DerError::InvalidBitString));
        }
        // 미사용 비트가 있는 경우 데이터가 최소 1바이트 이상이어야 함
        if unused_bits > 0 && length < 2 {
            return Err(DER(DerError::InvalidBitString));
        }
        Ok((&raw[1..], unused_bits))
    }

    /// OID를 파싱하는 함수입니다.
    pub fn read_oid(&mut self) -> Result<Oid, ArmorError> {
        let (tag, length) = self.read_tag_and_length()?;
        if tag != Tag::OID {
            return Err(DER(DerError::UnexpectedTag {
                expected: Tag::OID.0,
                got: tag.0,
            }));
        }
        if length == 0 {
            return Err(DER(DerError::InvalidOid));
        }
        let value = self.take_value_slice(length)?;
        crate::asn1::decode_oid(value)
    }

    /// NULL을 파싱하는 함수입니다.
    ///
    /// # Errors
    /// NULL의 길이가 0이 아니면 `InvalidLength`.
    pub fn read_null(&mut self) -> Result<(), ArmorError> {
        let (tag, length) = self.read_tag_and_length()?;
        if tag != Tag::NULL {
            return Err(DER(DerError::UnexpectedTag {
                expected: Tag::NULL.0,
                got: tag.0,
            }));
        }
        if length != 0 {
            return Err(DER(DerError::InvalidLength));
        }
        Ok(())
    }

    /// BOOLEAN을 파싱하는 함수입니다.
    ///
    /// # Security Note
    /// DER에서 BOOLEAN은 0x00(false) 또는 0xFF(true)만 허용합니다.
    /// BER의 0x01..0xFE는 거부됩니다.
    pub fn read_boolean(&mut self) -> Result<bool, ArmorError> {
        let (tag, length) = self.read_tag_and_length()?;
        if tag != Tag::BOOLEAN {
            return Err(DER(DerError::UnexpectedTag {
                expected: Tag::BOOLEAN.0,
                got: tag.0,
            }));
        }
        if length != 1 {
            return Err(DER(DerError::InvalidLength));
        }
        let value = self.take_value_slice(1)?;
        match value[0] {
            0x00 => Ok(false),
            0xFF => Ok(true),
            _ => Err(DER(DerError::InvalidBooleanEncoding)),
        }
    }

    /// 파싱 완료 후 잔여 바이트가 없는지 확인하는 함수입니다.
    ///
    /// # Errors
    /// 잔여 바이트가 있으면 `TrailingData`.
    pub fn expect_empty(&self) -> Result<(), ArmorError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(DER(DerError::TrailingData))
        }
    }

    //
    // 내부 헬퍼
    //

    fn read_tag_and_length(&mut self) -> Result<(Tag, usize), ArmorError> {
        if self.pos >= self.buf.len() {
            return Err(DER(DerError::UnexpectedEof));
        }
        let tag_byte = self.buf[self.pos];
        validate_tag_byte(tag_byte)?;
        self.pos += 1;

        let (length, consumed) = length::decode_length(self.buf, self.pos)?;
        self.pos += consumed;
        Ok((Tag(tag_byte), length))
    }

    fn take_value_slice(&mut self, length: usize) -> Result<&'a [u8], ArmorError> {
        let end = self
            .pos
            .checked_add(length)
            .ok_or(DER(DerError::LengthOverflow))?;
        if end > self.buf.len() {
            return Err(DER(DerError::UnexpectedEof));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_constructed(
        &mut self,
        expected_tag: Tag,
        depth: &mut u8,
    ) -> Result<DerReader<'a>, ArmorError> {
        if *depth == 0 {
            return Err(DER(DerError::MaxDepthExceeded));
        }
        let (tag, length) = self.read_tag_and_length()?;
        if tag != expected_tag {
            return Err(DER(DerError::UnexpectedTag {
                expected: expected_tag.0,
                got: tag.0,
            }));
        }
        let inner = self.take_value_slice(length)?;
        *depth -= 1;
        Ok(DerReader::from_slice(inner))
    }
}

//
// 파일-내부 헬퍼 함수
//

/// 태그 바이트 유효성 검사 함수입니다.
///
/// # Security Note
/// - 장형식 태그(0x1F 마스크) 거부: 다중 바이트 태그 파싱 로직 제거로 공격 면 축소
/// - EOC 태그(0x00) 거부: 부정길이 BER 구조에서만 사용
fn validate_tag_byte(byte: u8) -> Result<(), ArmorError> {
    if byte & 0x1F == 0x1F {
        return Err(DER(DerError::InvalidTag));
    }
    if byte == 0x00 {
        return Err(DER(DerError::InvalidTag));
    }
    Ok(())
}

/// INTEGER 인코딩의 최소성을 검증하는 함수입니다.
fn validate_integer_encoding(bytes: &[u8]) -> Result<(), ArmorError> {
    if bytes.is_empty() {
        return Err(DER(DerError::NonMinimalInteger));
    }
    if bytes.len() > 1 {
        // 불필요한 선행 0x00 (양수의 비최소 인코딩)
        if bytes[0] == 0x00 && bytes[1] & 0x80 == 0 {
            return Err(DER(DerError::NonMinimalInteger));
        }
        // 불필요한 선행 0xFF (음수의 비최소 인코딩)
        if bytes[0] == 0xFF && bytes[1] & 0x80 != 0 {
            return Err(DER(DerError::NonMinimalInteger));
        }
    }
    Ok(())
}

/// 바이트 슬라이스를 SecureBuffer에 복사하는 함수입니다.
fn copy_to_secure_buffer(bytes: &[u8]) -> Result<SecureBuffer, ArmorError> {
    let mut buf =
        SecureBuffer::new_owned(bytes.len()).map_err(|_| DER(DerError::AllocationError))?;
    buf.as_mut_slice().copy_from_slice(bytes);
    Ok(buf)
}
