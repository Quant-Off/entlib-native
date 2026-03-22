//! ASN.1 OID(Object Identifier) 타입 모듈입니다.
//! OID 비교는 알고리즘 식별자 누출을 막기 위해 상수-시간으로 수행합니다.

use entlib_native_constant_time::traits::ConstantTimeEq;

use crate::asn1::error::ASN1Error;
use crate::error::ArmorError;
use crate::error::ArmorError::ASN1;

/// OID 최대 아크(arc) 수
pub const OID_MAX_ARCS: usize = 16;

/// ASN.1 OID를 나타내는 구조체입니다.
/// 내부 아크 배열은 항상 `OID_MAX_ARCS` 크기로 고정되어 있으며,
/// `len` 이후의 슬롯은 0으로 패딩되어 상수-시간 비교를 보장합니다.
#[derive(Clone, Copy, Debug)]
pub struct Oid {
    arcs: [u32; OID_MAX_ARCS],
    len: usize,
}

impl Oid {
    /// 아크 슬라이스로 OID를 생성하는 함수입니다.
    ///
    /// # Arguments
    /// `arcs` — OID 아크 배열. 첫 번째 아크는 0, 1, 2 중 하나여야 합니다.
    ///
    /// # Errors
    /// 아크 수가 2 미만이거나 `OID_MAX_ARCS` 초과, 또는 첫 아크 > 2이면 `InvalidOid`.
    pub fn from_arcs(arcs: &[u32]) -> Result<Self, ArmorError> {
        if arcs.len() < 2 || arcs.len() > OID_MAX_ARCS {
            return Err(ASN1(ASN1Error::InvalidOid));
        }
        if arcs[0] > 2 {
            return Err(ASN1(ASN1Error::InvalidOid));
        }
        // 첫 아크가 0 또는 1이면 두 번째 아크는 반드시 0–39
        if arcs[0] < 2 && arcs[1] > 39 {
            return Err(ASN1(ASN1Error::InvalidOid));
        }
        // 첫 두 아크의 결합 값(40*a0+a1)이 u32에 맞는지 확인
        let combined = (arcs[0] as u64)
            .checked_mul(40)
            .and_then(|v| v.checked_add(arcs[1] as u64))
            .ok_or(ASN1(ASN1Error::InvalidOid))?;
        if combined > u32::MAX as u64 {
            return Err(ASN1(ASN1Error::InvalidOid));
        }

        let mut result = Oid {
            arcs: [0u32; OID_MAX_ARCS],
            len: arcs.len(),
        };
        result.arcs[..arcs.len()].copy_from_slice(arcs);
        Ok(result)
    }

    /// OID 아크 슬라이스를 반환합니다.
    #[inline(always)]
    pub fn arcs(&self) -> &[u32] {
        &self.arcs[..self.len]
    }

    /// 아크 수를 반환합니다.
    #[inline(always)]
    pub fn arc_count(&self) -> usize {
        self.len
    }

    /// 두 OID를 상수-시간으로 비교하는 함수입니다.
    ///
    /// # Security Note
    /// 알고리즘 식별자 비교 시 타이밍 부채널 공격을 방지하기 위해
    /// 모든 `OID_MAX_ARCS` 슬롯을 항상 비교합니다.
    pub fn ct_eq(&self, other: &Oid) -> bool {
        // 길이 비교 (상수-시간)
        let len_eq = self.len.ct_eq(&other.len).unwrap_u8();

        // 아크 배열 전체 비교 — len 이후는 0 패딩이므로 항상 동일
        let mut acc = 0xFFu8;
        for i in 0..OID_MAX_ARCS {
            acc &= self.arcs[i].ct_eq(&other.arcs[i]).unwrap_u8();
        }

        (acc & len_eq) == 0xFF
    }

    /// DER 인코딩 시 값 바이트 길이를 반환하는 함수입니다.
    #[allow(dead_code)]
    pub(crate) fn der_value_len(&self) -> Result<usize, ArmorError> {
        let first = (self.arcs[0] as u64)
            .checked_mul(40)
            .and_then(|v| v.checked_add(self.arcs[1] as u64))
            .ok_or(ASN1(ASN1Error::InvalidOid))? as u32;

        let mut total = base128_encoded_len(first);
        for i in 2..self.len {
            total = total
                .checked_add(base128_encoded_len(self.arcs[i]))
                .ok_or(ASN1(ASN1Error::LengthOverflow))?;
        }
        Ok(total)
    }
}

/// base-128 VarInt 인코딩 바이트 수를 반환하는 함수입니다.
#[allow(dead_code)]
pub(crate) fn base128_encoded_len(val: u32) -> usize {
    match val {
        0x0000_0000..=0x0000_007F => 1,
        0x0000_0080..=0x0000_3FFF => 2,
        0x0000_4000..=0x001F_FFFF => 3,
        0x0020_0000..=0x0FFF_FFFF => 4,
        _ => 5,
    }
}

/// base-128 VarInt를 `buf`에 인코딩하는 함수입니다.
pub(crate) fn encode_base128(buf: &mut alloc::vec::Vec<u8>, val: u32) {
    if val == 0 {
        buf.push(0x00);
        return;
    }
    let mut tmp = [0u8; 5];
    let mut count = 0usize;
    let mut v = val;
    while v > 0 {
        tmp[count] = (v & 0x7F) as u8;
        v >>= 7;
        count += 1;
    }
    // 최상위 그룹부터 내림차순으로 기록 (모든 바이트 except last에 0x80 세트)
    for i in (0..count).rev() {
        let continuation = if i > 0 { 0x80u8 } else { 0x00u8 };
        buf.push(tmp[i] | continuation);
    }
}

/// `buf[pos..end]`에서 base-128 VarInt를 디코딩하는 함수입니다.
///
/// # Security Note
/// 5바이트 초과 시 오류, u32 범위 초과 시 오류 (버퍼 오버리드 방지).
pub(crate) fn decode_base128(buf: &[u8], pos: &mut usize, end: usize) -> Result<u32, ArmorError> {
    let mut val: u64 = 0;
    let mut count = 0usize;
    loop {
        if *pos >= end {
            return Err(ASN1(ASN1Error::UnexpectedEof));
        }
        if count >= 5 {
            return Err(ASN1(ASN1Error::InvalidOid));
        }
        let byte = buf[*pos];
        *pos += 1;
        count += 1;
        val = (val << 7) | (byte & 0x7F) as u64;
        if val > u32::MAX as u64 {
            return Err(ASN1(ASN1Error::InvalidOid));
        }
        if byte & 0x80 == 0 {
            return Ok(val as u32);
        }
    }
}

/// DER OID 값 바이트로부터 `Oid`를 파싱하는 함수입니다.
pub(crate) fn decode_oid(bytes: &[u8]) -> Result<Oid, ArmorError> {
    if bytes.is_empty() {
        return Err(ASN1(ASN1Error::InvalidOid));
    }

    let mut arcs = [0u32; OID_MAX_ARCS];
    let mut arc_count = 0usize;
    let mut pos = 0usize;

    // 첫 번째 하위식별자: 40*a0 + a1
    let first_sub = decode_base128(bytes, &mut pos, bytes.len())?;
    let (a0, a1) = if first_sub < 40 {
        (0u32, first_sub)
    } else if first_sub < 80 {
        (1u32, first_sub - 40)
    } else {
        (2u32, first_sub.wrapping_sub(80))
    };
    arcs[arc_count] = a0;
    arc_count += 1;
    arcs[arc_count] = a1;
    arc_count += 1;

    // 나머지 하위식별자
    while pos < bytes.len() {
        if arc_count >= OID_MAX_ARCS {
            return Err(ASN1(ASN1Error::InvalidOid));
        }
        arcs[arc_count] = decode_base128(bytes, &mut pos, bytes.len())?;
        arc_count += 1;
    }

    Ok(Oid {
        arcs,
        len: arc_count,
    })
}
