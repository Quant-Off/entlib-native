//! DER 봉투 검증 필터 모듈입니다.

use super::error::PemError;
use crate::der::DerReader;
use crate::error::ArmorError;
use crate::error::ArmorError::PEM;

/// DER 최상위 TLV 구조를 검증하는 함수입니다.
///
/// # Security Note
/// 정확히 하나의 완전한 TLV를 강제하여 절단 페이로드와
/// 트레일링 데이터를 거부합니다. DER 파서의 검증 로직을 재사용합니다.
pub(crate) fn validate_der_envelope(der: &[u8]) -> Result<(), ArmorError> {
    let mut reader = DerReader::new(der).map_err(|_| PEM(PemError::InvalidDer))?;
    reader.read_tlv().map_err(|_| PEM(PemError::InvalidDer))?;
    reader
        .expect_empty()
        .map_err(|_| PEM(PemError::InvalidDer))?;
    Ok(())
}
