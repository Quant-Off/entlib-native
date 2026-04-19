//! ASN.1 오류 타입 모듈입니다.

/// ASN.1 관련 연산 중 발생하는 오류 열거형입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ASN1Error {
    /// 입력 버퍼가 예상보다 짧음
    UnexpectedEof,
    /// 유효하지 않은 OID 인코딩 또는 구조
    InvalidOid,
    /// 길이 계산 시 산술 오버플로우
    LengthOverflow,
}
