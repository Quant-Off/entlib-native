//! DER 파싱·인코딩 오류 타입 모듈입니다.

/// DER 파싱 및 인코딩 중 발생하는 오류 열거형입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerError {
    /// 입력 버퍼가 예상보다 짧음
    UnexpectedEof,
    /// 유효하지 않은 태그 바이트 (EOC, 장형식 태그 등)
    InvalidTag,
    /// 유효하지 않은 길이 인코딩
    InvalidLength,
    /// 부정길이(Indefinite-Length) 형식 거부 — BER 전용
    IndefiniteLength,
    /// 비최소 길이 인코딩 (DER 위반)
    NonMinimalLength,
    /// 비최소 INTEGER 인코딩 (불필요한 선행 0x00/0xFF 바이트)
    NonMinimalInteger,
    /// BOOLEAN 값이 0x00 또는 0xFF가 아님 (DER 위반)
    InvalidBooleanEncoding,
    /// BIT STRING의 미사용 비트 수가 0-7 범위를 벗어남
    InvalidBitString,
    /// 유효하지 않은 OID 인코딩 또는 구조
    InvalidOid,
    /// 예상한 태그와 실제 태그가 불일치
    UnexpectedTag { expected: u8, got: u8 },
    /// 길이 계산 시 산술 오버플로우
    LengthOverflow,
    /// 최대 중첩 깊이 초과 — 재귀 폭탄 방지
    MaxDepthExceeded,
    /// 파싱 완료 후 잔여 바이트 존재
    TrailingData,
    /// 빈 입력
    EmptyInput,
    /// SecureBuffer 할당 실패
    AllocationError,
}
