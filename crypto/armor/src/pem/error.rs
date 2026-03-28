//! PEM 오류 타입 모듈입니다.

/// PEM 인코딩/디코딩 중 발생하는 오류 열거형입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PemError {
    /// `-----BEGIN ...-----` 줄을 찾을 수 없음
    MissingHeader,
    /// `-----END ...-----` 줄을 찾을 수 없음
    MissingFooter,
    /// 헤더 형식 위반
    InvalidHeader,
    /// 푸터 형식 위반
    InvalidFooter,
    /// BEGIN과 END 레이블 불일치
    LabelMismatch,
    /// 허용 목록에 없는 레이블
    UnknownLabel,
    /// 유효하지 않은 Base64 인코딩
    Base64Error,
    /// Base64 본문이 없음
    EmptyBody,
    /// 유효하지 않은 DER 외곽 구조
    InvalidDer,
    /// SecureBuffer 할당 실패
    AllocationError,
}
