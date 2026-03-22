//! AES-256 오류 타입 모듈입니다.

/// AES-256 연산 중 발생할 수 있는 오류 열거형입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AESError {
    /// 키 길이가 256비트(32 bytes)가 아님
    InvalidKeyLength,
    /// GCM 출력 버퍼 부족
    OutputBufferTooSmall,
    /// GCM 태그 검증 실패 또는 CBC HMAC 검증 실패
    AuthenticationFailed,
    /// CBC 입력 형식 오류 (최소 길이 미달 또는 블록 크기 불일치)
    InvalidInputLength,
    /// 내부 오류 (PKCS7 패딩 손상, HMAC 연산 실패 등)
    InternalError,
}
