// mod 오 에러 정의하는것보단 enum이 괜찮을 듯

#[derive(Debug)]
pub enum MLDSAError {
    /// 입력 바이트 슬라이스의 길이가 요구사항과 일치하지 않습니다.
    InvalidLength(&'static str),
    /// 내부 연산 실패 (예: 해시 함수 오류, 메모리 할당 실패)
    InternalError(&'static str),
    /// 난수 생성기(RNG) 오류
    RngError(&'static str),
    /// ctx(컨텍스트) 길이가 FIPS 204 제한(255바이트)을 초과합니다.
    ContextTooLong,
    /// 서명 시도가 최대 반복 횟수를 초과하였습니다 (극히 희박한 경우).
    SigningFailed,
    /// 서명 검증 실패
    InvalidSignature,
    /// 아직 구현되지 않은 기능입니다.
    NotImplemented(&'static str),
}

impl From<&'static str> for MLDSAError {
    fn from(s: &'static str) -> Self {
        MLDSAError::InternalError(s)
    }
}
