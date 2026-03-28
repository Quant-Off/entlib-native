/// FFI 경계를 넘어 전달될 수 있는 C 호환 에러 코드 열거형입니다.
/// 메시지는 모호하게 유지되며, 구체적인 실패 원인은 내부 로그(보안 감사용)로만 남겨야 합니다.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EntLibState {
    /// 과정 또는 결과 표현이 성공했습니다.
    Success = 0,

    /// 모듈 상태 오류 (Module State Error)
    /// 모듈이 초기화되지 않았거나, POST(자가 진단)가 실패하여
    /// '에러 상태(Error State)'에 진입했을 때 발생합니다. 이 상태에서는 모든 암호 연산이 차단되어야 합니다.
    StateError = 1,

    /// 유효하지 않은 입력 (Invalid Input)
    /// 키 길이 불일치, 포맷 오류, 범위를 벗어난 매개변수 등 입력값 검증 실패 시 반환됩니다.
    /// "어떤" 값이 "왜" 틀렸는지는 절대 반환하지 않습니다.
    InvalidInput = 2,

    /// 암호 연산 실패 (Cryptographic Operation Failed)
    /// 서명 검증 실패, MAC 불일치, 복호화 실패 등 알고리즘 수행 중 발생한 논리적 오류입니다.
    /// 타이밍 공격을 막기 위해 상수-시간(Constant-Time) 검증이 끝난 후 일괄적으로 이 에러를 반환해야 합니다.
    OperationFailed = 3,

    /// 리소스 및 환경 오류 (Resource/Environment Error)
    /// OS 메모리 할당 실패, 난수 발생기(RNG) 엔트로피 부족,
    /// 또는 외부 주입 메모리의 페이지 정렬(Alignment) 검증 실패 시 발생합니다.
    ResourceError = 4,

    /// 내부 패닉 및 치명적 예외 (Fatal Error)
    /// Rust 내부에서 `panic!`이 발생했거나 복구할 수 없는 하드웨어 결함이 감지되었을 때 반환됩니다.
    FatalError = 5,
}

/// 개별 크레이트의 상세 에러를 FFI 경계용 모호한 에러로 변환하는 트레이트입니다.
pub trait ToExternalError {
    /// 상세 에러를 FIPS 요구사항에 맞는 안전한 에러 코드로 변환합니다.
    fn to_fips_error(&self) -> EntLibState;

    /// (선택적) CC EAL4+ 인증을 위해 내부 보안 감사 로그(Audit Log)에
    /// 상세 에러 원인을 기록하는 기본 메서드를 제공할 수 있습니다.
    fn log_security_audit(&self) {
        // TODO: 내부 로깅 시스템 호출 (예: tracing, log 크레이트 연동)
        //       외부(Java)로는 절대 전달되지 않는 안전한 영역임.
    }
}

pub mod hash {
    use crate::error::secure_buffer::SecureBufferError;
    use crate::error::{EntLibState, ToExternalError};

    #[derive(Debug)]
    pub enum HashError {
        InvalidOutputLength,
        Buffer(SecureBufferError),
    }

    impl core::fmt::Display for HashError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                HashError::InvalidOutputLength => f.write_str("invalid output length"),
                HashError::Buffer(e) => write!(f, "{}", e),
            }
        }
    }

    impl core::error::Error for HashError {}

    impl From<SecureBufferError> for HashError {
        fn from(e: SecureBufferError) -> Self {
            HashError::Buffer(e)
        }
    }

    impl ToExternalError for HashError {
        fn to_fips_error(&self) -> EntLibState {
            match self {
                HashError::InvalidOutputLength => EntLibState::InvalidInput,
                HashError::Buffer(e) => e.to_fips_error(),
            }
        }
    }
}

pub mod argon2id {
    use crate::error::hash::HashError;
    use crate::error::secure_buffer::SecureBufferError;
    use crate::error::{EntLibState, ToExternalError};

    #[derive(Debug)]
    pub enum Argon2idError {
        InvalidParameter,
        Hash(HashError),
        Buffer(SecureBufferError),
    }

    impl core::fmt::Display for Argon2idError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Argon2idError::InvalidParameter => f.write_str("invalid parameter"),
                Argon2idError::Hash(e) => write!(f, "{}", e),
                Argon2idError::Buffer(e) => write!(f, "{}", e),
            }
        }
    }

    impl core::error::Error for Argon2idError {}

    impl From<HashError> for Argon2idError {
        fn from(e: HashError) -> Self {
            Argon2idError::Hash(e)
        }
    }

    impl From<SecureBufferError> for Argon2idError {
        fn from(e: SecureBufferError) -> Self {
            Argon2idError::Buffer(e)
        }
    }

    impl ToExternalError for Argon2idError {
        fn to_fips_error(&self) -> EntLibState {
            match self {
                Argon2idError::InvalidParameter => EntLibState::InvalidInput,
                Argon2idError::Hash(e) => e.to_fips_error(),
                Argon2idError::Buffer(e) => e.to_fips_error(),
            }
        }
    }
}

pub mod secure_buffer {
    use crate::error::{EntLibState, ToExternalError};

    #[derive(Debug)]
    pub enum SecureBufferError {
        AllocationFailed,
        InvalidLayout,
        MemoryLockFailed,
        PageAlignmentViolation,
    }

    impl core::fmt::Display for SecureBufferError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                SecureBufferError::AllocationFailed => f.write_str("allocation failed"),
                SecureBufferError::InvalidLayout => f.write_str("invalid layout"),
                SecureBufferError::MemoryLockFailed => f.write_str("memory lock failed"),
                SecureBufferError::PageAlignmentViolation => {
                    f.write_str("page alignment violation")
                }
            }
        }
    }

    impl core::error::Error for SecureBufferError {}

    impl ToExternalError for SecureBufferError {
        fn to_fips_error(&self) -> EntLibState {
            match self {
                SecureBufferError::AllocationFailed
                | SecureBufferError::InvalidLayout
                | SecureBufferError::MemoryLockFailed => EntLibState::ResourceError,
                SecureBufferError::PageAlignmentViolation => EntLibState::InvalidInput,
            }
        }
    }
}

pub mod rng {
    use crate::error::secure_buffer::SecureBufferError;
    use crate::error::{EntLibState, ToExternalError};

    #[derive(Debug)]
    pub enum RngError {
        OsKernelError,
        EntropySourceEof,
        SizeLimitExceeded,
        InvalidAlignment,
        HardwareEntropyExhausted,
        InsufficientEntropy,
        Buffer(SecureBufferError),
    }

    impl From<SecureBufferError> for RngError {
        fn from(e: SecureBufferError) -> Self {
            RngError::Buffer(e)
        }
    }

    impl ToExternalError for RngError {
        fn to_fips_error(&self) -> EntLibState {
            match self {
                RngError::SizeLimitExceeded
                | RngError::InvalidAlignment
                | RngError::InsufficientEntropy => EntLibState::InvalidInput,
                RngError::OsKernelError
                | RngError::EntropySourceEof
                | RngError::HardwareEntropyExhausted => EntLibState::ResourceError,
                RngError::Buffer(e) => e.to_fips_error(),
            }
        }
    }
}

pub mod hex {
    use crate::error::secure_buffer::SecureBufferError;
    use crate::error::{EntLibState, ToExternalError};

    #[derive(Debug)]
    pub enum HexError {
        IllegalCharacter,
        Buffer(SecureBufferError),
    }

    impl core::fmt::Display for HexError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                HexError::IllegalCharacter => f.write_str("illegal character"),
                HexError::Buffer(e) => write!(f, "{}", e),
            }
        }
    }

    impl core::error::Error for HexError {}

    impl From<SecureBufferError> for HexError {
        fn from(e: SecureBufferError) -> Self {
            HexError::Buffer(e)
        }
    }

    impl ToExternalError for HexError {
        fn to_fips_error(&self) -> EntLibState {
            match self {
                HexError::IllegalCharacter => EntLibState::InvalidInput,
                HexError::Buffer(e) => e.to_fips_error(),
            }
        }
    }
}

pub mod base64 {
    use crate::error::secure_buffer::SecureBufferError;
    use crate::error::{EntLibState, ToExternalError};

    #[derive(Debug)]
    pub enum Base64Error {
        InvalidLength,
        IllegalCharacterOrPadding,
        Buffer(SecureBufferError),
    }

    impl core::fmt::Display for Base64Error {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Base64Error::InvalidLength => f.write_str("invalid length"),
                Base64Error::IllegalCharacterOrPadding => {
                    f.write_str("illegal character or padding")
                }
                Base64Error::Buffer(e) => write!(f, "{}", e),
            }
        }
    }

    impl core::error::Error for Base64Error {}

    impl From<SecureBufferError> for Base64Error {
        fn from(e: SecureBufferError) -> Self {
            Base64Error::Buffer(e)
        }
    }

    impl ToExternalError for Base64Error {
        fn to_fips_error(&self) -> EntLibState {
            match self {
                Base64Error::InvalidLength | Base64Error::IllegalCharacterOrPadding => {
                    EntLibState::InvalidInput
                }
                Base64Error::Buffer(e) => e.to_fips_error(),
            }
        }
    }
}

pub mod mldsa {
    use crate::error::hash::HashError;
    use crate::error::secure_buffer::SecureBufferError;
    use crate::error::{EntLibState, ToExternalError};

    #[derive(Debug)]
    pub enum MLDSAError {
        /// 입력 바이트 슬라이스의 길이가 요구사항과 일치하지 않습니다.
        InvalidLength,
        /// 내부 연산 실패 (예: 해시 함수 오류, 메모리 할당 실패)
        InternalError,
        /// 난수 생성기(RNG) 오류
        RngError,
        /// ctx(컨텍스트) 길이가 FIPS 204 제한(255바이트)을 초과합니다.
        ContextTooLong,
        /// 서명 시도가 최대 반복 횟수를 초과하였습니다 (극히 희박한 경우).
        SigningFailed,
        /// 서명 검증 실패
        InvalidSignature,
        /// 아직 구현되지 않은 기능입니다.
        NotImplemented,
        /// 내부 해시 연산 실패
        Hash(HashError),
        /// SecureBuffer 할당 실패
        Buffer(SecureBufferError),
    }

    impl ToExternalError for MLDSAError {
        fn to_fips_error(&self) -> EntLibState {
            match self {
                MLDSAError::InvalidLength | MLDSAError::ContextTooLong => EntLibState::InvalidInput,

                MLDSAError::InvalidSignature | MLDSAError::SigningFailed | MLDSAError::Hash(_) => {
                    EntLibState::OperationFailed
                }

                MLDSAError::RngError | MLDSAError::Buffer(_) => EntLibState::ResourceError,

                MLDSAError::InternalError | MLDSAError::NotImplemented => EntLibState::FatalError,
            }
        }
    }

    impl From<HashError> for MLDSAError {
        fn from(e: HashError) -> Self {
            MLDSAError::Hash(e)
        }
    }

    impl From<SecureBufferError> for MLDSAError {
        fn from(e: SecureBufferError) -> Self {
            MLDSAError::Buffer(e)
        }
    }
}
