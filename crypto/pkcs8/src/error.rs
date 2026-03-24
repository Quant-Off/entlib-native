use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pkcs8Error {
    InvalidAlgorithm,
    KdfFailed,
    EncryptionFailed,
    DecryptionFailed,
    AuthenticationFailed,
    DerEncodingFailed,
    DerDecodingFailed,
    PemEncodingFailed,
    PemDecodingFailed,
    InvalidStructure,
    UnknownAlgorithm,
    AllocationFailed,
}

impl fmt::Display for Pkcs8Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAlgorithm => write!(f, "알 수 없는 알고리즘"),
            Self::KdfFailed => write!(f, "KDF 오류"),
            Self::EncryptionFailed => write!(f, "암호화 오류"),
            Self::DecryptionFailed => write!(f, "복호화 오류"),
            Self::AuthenticationFailed => write!(f, "인증 태그 검증 실패"),
            Self::DerEncodingFailed => write!(f, "DER 인코딩 오류"),
            Self::DerDecodingFailed => write!(f, "DER 디코딩 오류"),
            Self::PemEncodingFailed => write!(f, "PEM 인코딩 오류"),
            Self::PemDecodingFailed => write!(f, "PEM 디코딩 오류"),
            Self::InvalidStructure => write!(f, "잘못된 구조"),
            Self::UnknownAlgorithm => write!(f, "알 수 없는 알고리즘 OID"),
            Self::AllocationFailed => write!(f, "메모리 할당 실패"),
        }
    }
}
