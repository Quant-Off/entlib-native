//! PEM 레이블 허용 목록 모듈입니다.

use super::error::PemError;
use crate::error::ArmorError;
use crate::error::ArmorError::PEM;

/// 파이프라인 보안 정책에 따라 허용된 PEM 레이블 열거형입니다.
///
/// # Security Note
/// 허용 목록 외 레이블은 즉시 `UnknownLabel`로 거부합니다.
/// 암호화되지 않은 개인 키(`PRIVATE KEY`)는 의도적으로 제외됩니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PemLabel {
    /// PKCS#8 EncryptedPrivateKeyInfo (RFC 5958) — 암호화된 개인 키
    EncryptedPrivateKey,
    /// X.509 인증서 (RFC 5280)
    Certificate, // todo: 크레이트 격리
    /// SubjectPublicKeyInfo (RFC 5480)
    PublicKey,
    /// PKCS#10 인증서 서명 요청 (RFC 2986)
    CertificateRequest,
}

impl PemLabel {
    pub(crate) fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::EncryptedPrivateKey => b"ENCRYPTED PRIVATE KEY",
            Self::Certificate => b"CERTIFICATE",  // todo: 크레이트 격리
            Self::PublicKey => b"PUBLIC KEY",
            Self::CertificateRequest => b"CERTIFICATE REQUEST",
        }
    }

    pub(crate) fn from_bytes(label: &[u8]) -> Result<Self, ArmorError> {
        match label {
            b"ENCRYPTED PRIVATE KEY" => Ok(Self::EncryptedPrivateKey),
            b"CERTIFICATE" => Ok(Self::Certificate), // todo: 크레이트 격리
            b"PUBLIC KEY" => Ok(Self::PublicKey),
            b"CERTIFICATE REQUEST" => Ok(Self::CertificateRequest),
            _ => Err(PEM(PemError::UnknownLabel)),
        }
    }
}
