//! ArmorError 통합 오류 타입 모듈입니다.

/// armor 크레이트 전체 오류 열거형입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmorError {
    ASN1(crate::asn1::ASN1Error),
    DER(crate::der::DerError),
    PEM(crate::pem::PemError),
    #[cfg(feature = "std")]
    IO(crate::io::IoError),
}