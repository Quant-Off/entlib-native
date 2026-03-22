#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmorError {
    ASN1(crate::asn1::ASN1Error),
    DER(crate::der::DerError),
}
