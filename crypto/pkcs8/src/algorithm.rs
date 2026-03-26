use crate::error::Pkcs8Error;
use crate::oid;
use entlib_native_armor::asn1::Oid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    MLDSA44,
    MLDSA65,
    MLDSA87,
    MLKEM512,
    MLKEM768,
    MLKEM1024,
}

impl Algorithm {
    pub fn oid(&self) -> Oid {
        match self {
            Self::MLDSA44 => oid::oid_mldsa44(),
            Self::MLDSA65 => oid::oid_mldsa65(),
            Self::MLDSA87 => oid::oid_mldsa87(),
            Self::MLKEM512 => oid::oid_mlkem512(),
            Self::MLKEM768 => oid::oid_mlkem768(),
            Self::MLKEM1024 => oid::oid_mlkem1024(),
        }
    }

    pub fn from_oid(oid: &Oid) -> Result<Self, Pkcs8Error> {
        if oid.ct_eq(&oid::oid_mldsa44()) {
            Ok(Self::MLDSA44)
        } else if oid.ct_eq(&oid::oid_mldsa65()) {
            Ok(Self::MLDSA65)
        } else if oid.ct_eq(&oid::oid_mldsa87()) {
            Ok(Self::MLDSA87)
        } else if oid.ct_eq(&oid::oid_mlkem512()) {
            Ok(Self::MLKEM512)
        } else if oid.ct_eq(&oid::oid_mlkem768()) {
            Ok(Self::MLKEM768)
        } else if oid.ct_eq(&oid::oid_mlkem1024()) {
            Ok(Self::MLKEM1024)
        } else {
            Err(Pkcs8Error::UnknownAlgorithm)
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::MLDSA44 => "ml-dsa-44",
            Self::MLDSA65 => "ml-dsa-65",
            Self::MLDSA87 => "ml-dsa-87",
            Self::MLKEM512 => "ml-kem-512",
            Self::MLKEM768 => "ml-kem-768",
            Self::MLKEM1024 => "ml-kem-1024",
        }
    }

    pub fn from_name(s: &str) -> Result<Self, Pkcs8Error> {
        match s {
            "ml-dsa-44" | "mldsa44" | "ML-DSA-44" => Ok(Self::MLDSA44),
            "ml-dsa-65" | "mldsa65" | "ML-DSA-65" => Ok(Self::MLDSA65),
            "ml-dsa-87" | "mldsa87" | "ML-DSA-87" => Ok(Self::MLDSA87),
            "ml-kem-512" | "mlkem512" | "ML-KEM-512" => Ok(Self::MLKEM512),
            "ml-kem-768" | "mlkem768" | "ML-KEM-768" => Ok(Self::MLKEM768),
            "ml-kem-1024" | "mlkem1024" | "ML-KEM-1024" => Ok(Self::MLKEM1024),
            _ => Err(Pkcs8Error::InvalidAlgorithm),
        }
    }
}
