#[derive(Debug)]
pub enum MLKEMError {
    InvalidLength(&'static str),
    InternalError(&'static str),
    RngError(&'static str),
    InvalidEncapsulationKey,
    InvalidDecapsulationKey,
    NotImplemented(&'static str),
}

impl From<&'static str> for MLKEMError {
    fn from(s: &'static str) -> Self {
        MLKEMError::InternalError(s)
    }
}
