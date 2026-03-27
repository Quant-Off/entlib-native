use entlib_native_base::error::hash::HashError;
use entlib_native_base::error::secure_buffer::SecureBufferError;

#[derive(Debug)]
pub enum MLKEMError {
    InvalidLength,
    InternalError,
    RngError,
    InvalidEncapsulationKey,
    InvalidDecapsulationKey,
    NotImplemented,
    Hash(HashError),
    Buffer(SecureBufferError),
}

impl From<HashError> for MLKEMError {
    fn from(e: HashError) -> Self {
        MLKEMError::Hash(e)
    }
}

impl From<SecureBufferError> for MLKEMError {
    fn from(e: SecureBufferError) -> Self {
        MLKEMError::Buffer(e)
    }
}
