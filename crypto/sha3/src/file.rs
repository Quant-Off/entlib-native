use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use entlib_native_base::error::hash::HashError;
use entlib_native_secure_buffer::SecureBuffer;

use crate::api::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};

const BUF_SIZE: usize = 8192;

#[derive(Debug)]
pub enum FileHashError {
    Io(io::Error),
    Hash(HashError),
}

impl From<io::Error> for FileHashError {
    fn from(e: io::Error) -> Self {
        FileHashError::Io(e)
    }
}

impl From<HashError> for FileHashError {
    fn from(e: HashError) -> Self {
        FileHashError::Hash(e)
    }
}

impl core::fmt::Display for FileHashError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FileHashError::Io(e) => write!(f, "{}", e),
            FileHashError::Hash(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for FileHashError {}

macro_rules! impl_file_hash {
    ($struct_name:ident, $mod_name:ident) => {
        pub mod $mod_name {
            use super::*;

            pub fn hash_reader<R: Read>(reader: &mut R) -> Result<SecureBuffer, FileHashError> {
                let mut hasher = $struct_name::new();
                let mut buf = [0u8; BUF_SIZE];
                loop {
                    let n = reader.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                Ok(hasher.finalize()?)
            }

            pub fn hash_file<P: AsRef<Path>>(path: P) -> Result<SecureBuffer, FileHashError> {
                let mut file = File::open(path)?;
                hash_reader(&mut file)
            }
        }
    };
}

impl_file_hash!(SHA3_224, sha3_224);
impl_file_hash!(SHA3_256, sha3_256);
impl_file_hash!(SHA3_384, sha3_384);
impl_file_hash!(SHA3_512, sha3_512);
