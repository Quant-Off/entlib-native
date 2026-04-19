use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use entlib_native_base::error::hash::HashError;
use entlib_native_secure_buffer::SecureBuffer;

use crate::{Blake2b, Blake3};

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

pub mod blake2b {
    use super::*;

    pub fn hash_reader<R: Read>(reader: &mut R, output_len: usize) -> Result<SecureBuffer, FileHashError> {
        let mut hasher = Blake2b::new(output_len);
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

    pub fn hash_file<P: AsRef<Path>>(path: P, output_len: usize) -> Result<SecureBuffer, FileHashError> {
        let mut file = File::open(path)?;
        hash_reader(&mut file, output_len)
    }
}

pub mod blake3 {
    use super::*;

    pub fn hash_reader<R: Read>(reader: &mut R, output_len: usize) -> Result<SecureBuffer, FileHashError> {
        let mut hasher = Blake3::new();
        let mut buf = [0u8; BUF_SIZE];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hasher.finalize_xof(output_len)?)
    }

    pub fn hash_file<P: AsRef<Path>>(path: P, output_len: usize) -> Result<SecureBuffer, FileHashError> {
        let mut file = File::open(path)?;
        hash_reader(&mut file, output_len)
    }
}
