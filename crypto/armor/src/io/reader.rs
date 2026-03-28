//! DER/PEM 파일 읽기 모듈입니다.

use super::error::IoError;
use crate::error::ArmorError;
use crate::error::ArmorError::IO;
use crate::pem::{PemLabel, decode as pem_decode};
use entlib_native_secure_buffer::SecureBuffer;
use std::fs;
use std::path::Path;

/// 파일 최대 읽기 크기 (1 MiB) — DoS 방어
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// DER 파일을 읽어 SecureBuffer로 반환하는 함수입니다.
///
/// # Security Note
/// 파일 크기를 1 MiB로 제한하여 메모리 고갈 공격을 방어합니다.
/// 결과는 SecureBuffer(mlock)에 보관됩니다.
///
/// # Errors
/// `InvalidPath`, `FileNotFound`, `PermissionDenied`, `FileTooLarge`,
/// `ReadFailed`, `AllocationError`
pub fn read_der(path: &Path) -> Result<SecureBuffer, ArmorError> {
    validate_path(path)?;
    let bytes = read_file_bounded(path)?;
    Ok(bytes)
}

/// PEM 파일을 읽어 레이블과 DER SecureBuffer를 반환하는 함수입니다.
///
/// # Security Note
/// 파일 크기를 1 MiB로 제한합니다.
/// PEM 디코딩 후 DER 외곽 TLV 구조와 레이블 허용 목록을 검증합니다.
///
/// # Errors
/// `InvalidPath`, `FileNotFound`, `PermissionDenied`, `FileTooLarge`,
/// `ReadFailed`, `AllocationError`, 그리고 PEM 파싱 오류
pub fn read_pem(path: &Path) -> Result<(PemLabel, SecureBuffer), ArmorError> {
    validate_path(path)?;
    let raw = read_file_bounded(path)?;
    pem_decode(raw.as_slice())
}

fn validate_path(path: &Path) -> Result<(), ArmorError> {
    let s = path.as_os_str().as_encoded_bytes();
    if s.is_empty() {
        return Err(IO(IoError::InvalidPath));
    }
    if s.contains(&0u8) {
        return Err(IO(IoError::InvalidPath));
    }
    Ok(())
}

fn read_file_bounded(path: &Path) -> Result<SecureBuffer, ArmorError> {
    let meta = fs::metadata(path).map_err(map_read_error)?;

    if meta.len() > MAX_FILE_BYTES {
        return Err(IO(IoError::FileTooLarge));
    }

    let len = meta.len() as usize;
    let content = fs::read(path).map_err(map_read_error)?;

    let mut buf = SecureBuffer::new_owned(len).map_err(|_| IO(IoError::AllocationError))?;
    buf.as_mut_slice().copy_from_slice(&content);
    Ok(buf)
}

fn map_read_error(e: std::io::Error) -> ArmorError {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::NotFound => IO(IoError::FileNotFound),
        ErrorKind::PermissionDenied => IO(IoError::PermissionDenied),
        _ => IO(IoError::ReadFailed),
    }
}
