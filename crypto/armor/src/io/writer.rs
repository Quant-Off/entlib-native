//! DER/PEM 파일 쓰기 모듈입니다.
//!
//! RFC 7468 표준을 준수하는 PEM 출력과 원자적 파일 교체를 구현합니다.

use super::error::IoError;
use crate::error::ArmorError;
use crate::error::ArmorError::IO;
use crate::pem::{PemLabel, encode as pem_encode};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// DER 바이트열을 파일에 쓰는 함수입니다.
///
/// # Security Note
/// Unix에서 파일 권한을 `0o600`(소유자 읽기/쓰기 전용)으로 설정합니다.
/// 임시 파일에 먼저 쓰고 원자적으로 교체하여 부분 기록을 방지합니다.
///
/// # Errors
/// `InvalidPath`, `WriteFailed`, `AtomicRenameFailed`
pub fn write_der(path: &Path, der: &[u8]) -> Result<(), ArmorError> {
    validate_path(path)?;
    write_atomic(path, der)
}

/// DER 바이트열을 RFC 7468 PEM 형식으로 파일에 쓰는 함수입니다.
///
/// # Security Note
/// PEM 인코딩 전 DER 외곽 TLV 구조를 검증합니다.
/// Unix에서 파일 권한을 `0o600`으로 설정합니다.
/// 원자적 파일 교체로 부분 기록을 방지합니다.
///
/// # Errors
/// `InvalidPath`, `WriteFailed`, `AtomicRenameFailed`, PEM 인코딩 오류
pub fn write_pem(path: &Path, der: &[u8], label: PemLabel) -> Result<(), ArmorError> {
    validate_path(path)?;
    let pem_buf = pem_encode(der, label)?;
    write_atomic(path, pem_buf.as_slice())
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

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), ArmorError> {
    let parent = path.parent().ok_or(IO(IoError::InvalidPath))?;
    let file_name = path.file_name().ok_or(IO(IoError::InvalidPath))?;

    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(".tmp");
    let tmp_path = parent.join(tmp_name);

    {
        let mut file = create_secure_file(&tmp_path).map_err(|_| IO(IoError::WriteFailed))?;
        file.write_all(data).map_err(|_| IO(IoError::WriteFailed))?;
        file.flush().map_err(|_| IO(IoError::WriteFailed))?;
        // file closed here — OS flushes buffers
    }

    fs::rename(&tmp_path, path).map_err(|_| {
        // 최선 시도: 임시 파일 정리
        let _ = fs::remove_file(&tmp_path);
        IO(IoError::AtomicRenameFailed)
    })?;

    Ok(())
}

#[cfg(unix)]
fn create_secure_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_secure_file(path: &Path) -> std::io::Result<std::fs::File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}
