//! ANU QRNG API(Streaming)
//!
//! TLS통신을 통해 작업을 수행하기 떄문에
//! 네트워크 지연 등의 문제가 있습니다.
//!
//! # Author
//! Q. T. Felix

use crate::base_rng::RngError;
use entlib_native_core_secure::secure_buffer::SecureBuffer;
use std::process::Command;
use std::str;
use std::vec::Vec;

pub struct AnuQrngClient;

impl AnuQrngClient {
    pub fn fetch_secure_bytes(length: usize) -> Result<SecureBuffer, RngError> {
        if !(1..=1024).contains(&length) {
            return Err(RngError::ParseError);
        }

        let url = format!(
            "https://qrng.anu.edu.au/API/jsonI.php?length={}&type=uint8",
            length
        );

        // -f (HTTP 오류 시 실패), -L (리다이렉트 추적)
        let output = Command::new("curl")
            .arg("-s")
            .arg("-f")
            .arg("-L")
            .arg(url)
            .output()
            .map_err(|_| RngError::NetworkFailure)?;

        if !output.status.success() {
            return Err(RngError::NetworkFailure);
        }

        let response_str = str::from_utf8(&output.stdout).map_err(|_| RngError::ParseError)?;

        let bytes = Self::parse_json_data(response_str)?;

        Ok(SecureBuffer { inner: bytes })
    }

    /// 공백 및 포맷 변경에 강건하게 대응하는 개선된 슬라이싱 파서
    pub fn parse_json_data(json: &str) -> Result<Vec<u8>, RngError> {
        let data_key = "\"data\"";

        // "data" 키의 시작 위치 탐색
        let key_idx = json.find(data_key).ok_or(RngError::ParseError)?;

        // 키 이후부터 첫 번째 '[' 탐색
        let start_bracket = json[key_idx..].find('[').ok_or(RngError::ParseError)? + key_idx + 1;

        // '[' 이후부터 첫 번째 ']' 탐색
        let end_bracket = json[start_bracket..]
            .find(']')
            .ok_or(RngError::ParseError)?
            + start_bracket;

        let data_part = &json[start_bracket..end_bracket];
        let mut bytes = Vec::new();

        for val_str in data_part.split(',') {
            let trimmed = val_str.trim();
            if !trimmed.is_empty() {
                let val = trimmed.parse::<u8>().map_err(|_| RngError::ParseError)?;
                bytes.push(val);
            }
        }

        Ok(bytes)
    }
}
