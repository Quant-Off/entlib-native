//! ANU QRNG API(Streaming)
//!
//! # Secure Warning
//! TLS통신을 통해 작업을 수행하기 때문에
//! 네트워크 지연 등의 문제가 있습니다.
//!
//! # Author
//! Q. T. Felix

use crate::base_rng::RngError;
use entlib_native_core_secure::secure_buffer::SecureBuffer;
use std::process::Stdio;
use std::str;
use std::vec::Vec;
use tokio::process::Command;

pub struct AnuQrngClient;

impl AnuQrngClient {
    pub async fn fetch_secure_bytes(length: usize) -> Result<SecureBuffer, RngError> {
        if !(1..=1024).contains(&length) {
            return Err(RngError::ParseError);
        }

        let url = format!(
            "https://api.quantumnumbers.anu.edu.au?length={}&type=uint8",
            length
        );

        let output = Command::new("curl")
            .arg("-sS") // silent (진행률 숨김) + 오류 메시지 표시
            .arg("-f") // HTTP 오류 시 실패
            .arg("-L") // 리다이렉트 추적
            .arg("-X")
            .arg("GET")
            .arg("-H")
            .arg(format!(
                "x-api-key:{}",
                std::env::var("QRNG_ANU_KEY").expect("QRNG_ANU_KEY must be set")
            ))
            .arg("--connect-timeout")
            .arg("10") // 연결 타임아웃: 10초
            .arg("--max-time")
            .arg("30") // 전체 요청 타임아웃: 30초
            .arg(url)
            .stdin(Stdio::null()) // JVM FFI 컨텍스트에서의 stdin 상속 차단
            .output()
            .await
            .map_err(|e| RngError::NetworkFailure(format!("curl 실행 실패: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(RngError::NetworkFailure(format!(
                "HTTP 실패 (code: {}) | stderr: {}",
                output.status,
                stderr.trim()
            )));
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
