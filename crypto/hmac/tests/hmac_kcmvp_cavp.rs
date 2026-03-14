#[cfg(test)]
mod kcmvp_cavp_test {
    use std::fs::File;
    use std::io::{BufRead, BufReader, BufWriter, Write};
    use std::path::Path;

    /// 헥스 문자열을 안전하게 바이트 벡터로 변환 (Zero-Trust 원칙 적용)
    fn decode_hex(s: &str) -> Result<Vec<u8>, &'static str> {
        if !s.len().is_multiple_of(2) {
            return Err("Invalid hex string length");
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "Invalid hex character"))
            .collect()
    }

    /// 바이트 슬라이스를 헥스 문자열로 변환
    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// 단일 알고리즘에 대한 CAVP 테스트 벡터 처리기
    /// `compute_mac` 클로저를 통해 구체적인 HMAC 알고리즘을 주입받습니다.
    #[allow(unused_assignments)]
    fn process_cavp_file<F>(req_path: &str, rsp_path: &str, mut compute_mac: F)
    where
        // 입력: key, msg / 출력: Result<전체 MAC 바이트, 에러>
        F: FnMut(&[u8], &[u8]) -> Result<Vec<u8>, &'static str>,
    {
        let req_file = File::open(Path::new(req_path)).expect("Failed to open .req file");
        let rsp_file = File::create(Path::new(rsp_path)).expect("Failed to create .rsp file");

        let reader = BufReader::new(req_file);
        let mut writer = BufWriter::new(rsp_file);

        let mut current_tlen = 0usize;
        let mut current_key = Vec::new();
        let mut current_msg = Vec::new();

        for line_result in reader.lines() {
            let line = line_result.expect("Failed to read line");
            let trimmed = line.trim();

            // 빈 줄이나 대괄호 표기(예: [L=32])는 그대로 출력
            if trimmed.is_empty() || trimmed.starts_with('[') {
                writeln!(writer, "{}", line).unwrap();
                continue;
            }

            // "Key = Value" 형태 파싱
            if let Some((k, v)) = trimmed.split_once('=') {
                let key = k.trim();
                let val = v.trim();

                // 기존 라인 출력 (요청에 맞게 원본 유지)
                writeln!(writer, "{}", line).unwrap();

                match key {
                    "Tlen" => {
                        current_tlen = val.parse::<usize>().expect("Invalid Tlen");
                    }
                    "Key" => {
                        current_key = decode_hex(val).expect("Failed to decode Key");
                    }
                    "Msg" => {
                        current_msg = decode_hex(val).expect("Failed to decode Msg");

                        // Msg 파싱이 완료되면 하나의 테스트 케이스 입력이 모두 준비된 것으로 간주하고 MAC 산출
                        match compute_mac(&current_key, &current_msg) {
                            Ok(full_mac) => {
                                // NIST SP 800-107r1 Tlen (Truncation) 처리
                                // 전체 MAC에서 Tlen 바이트만큼만 잘라내 출력
                                if current_tlen > full_mac.len() {
                                    panic!(
                                        "Tlen cannot be greater than the underlying hash output length"
                                    );
                                }
                                let truncated_mac = &full_mac[..current_tlen];
                                writeln!(writer, "Mac = {}", encode_hex(truncated_mac)).unwrap();
                            }
                            Err(e) => {
                                // 고보안 요구사항 미달 (112bit 미만 키와 같은 이유로) 시 CAVP 테스트에서는
                                // 테스트 벡터 자체의 의도에 따라 처리가 달라질 수 있음
                                // 에러 발생 시 로그를 남기고 스킵하거나 특정 포맷으로 출력
                                writeln!(writer, "MacError = {}", e).unwrap();
                            }
                        }
                    }
                    _ => { /* COUNT, Klen 등은 위에서 원본 라인으로 출력되었으므로 무시 */
                    }
                }
            } else {
                writeln!(writer, "{}", line).unwrap();
            }
        }
    }

    //
    // 실제 테스트 실행부
    //
    #[test]
    fn cavp_hmac_sha256_test() {
        use entlib_native_hmac::{HMACSHA224, HMACSHA256, HMACSHA384, HMACSHA512};

        let dir = match std::env::var("KCMVP_CAVP_DIR") {
            Ok(val) => val,
            Err(_) => panic!("env"),
        };

        process_cavp_file(
            format!(
                "{}/entanglementlib__CAVP_2_20260312205017/HMAC_SHA-224_KAT.req",
                dir
            )
            .as_str(),
            format!(
                "{}/entanglementlib__CAVP_2_20260312205017/HMAC_SHA-224_KAT.rsp",
                dir
            )
            .as_str(),
            |key, msg| {
                // 초기화 시 보안 정책(112bit 미만 차단 등)에 의해 에러가 발생할 수 있음
                let mut hmac = HMACSHA224::new(key).map_err(|_| "HmacInitError")?;
                hmac.update(msg);
                let result = hmac.finalize().map_err(|_| "HmacFinalizeError")?;

                // Const Generics로 구현된 내부 배열(.0)을 복사하여 반환
                Ok(result.0.to_vec())
            },
        );

        process_cavp_file(
            format!(
                "{}/entanglementlib__CAVP_2_20260312205017/HMAC_SHA-256_KAT.req",
                dir
            )
            .as_str(),
            format!(
                "{}/entanglementlib__CAVP_2_20260312205017/HMAC_SHA-256_KAT.rsp",
                dir
            )
            .as_str(),
            |key, msg| {
                // 초기화 시 보안 정책(112bit 미만 차단 등)에 의해 에러가 발생할 수 있음
                let mut hmac = HMACSHA256::new(key).map_err(|_| "HmacInitError")?;
                hmac.update(msg);
                let result = hmac.finalize().map_err(|_| "HmacFinalizeError")?;

                // Const Generics로 구현된 내부 배열(.0)을 복사하여 반환
                Ok(result.0.to_vec())
            },
        );

        process_cavp_file(
            format!(
                "{}/entanglementlib__CAVP_2_20260312205017/HMAC_SHA-384_KAT.req",
                dir
            )
            .as_str(),
            format!(
                "{}/entanglementlib__CAVP_2_20260312205017/HMAC_SHA-384_KAT.rsp",
                dir
            )
            .as_str(),
            |key, msg| {
                // 초기화 시 보안 정책(112bit 미만 차단 등)에 의해 에러가 발생할 수 있음
                let mut hmac = HMACSHA384::new(key).map_err(|_| "HmacInitError")?;
                hmac.update(msg);
                let result = hmac.finalize().map_err(|_| "HmacFinalizeError")?;

                // Const Generics로 구현된 내부 배열(.0)을 복사하여 반환
                Ok(result.0.to_vec())
            },
        );

        process_cavp_file(
            format!(
                "{}/entanglementlib__CAVP_2_20260312205017/HMAC_SHA-512_KAT.req",
                dir
            )
            .as_str(),
            format!(
                "{}/entanglementlib__CAVP_2_20260312205017/HMAC_SHA-512_KAT.rsp",
                dir
            )
            .as_str(),
            |key, msg| {
                // 초기화 시 보안 정책(112bit 미만 차단 등)에 의해 에러가 발생할 수 있음
                let mut hmac = HMACSHA512::new(key).map_err(|_| "HmacInitError")?;
                hmac.update(msg);
                let result = hmac.finalize().map_err(|_| "HmacFinalizeError")?;

                // Const Generics로 구현된 내부 배열(.0)을 복사하여 반환
                Ok(result.0.to_vec())
            },
        );
    }
}
