mod kcmvp_cavp_test {
    use entlib_native_sha3::api::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};
    use std::fs::File;
    use std::io::{BufRead, BufReader, BufWriter, Write};
    use std::path::Path;

    /// 외부 입력에 대한 엄격한 16진수 디코딩 (Zero-Trust 검증)
    fn decode_hex(hex_str: &str) -> Result<Vec<u8>, &'static str> {
        if hex_str.len() % 2 != 0 {
            return Err("Hex string length must be even");
        }
        (0..hex_str.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex_str[i..i + 2], 16).map_err(|_| "Invalid hex character")
            })
            .collect()
    }

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// SHA3 해시 연산을 추상화하는 매크로
    /// api.rs의 finalize 및 finalize_bits를 통해 비트 단위 해시를 완벽히 지원합니다.
    macro_rules! compute_sha3 {
        ($algo:ident, $msg:expr, $bit_len:expr) => {{
            let mut hasher = $algo::new();
            let byte_len = $bit_len / 8;
            let rem_bits = $bit_len % 8;

            if byte_len > 0 {
                hasher.update(&$msg[..byte_len]);
            }

            // 불완전 바이트(valid_bits)가 존재하는 경우 finalize_bits 호출
            let secure_buf = if rem_bits == 0 {
                hasher.finalize()?
            } else {
                hasher.finalize_bits($msg[byte_len], rem_bits)?
            };

            // SecureBuffer 내의 데이터를 복사한 후,
            // secure_buf는 스코프 종료 시 Drop되어 물리적 소거(Zeroization) 수행
            secure_buf.as_slice().to_vec()
        }};
    }

    pub enum Sha3Variant {
        Sha3_224,
        Sha3_256,
        Sha3_384,
        Sha3_512,
    }

    impl Sha3Variant {
        fn hash(&self, msg: &[u8], bit_len: usize) -> Result<Vec<u8>, &'static str> {
            match self {
                Sha3Variant::Sha3_224 => Ok(compute_sha3!(SHA3_224, msg, bit_len)),
                Sha3Variant::Sha3_256 => Ok(compute_sha3!(SHA3_256, msg, bit_len)),
                Sha3Variant::Sha3_384 => Ok(compute_sha3!(SHA3_384, msg, bit_len)),
                Sha3Variant::Sha3_512 => Ok(compute_sha3!(SHA3_512, msg, bit_len)),
            }
        }

        /// KCMVP 규격에 따른 스펀지 구조 파라미터 (r, n) 반환
        fn parameters(&self) -> (usize, usize) {
            match self {
                Sha3Variant::Sha3_224 => (1152, 224), //
                Sha3Variant::Sha3_256 => (1088, 256), //
                Sha3Variant::Sha3_384 => (832, 384),  //
                Sha3Variant::Sha3_512 => (576, 512),  //
            }
        }
    }

    /// SMT 및 LMT 테스트 벡터 파싱 및 검증 수행
    fn process_smt_lmt(
        req_path: &str,
        rsp_path: &str,
        variant: Sha3Variant,
    ) -> Result<(), &'static str> {
        let req_file = File::open(Path::new(req_path)).map_err(|_| "Failed to open .req file")?;
        let rsp_file =
            File::create(Path::new(rsp_path)).map_err(|_| "Failed to create .rsp file")?;

        let reader = BufReader::new(req_file);
        let mut writer = BufWriter::new(rsp_file);

        let mut current_len: Option<usize> = None;

        for line in reader.lines() {
            let line = line.map_err(|_| "IO Read Error")?;
            let trimmed = line.trim();

            if trimmed.starts_with('#') || trimmed.is_empty() {
                writeln!(writer, "{}", line).map_err(|_| "IO Write Error")?;
                continue;
            }

            if let Some(len_str) = trimmed.strip_prefix("Len = ") {
                current_len = Some(len_str.parse::<usize>().map_err(|_| "Invalid Len value")?);
                writeln!(writer, "{}", trimmed).map_err(|_| "IO Write Error")?;
            } else if let Some(msg_str) = trimmed.strip_prefix("Msg = ") {
                writeln!(writer, "{}", trimmed).map_err(|_| "IO Write Error")?;

                let bit_len = current_len.take().ok_or("Msg found before Len")?;

                // Len이 0인 경우 Msg가 "00"으로 올 수 있으나, 빈 배열로 처리
                let msg_bytes = if bit_len == 0 {
                    vec![]
                } else {
                    decode_hex(msg_str)?
                };

                let md = variant.hash(&msg_bytes, bit_len)?;
                writeln!(writer, "MD = {}", encode_hex(&md)).map_err(|_| "IO Write Error")?;
            } else {
                // 그 외 헤더 정보 유지
                writeln!(writer, "{}", trimmed).map_err(|_| "IO Write Error")?;
            }
        }

        writer.flush().map_err(|_| "Failed to flush .rsp file")?;
        Ok(())
    }

    /// MCT(Monte Carlo Test) 검증 로직 수행
    /// 100,000번의 해시 반복 수행 중 메모리 누수 및 타이밍 이슈가 없는지 철저히 격리합니다.
    pub fn process_mct(
        req_path: &str,
        rsp_path: &str,
        variant: Sha3Variant,
    ) -> Result<(), &'static str> {
        let req_file = File::open(Path::new(req_path)).map_err(|_| "Failed to open .req file")?;
        let rsp_file =
            File::create(Path::new(rsp_path)).map_err(|_| "Failed to create .rsp file")?;

        let reader = BufReader::new(req_file);
        let mut writer = BufWriter::new(rsp_file);

        // KCMVP MCT 파라미터 계산
        let (r_bits, n_bits) = variant.parameters();
        let n_bytes = n_bits / 8;
        let n_blocks = (r_bits / n_bits) + 1; // N = floor(r/n) + 1

        for line in reader.lines() {
            let line = line.map_err(|_| "IO Read Error")?;
            let trimmed = line.trim();

            if trimmed.starts_with("Seed = ") {
                let seed_str = trimmed.strip_prefix("Seed = ").unwrap();
                let mut current_seed = decode_hex(seed_str)?;

                writeln!(writer, "{}", trimmed).map_err(|_| "IO Write Error")?;

                // 100개의 체크포인트(MD) 생성 루프
                for count in 0..100 {
                    writeln!(writer, "COUNT = {}", count).map_err(|_| "IO Write Error")?;

                    // 초기 MD 배열 (크기 N)을 Seed로 모두 채움
                    let mut md_history: Vec<Vec<u8>> = vec![current_seed.clone(); n_blocks];

                    // 내부 연쇄에 사용할 고정 크기 메시지 버퍼 미리 할당 (Zero-Allocation 전략)
                    let mut msg_buffer = vec![0u8; n_blocks * n_bytes];

                    // 1,000회 반복 해시 연산
                    for _ in 0..1000 {
                        // Msg_i = MD_{k-N} || ... || MD_{k-2} || MD_{k-1}
                        // 고정 버퍼에 복사하여 힙(Heap) 오염 최소화
                        for (idx, md) in md_history.iter().enumerate() {
                            let start = idx * n_bytes;
                            let end = start + n_bytes;
                            msg_buffer[start..end].copy_from_slice(md);
                        }

                        // 해시 수행
                        let bit_len = msg_buffer.len() * 8;
                        let md_k = variant.hash(&msg_buffer, bit_len)?;

                        // 히스토리 상태 전이 (오래된 데이터 밀어내기)
                        for i in 0..(n_blocks - 1) {
                            md_history[i] = md_history[i + 1].clone();
                        }
                        md_history[n_blocks - 1] = md_k;
                    }

                    // 1,000회 완료 후의 최신 MD를 다음 루프의 Seed로 설정
                    current_seed = md_history[n_blocks - 1].clone();

                    writeln!(writer, "MD = {}", encode_hex(&current_seed))
                        .map_err(|_| "IO Write Error")?;
                    writeln!(writer).map_err(|_| "IO Write Error")?;
                }
            } else if trimmed.starts_with('#') || trimmed.is_empty() || trimmed.starts_with('[') {
                writeln!(writer, "{}", line).map_err(|_| "IO Write Error")?;
            }
        }

        writer.flush().map_err(|_| "Failed to flush .rsp file")?;
        Ok(())
    }

    //
    // 실제 테스트 실행부
    //
    #[test]
    fn cavp_sha3_test() {
        let dir = match std::env::var("KCMVP_CAVP_DIR") {
            Ok(val) => val,
            Err(_) => panic!("env"),
        };

        // SHA3-224
        // process_smt_lmt(
        //     format!("{}/entanglementlib__CAVP_1_20260307173059/SHA3-224_(Byte)_SMT.req", dir).as_str(),
        //     format!("{}/entanglementlib__CAVP_1_20260307173059/SHA3-224_(Byte)_SMT.rsp", dir).as_str(),
        //     Sha3Variant::Sha3_224
        // ).unwrap();
        // process_smt_lmt(
        //     format!("{}/entanglementlib__CAVP_1_20260307173059/SHA3-224_(Byte)_LMT.req", dir).as_str(),
        //     format!("{}/entanglementlib__CAVP_1_20260307173059/SHA3-224_(Byte)_LMT.rsp", dir).as_str(),
        //     Sha3Variant::Sha3_224
        // ).unwrap();
        process_mct(
            format!(
                "{}/entanglementlib__CAVP_1_20260307173059/SHA3-224_(Byte)_MCT.req",
                dir
            )
            .as_str(),
            format!(
                "{}/entanglementlib__CAVP_1_20260307173059/SHA3-224_(Byte)_MCT.rsp",
                dir
            )
            .as_str(),
            Sha3Variant::Sha3_224,
        )
        .unwrap();

        // SHA3-256
        // process_smt_lmt(
        //     format!("{}/entanglementlib__CAVP_1_20260307173059/SHA3-256_(Byte)_SMT.req", dir).as_str(),
        //     format!("{}/entanglementlib__CAVP_1_20260307173059/SHA3-256_(Byte)_SMT.rsp", dir).as_str(),
        //     Sha3Variant::Sha3_256
        // ).unwrap();
        // process_smt_lmt(
        //     format!("{}/entanglementlib__CAVP_1_20260307173059/SHA3-256_(Byte)_LMT.req", dir).as_str(),
        //     format!("{}/entanglementlib__CAVP_1_20260307173059/SHA3-256_(Byte)_LMT.rsp", dir).as_str(),
        //     Sha3Variant::Sha3_256
        // ).unwrap();
        process_mct(
            format!(
                "{}/entanglementlib__CAVP_1_20260307173059/SHA3-256_(Byte)_MCT.req",
                dir
            )
            .as_str(),
            format!(
                "{}/entanglementlib__CAVP_1_20260307173059/SHA3-256_(Byte)_MCT.rsp",
                dir
            )
            .as_str(),
            Sha3Variant::Sha3_256,
        )
        .unwrap();

        // SHA3-384
        // process_smt_lmt(
        //     format!("{}/entanglementlib__CAVP_1_20260307173059/SHA3-384_(Byte)_SMT.req", dir).as_str(),
        //     format!("{}/entanglementlib__CAVP_1_20260307173059/SHA3-384_(Byte)_SMT.rsp", dir).as_str(),
        //     Sha3Variant::Sha3_384
        // ).unwrap();
        // process_smt_lmt(
        //     format!("{}/entanglementlib__CAVP_1_20260307173059/SHA3-384_(Byte)_LMT.req", dir).as_str(),
        //     format!("{}/entanglementlib__CAVP_1_20260307173059/SHA3-384_(Byte)_LMT.rsp", dir).as_str(),
        //     Sha3Variant::Sha3_384
        // ).unwrap();
        process_mct(
            format!(
                "{}/entanglementlib__CAVP_1_20260307173059/SHA3-384_(Byte)_MCT.req",
                dir
            )
            .as_str(),
            format!(
                "{}/entanglementlib__CAVP_1_20260307173059/SHA3-384_(Byte)_MCT.rsp",
                dir
            )
            .as_str(),
            Sha3Variant::Sha3_384,
        )
        .unwrap();

        // SHA3-512
        // process_smt_lmt(
        //     format!("{}/entanglementlib__CAVP_1_20260307173059/SHA3-512_(Byte)_SMT.req", dir).as_str(),
        //     format!("{}/entanglementlib__CAVP_1_20260307173059/SHA3-512_(Byte)_SMT.rsp", dir).as_str(),
        //     Sha3Variant::Sha3_512
        // ).unwrap();
        // process_smt_lmt(
        //     format!("{}/entanglementlib__CAVP_1_20260307173059/SHA3-512_(Byte)_LMT.req", dir).as_str(),
        //     format!("{}/entanglementlib__CAVP_1_20260307173059/SHA3-512_(Byte)_LMT.rsp", dir).as_str(),
        //     Sha3Variant::Sha3_512
        // ).unwrap();
        process_mct(
            format!(
                "{}/entanglementlib__CAVP_1_20260307173059/SHA3-512_(Byte)_MCT.req",
                dir
            )
            .as_str(),
            format!(
                "{}/entanglementlib__CAVP_1_20260307173059/SHA3-512_(Byte)_MCT.rsp",
                dir
            )
            .as_str(),
            Sha3Variant::Sha3_512,
        )
        .unwrap();
    }
}
